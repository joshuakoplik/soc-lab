// Live Attack Map -- a vanilla-SVG animated network map for demos. It fetches the
// node topology from /api/lab/map and rides the SAME WebSocket stream the rest of
// the dashboard uses (app.js calls window.mapConsume(table, row) from its central
// dispatch). No dependencies.
//
// Activity model: each side has ONE "current activity" that runs CONTINUOUSLY
// (flowing dashed edge + a steady stream of packets + a pulsing node) until the
// next row for that side replaces it -- so the current step reads as ongoing, not
// a single projectile that vanishes. Attacker activity is captioned in the top box,
// defender/SOC activity in the bottom box; each caption persists until the next.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const VW = 1000, VH = 620;
  let svg = null, layers = null, initialized = false, topo = null;
  let nodes = {};          // id -> {el, x, y, kind}
  let edges = {};          // id -> {path, len}
  let packets = [];        // active {path, len, t0, dur, color, r}
  let rafId = null, refreshTimer = null;
  let capAtkEl = null, capDefEl = null;
  let activeAttack = null; // {edges:[id], color, kind, spawn, ring}
  let activeDefense = null;// {edges:[id], color, kind, spawn}
  let severed = false;     // attack path currently cut by a block
  const STREAM_MS = 480;   // spacing between streamed packets on an active edge

  // ---------- small helpers ----------
  const el = (name, attrs) => {
    const e = document.createElementNS(NS, name);
    for (const k in (attrs || {})) e.setAttribute(k, attrs[k]);
    return e;
  };
  const short = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
  const esc = (s) => { const d = document.createElement("div"); d.textContent = String(s == null ? "" : s); return d.innerHTML; };

  // ---------- scene build ----------
  function positions() {
    return { attacker: { x: 130, y: 300 }, firewall: { x: 355, y: 300 },
             target: { x: 760, y: 250 }, siem: { x: 760, y: 520 } };
  }

  function buildScene() {
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    nodes = {}; edges = {}; packets = [];

    const defs = el("defs");
    defs.innerHTML =
      '<filter id="glow" x="-60%" y="-60%" width="220%" height="220%">' +
      '<feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
      '<filter id="glowBig" x="-80%" y="-80%" width="260%" height="260%">' +
      '<feGaussianBlur stdDeviation="9" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
    svg.appendChild(defs);

    const bg = el("g", { class: "map-grid" });
    for (let x = 0; x <= VW; x += 40) bg.appendChild(el("line", { x1: x, y1: 0, x2: x, y2: VH }));
    for (let y = 0; y <= VH; y += 40) bg.appendChild(el("line", { x1: 0, y1: y, x2: VW, y2: y }));
    svg.appendChild(bg);

    layers = { edges: el("g", { class: "map-edges" }), fx: el("g", { class: "map-fx" }), nodes: el("g", { class: "map-nodes" }) };
    svg.appendChild(layers.edges); svg.appendChild(layers.fx); svg.appendChild(layers.nodes);

    const pos = positions();
    const t = topo || {};
    const firewall = !!t.firewall;

    if (firewall) {
      addEdge("attack", pos.attacker, pos.firewall, "attack");
      addEdge("attack2", pos.firewall, pos.target, "attack");
    } else {
      addEdge("attack", pos.attacker, pos.target, "attack");
    }
    addEdge("telemetry", pos.target, pos.siem, "telemetry");
    addEdge("response", pos.siem, firewall ? pos.firewall : pos.target, "response");

    addNode("attacker", pos.attacker, "attacker", "attacker",
      (t.attacker && t.attacker.ip) || "soc-attacker");
    if (firewall) addNode("firewall", pos.firewall, "firewall", "firewall", "perimeter");
    const primary = (t.targets || [])[0];
    addNode("target", pos.target, "target", primary ? short(primary.name, 12) : "target",
      primary ? (primary.label ? short(primary.label.split("/").pop(), 20) : primary.ip || "") : "down");
    addNode("siem", pos.siem, "siem", "SOC / SIEM", "Suricata · Wazuh · hunter");

    const flocks = (t.flocks || []).slice(0, 8);
    flocks.forEach((f, i) => {
      const ang = (-90 + (i - (flocks.length - 1) / 2) * 34) * Math.PI / 180;
      const fx = pos.target.x + Math.cos(ang) * 150, fy = pos.target.y + Math.sin(ang) * 110;
      addNode("flock-" + i, { x: fx, y: fy }, "flock", "", short(f.name, 12));
    });

    const mm = document.getElementById("map-mode-label");
    if (mm) mm.textContent = `${t.mode || "—"} · ${t.posture || "—"}${firewall ? " · perimeter up" : ""}`;
    if (!primary) setAtkCaption(null);
    reapplyActive();   // a topology refresh rebuilds the SVG; restore in-progress flow
  }

  function addNode(id, p, kind, title, sub) {
    const g = el("g", { class: "map-node kind-" + kind, transform: `translate(${p.x},${p.y})` });
    if (kind === "firewall") {
      g.appendChild(el("rect", { x: -14, y: -34, width: 28, height: 68, rx: 4, class: "node-shape", filter: "url(#glow)" }));
    } else {
      const r = kind === "target" || kind === "attacker" || kind === "siem" ? 26 : 15;
      g.appendChild(el("circle", { r: r + 7, class: "node-halo" }));
      g.appendChild(el("circle", { r: r, class: "node-shape", filter: "url(#glow)" }));
    }
    if (title) { const tt = el("text", { class: "node-title", y: kind === "flock" ? 30 : 44 }); tt.textContent = title; g.appendChild(tt); }
    if (sub) { const st = el("text", { class: "node-sub", y: kind === "flock" ? 42 : 58 }); st.textContent = sub; g.appendChild(st); }
    layers.nodes.appendChild(g);
    nodes[id] = { el: g, x: p.x, y: p.y, kind: kind };
  }

  function addEdge(id, a, b, cls) {
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - Math.abs(b.x - a.x) * 0.06;
    const d = `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`;
    const path = el("path", { d: d, class: "map-edge edge-" + cls, id: "edge-" + id });
    layers.edges.appendChild(path);
    edges[id] = { path: path, len: path.getTotalLength() };
  }

  // ---------- continuous activity streams ----------
  function attackEdgeIds() { return edges["attack2"] ? ["attack", "attack2"] : ["attack"]; }
  function setEdgeFlow(ids, color, on) {
    ids.forEach((id) => {
      const e = edges[id]; if (!e) return;
      if (on) { e.path.classList.add("flowing"); if (color) e.path.style.stroke = color; }
      else { e.path.classList.remove("flowing"); e.path.style.stroke = ""; }
    });
  }
  function setNodeState(id, cls, on) { const n = nodes[id]; if (n) n.el.classList.toggle(cls, !!on); }
  function setSevered(on) {
    severed = on;
    attackEdgeIds().forEach((id) => { const e = edges[id]; if (e) e.path.classList.toggle("severed", on); });
  }
  function spawnPacket(edgeId, color, r, dur) {
    const e = edges[edgeId]; if (!e) return;
    packets.push({ path: e.path, len: e.len, t0: performance.now(), dur: dur || 1000, color: color, r: r || 5 });
  }

  function startAttack(color, kind) {
    setSevered(false);
    if (activeAttack) setEdgeFlow(activeAttack.edges, null, false);
    activeAttack = { edges: attackEdgeIds(), color: color, kind: kind, spawn: 0, ring: 0 };
    setEdgeFlow(activeAttack.edges, color, true);
    setNodeState("target", "under-attack", true);
    ensureRaf();
  }
  function startDefense(color, edgeIds, kind) {
    if (activeDefense) setEdgeFlow(activeDefense.edges, null, false);
    activeDefense = { edges: edgeIds, color: color, kind: kind, spawn: 0 };
    setEdgeFlow(edgeIds, color, true);
    setNodeState("siem", "soc-active", true);
    ensureRaf();
  }
  function reapplyActive() {
    if (activeAttack) {
      activeAttack.edges = attackEdgeIds();
      setEdgeFlow(activeAttack.edges, activeAttack.color, true);
      setNodeState("target", "under-attack", !severed);
    }
    if (severed) setSevered(true);
    if (activeDefense) { setEdgeFlow(activeDefense.edges, activeDefense.color, true); setNodeState("siem", "soc-active", true); }
    if (activeAttack || activeDefense || packets.length) ensureRaf();
  }
  function ensureRaf() { if (!rafId) rafId = requestAnimationFrame(tick); }

  function tick(now) {
    layers.fx.querySelectorAll(".map-packet").forEach((c) => c.remove());

    if (activeAttack && !severed && now - activeAttack.spawn >= STREAM_MS) {
      activeAttack.spawn = now;
      spawnPacket(activeAttack.edges[0], activeAttack.color);
      if (activeAttack.edges[1]) {
        const col = activeAttack.color;
        setTimeout(() => { if (activeAttack && !severed) spawnPacket("attack2", col); }, STREAM_MS * 0.45);
      }
      spawnPacket("telemetry", "#63e6c2", 4, 1300);   // observation trickle: target -> SIEM
      if (activeAttack.kind === "scan") { activeAttack.ring++; if (activeAttack.ring % 2 === 1) sweepRing(activeAttack.color); }
    }
    if (activeDefense && now - activeDefense.spawn >= STREAM_MS) {
      activeDefense.spawn = now;
      activeDefense.edges.forEach((id) => spawnPacket(id, activeDefense.color));
    }

    const live = [];
    for (const p of packets) {
      const t = (now - p.t0) / p.dur;
      if (t >= 1) continue;
      const pt = p.path.getPointAtLength(t * p.len);
      layers.fx.appendChild(el("circle", { class: "map-packet", cx: pt.x, cy: pt.y, r: p.r, fill: p.color, filter: "url(#glowBig)" }));
      live.push(p);
    }
    packets = live;
    if (activeAttack || activeDefense || packets.length) rafId = requestAnimationFrame(tick);
    else rafId = null;
  }

  // ---------- one-shot node fx ----------
  function flash(id, cls, ms) {
    const n = nodes[id]; if (!n) return;
    n.el.classList.add(cls);
    setTimeout(() => n.el.classList.remove(cls), ms || 900);
  }
  function sweepRing(color) {
    const a = nodes["attacker"]; if (!a) return;
    const ring = el("circle", { class: "map-sweep", cx: a.x, cy: a.y, r: 20, stroke: color || "#5bd0ff" });
    layers.fx.appendChild(ring);
    setTimeout(() => ring.remove(), 1200);
  }
  const COMPROMISE = { unconfirmed: 0, vuln_identified: 1, exploit_confirmed: 2, shell_or_creds: 3 };
  function setCompromise(tier) {
    const n = nodes["target"]; if (!n) return;
    const lvl = COMPROMISE[tier] != null ? COMPROMISE[tier] : 0;
    n.el.setAttribute("data-compromise", String(lvl));
    flash("target", "hit", 700);
  }

  // ---------- caption boxes (persist until next action) ----------
  function setAtkCaption(tool, target, cmd) {
    if (!capAtkEl) return;
    if (!tool) { capAtkEl.innerHTML = '<span class="cap-idle">waiting for activity…</span>'; return; }
    capAtkEl.innerHTML =
      `<span class="cap-tool">${esc(tool)}</span>` +
      (target ? ` <span class="cap-arrow">→</span> <span class="cap-target">${esc(short(target, 24))}</span>` : "") +
      (cmd ? ` <span class="cap-cmd">${esc(short(cmd, 70))}</span>` : "");
  }
  function setDefCaption(label, detail, cls) {
    if (!capDefEl) return;
    if (!label) { capDefEl.className = "map-caption def"; capDefEl.innerHTML = '<span class="cap-idle">standing by…</span>'; return; }
    capDefEl.className = "map-caption def " + (cls || "");
    capDefEl.innerHTML =
      `<span class="cap-kind">${esc(label)}</span>` +
      (detail ? ` <span class="cap-detail">${esc(short(detail, 72))}</span>` : "");
  }

  // ---------- activity -> animation ----------
  const ATTACK_COLORS = {
    nmap_scan: "#5bd0ff", http_probe: "#7cf6c7", shell_exec: "#ff7b5a",
    ssh_exec: "#ff7b5a", hydra_bruteforce: "#ffcf5b", sqlmap_scan: "#c58bff",
    msf_run_module: "#ff5a7b", propose_action: "#ff7b5a",
  };
  function cmdOf(row) {
    try { const inp = typeof row.input_json === "string" ? JSON.parse(row.input_json) : row.input_json;
      return (inp && (inp.command || inp.query || (inp.paths && inp.paths.join(" ")))) || ""; } catch (e) { return ""; }
  }
  function onAttackerAction(row) {
    const tool = row.tool || "action";
    const color = ATTACK_COLORS[tool] || "#ff7b5a";
    setAtkCaption(tool, row.target, cmdOf(row));
    const scan = tool === "nmap_scan" || (row.target && /\/\d+$/.test(String(row.target)));
    startAttack(color, scan ? "scan" : "exploit");
    if (scan) sweepRing(color);
  }
  function onWin(row) { setCompromise(row.evidence_tier); }
  function onRecon() { Object.keys(nodes).forEach((id) => { if (id.startsWith("flock-")) flash(id, "probed", 500); }); }
  function onDetection(row) {
    startDefense("#63e6c2", ["telemetry"], "detect");
    setDefCaption("DETECTED", (row.rule ? row.rule + " · " : "") + (row.severity || ""), "def-detect");
    flash("siem", "detect", 800);
  }
  function onIncident(row) {
    const sev = (row.severity || "").toLowerCase();
    const n = nodes["siem"]; if (n) n.el.setAttribute("data-sev", sev);
    startDefense("#ff5a7b", ["telemetry"], "incident");
    setDefCaption("INCIDENT", (row.severity ? row.severity.toUpperCase() + " · " : "") + (row.title || ""), "def-incident");
    flash("siem", "detect", 1000);
  }
  function onDefenderAction(row) {
    const kind = row.kind;
    if (kind === "block_ip") doBlock(row);
    else if (kind === "page_oncall") doPage(row);
    else if (kind === "alert") {
      startDefense("#63e6c2", ["telemetry"], "alert");
      setDefCaption("ALERT", row.reason || row.src_ip || "", "def-alert");
      flash("siem", "detect", 800);
    }
  }
  function doBlock(row) {
    const ip = (row && row.src_ip) || "";
    if (activeAttack) setEdgeFlow(activeAttack.edges, null, false);   // stop the attack stream
    setSevered(true);
    setNodeState("target", "under-attack", false);
    startDefense("#ff4d6d", ["response"], "block");
    setDefCaption("BLOCKED", (ip ? ip + " · " : "") + "attack path severed", "def-block");
    flash("firewall", "blocking", 1600);
    flash("siem", "detect", 700);
  }
  function doPage(row) {
    startDefense("#ffcf5b", ["telemetry"], "page");
    setDefCaption("PAGE ON-CALL", (row && (row.reason || row.src_ip)) || "analyst notified", "def-page");
    flash("siem", "paging", 1600);
  }

  // ---------- public API (used by app.js) ----------
  window.mapConsume = function (table, row) {
    if (!initialized || !row) return;
    try {
      switch (table) {
        case "pending_actions": onAttackerAction(row); break;
        case "wins": onWin(row); break;
        case "recon_findings": onRecon(row); break;
        case "candidates": onDetection(row); break;
        case "incidents": onIncident(row); break;
        case "chat_actions": onDefenderAction(row); break;
        case "block_ip_calls": doBlock(row); break;
        case "human_pages": doPage(row); break;
      }
    } catch (e) { /* never let a stray row break the map */ }
  };

  async function loadTopology() {
    try { topo = await (await fetch("/api/lab/map")).json(); } catch (e) { topo = topo || {}; }
    buildScene();
  }

  window.initMap = function () {
    svg = document.getElementById("map-svg");
    capAtkEl = document.getElementById("map-caption");
    capDefEl = document.getElementById("map-caption-def");
    if (!svg) return;
    if (!initialized) {
      initialized = true;
      loadTopology();
      refreshTimer = setInterval(loadTopology, 8000);   // topology only; activity is live via WS
    } else {
      loadTopology();
    }
  };
})();
