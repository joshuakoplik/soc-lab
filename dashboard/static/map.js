// Live Attack Map -- a vanilla-SVG animated network map for demos. It fetches the
// node topology from /api/lab/map and rides the SAME WebSocket stream the rest of
// the dashboard uses (app.js calls window.mapConsume(table, row) from its central
// dispatch). No dependencies. See plan: soft-dazzling-shannon.
(function () {
  const NS = "http://www.w3.org/2000/svg";
  const VW = 1000, VH = 620;
  let svg = null, layers = null, initialized = false, topo = null;
  let nodes = {};          // id -> {el, x, y, kind}
  let edges = {};          // "a>b" -> {path, len}
  let packets = [];        // active {path, len, t0, dur, color, r, glow}
  let rafId = null, refreshTimer = null, captionEl = null;

  // ---------- small SVG helpers ----------
  const el = (name, attrs) => {
    const e = document.createElementNS(NS, name);
    for (const k in (attrs || {})) e.setAttribute(k, attrs[k]);
    return e;
  };
  const short = (s, n) => { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; };

  // ---------- scene build ----------
  function positions() {
    // Fixed, curated layout: attacker (left) -> [firewall] -> target zone (right),
    // SIEM below the target zone watching it.
    const p = {
      attacker: { x: 130, y: 300 },
      firewall: { x: 355, y: 300 },
      target:   { x: 760, y: 250 },
      siem:     { x: 760, y: 520 },
    };
    return p;
  }

  function buildScene() {
    if (!svg) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    nodes = {}; edges = {}; packets = [];

    // defs: glow filters + arrowhead
    const defs = el("defs");
    defs.innerHTML =
      '<filter id="glow" x="-60%" y="-60%" width="220%" height="220%">' +
      '<feGaussianBlur stdDeviation="4" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>' +
      '<filter id="glowBig" x="-80%" y="-80%" width="260%" height="260%">' +
      '<feGaussianBlur stdDeviation="9" result="b"/><feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge></filter>';
    svg.appendChild(defs);

    // background grid
    const bg = el("g", { class: "map-grid" });
    for (let x = 0; x <= VW; x += 40) bg.appendChild(el("line", { x1: x, y1: 0, x2: x, y2: VH }));
    for (let y = 0; y <= VH; y += 40) bg.appendChild(el("line", { x1: 0, y1: y, x2: VW, y2: y }));
    svg.appendChild(bg);

    layers = { edges: el("g", { class: "map-edges" }), fx: el("g", { class: "map-fx" }), nodes: el("g", { class: "map-nodes" }) };
    svg.appendChild(layers.edges); svg.appendChild(layers.fx); svg.appendChild(layers.nodes);

    const pos = positions();
    const t = topo || {};
    const firewall = !!t.firewall;

    // ---- edges (draw first, under nodes) ----
    // attack path attacker -> target, bent through the firewall when remote
    if (firewall) {
      addEdge("attack", pos.attacker, pos.firewall, "attack");
      addEdge("attack2", pos.firewall, pos.target, "attack");
    } else {
      addEdge("attack", pos.attacker, pos.target, "attack");
    }
    addEdge("telemetry", pos.target, pos.siem, "telemetry");   // target -> SIEM
    addEdge("response", pos.siem, firewall ? pos.firewall : pos.target, "response"); // SIEM -> block point

    // ---- nodes ----
    addNode("attacker", pos.attacker, "attacker", "attacker",
      (t.attacker && t.attacker.ip) || "soc-attacker");
    if (firewall) addNode("firewall", pos.firewall, "firewall", "firewall", "perimeter");
    // target zone: primary target + flock decoys ringing it
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

    setCaption(primary ? "" : "no target running", "", "");
    document.getElementById("map-mode-label") && (document.getElementById("map-mode-label").textContent =
      `${t.mode || "—"} · ${t.posture || "—"}${firewall ? " · perimeter up" : ""}`);
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
    // gentle curve for visual interest
    const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - Math.abs(b.x - a.x) * 0.06;
    const d = `M ${a.x} ${a.y} Q ${mx} ${my} ${b.x} ${b.y}`;
    const path = el("path", { d: d, class: "map-edge edge-" + cls, id: "edge-" + id });
    layers.edges.appendChild(path);
    edges[id] = { path: path, len: path.getTotalLength() };
  }

  // ---------- animation loop ----------
  function firePacket(edgeId, color, opts) {
    const e = edges[edgeId];
    if (!e) return;
    opts = opts || {};
    packets.push({ path: e.path, len: e.len, t0: performance.now(), dur: opts.dur || 1100, color: color, r: opts.r || 5 });
    ensureRaf();
  }
  function ensureRaf() { if (!rafId) rafId = requestAnimationFrame(tick); }

  function tick(now) {
    // render packets
    const live = [];
    // clear previous packet circles
    let pc = layers.fx.querySelectorAll(".map-packet");
    pc.forEach((c) => c.remove());
    for (const p of packets) {
      const t = (now - p.t0) / p.dur;
      if (t >= 1) continue;
      const pt = p.path.getPointAtLength(t * p.len);
      const dot = el("circle", { class: "map-packet", cx: pt.x, cy: pt.y, r: p.r, fill: p.color, filter: "url(#glowBig)" });
      layers.fx.appendChild(dot);
      live.push(p);
    }
    packets = live;
    if (packets.length) rafId = requestAnimationFrame(tick);
    else { rafId = null; }
  }

  // ---------- node fx ----------
  function flash(id, cls, ms) {
    const n = nodes[id]; if (!n) return;
    n.el.classList.add(cls);
    setTimeout(() => n.el.classList.remove(cls), ms || 900);
  }
  const COMPROMISE = { unconfirmed: 0, vuln_identified: 1, exploit_confirmed: 2, shell_or_creds: 3 };
  function setCompromise(tier) {
    const n = nodes["target"]; if (!n) return;
    const lvl = COMPROMISE[tier] != null ? COMPROMISE[tier] : 0;
    n.el.setAttribute("data-compromise", String(lvl));
    flash("target", "hit", 700);
  }

  // ---------- caption banner ----------
  function setCaption(tool, target, cmd) {
    if (!captionEl) return;
    if (!tool) { captionEl.innerHTML = '<span class="cap-idle">waiting for activity…</span>'; return; }
    captionEl.innerHTML =
      `<span class="cap-tool">${escapeHtmlLocal(tool)}</span>` +
      (target ? ` <span class="cap-arrow">→</span> <span class="cap-target">${escapeHtmlLocal(short(target, 24))}</span>` : "") +
      (cmd ? ` <span class="cap-cmd">${escapeHtmlLocal(short(cmd, 70))}</span>` : "");
  }
  function escapeHtmlLocal(s) { const d = document.createElement("div"); d.textContent = String(s == null ? "" : s); return d.innerHTML; }

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
    setCaption(tool, row.target, cmdOf(row));
    const color = ATTACK_COLORS[tool] || "#ff7b5a";
    if (tool === "nmap_scan" || (row.target && /\/\d+$/.test(String(row.target)))) {
      sweep(color);                            // recon sweep across the zone
    } else {
      firePacket("attack", color);
      if (edges["attack2"]) setTimeout(() => firePacket("attack2", color), 260);
      flash("target", "probed", 500);
    }
    // telemetry captured -> SIEM
    setTimeout(() => firePacket("telemetry", "#63e6c2", { dur: 900 }), 500);
  }
  function sweep(color) {
    // radar arc expanding from the attacker + quick pulses to target and flocks
    const a = nodes["attacker"]; if (!a) return;
    const ring = el("circle", { class: "map-sweep", cx: a.x, cy: a.y, r: 20, stroke: color || "#5bd0ff" });
    layers.fx.appendChild(ring);
    setTimeout(() => ring.remove(), 1200);
    firePacket("attack", color || "#5bd0ff", { dur: 900 });
    Object.keys(nodes).forEach((id) => { if (id.startsWith("flock-")) flash(id, "probed", 600); });
  }
  function onWin(row) { setCompromise(row.evidence_tier); }
  function onRecon() { flash("target", "probed", 400); }
  function onDetection() { flash("siem", "detect", 800); firePacket("telemetry", "#63e6c2", { dur: 800 }); }
  function onIncident(row) {
    flash("siem", "detect", 1000);
    const sev = (row.severity || "").toLowerCase();
    const n = nodes["siem"]; if (n) n.el.setAttribute("data-sev", sev);
  }
  function onDefenderAction(row) {
    const kind = row.kind;
    if (kind === "block_ip") doBlock();
    else if (kind === "page_oncall") doPage();
    else if (kind === "alert") flash("siem", "detect", 700);
  }
  function doBlock() {
    // SIEM -> firewall/target response pulse, then sever the attack path
    firePacket("response", "#ff4d6d", { dur: 700 });
    flash("firewall", "blocking", 1400);
    flash("siem", "detect", 700);
    const e = edges["attack"]; if (e) { e.path.classList.add("severed"); setTimeout(() => e.path.classList.remove("severed"), 2600); }
    const e2 = edges["attack2"]; if (e2) { e2.path.classList.add("severed"); setTimeout(() => e2.path.classList.remove("severed"), 2600); }
  }
  function doPage() { flash("siem", "paging", 1600); }

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
        case "block_ip_calls": doBlock(); break;
        case "human_pages": doPage(); break;
      }
    } catch (e) { /* never let a stray row break the map */ }
  };

  async function loadTopology() {
    try { topo = await (await fetch("/api/lab/map")).json(); } catch (e) { topo = topo || {}; }
    buildScene();
  }

  window.initMap = function () {
    svg = document.getElementById("map-svg");
    captionEl = document.getElementById("map-caption");
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
