// Live client for the SOC lab dashboard. Read-only: renders whatever
// /api/bootstrap + the /ws stream hand it, never writes anything back.

const feedEvents = document.getElementById("feed-events");
const feedDefender = document.getElementById("feed-defender");
const feedAttacker = document.getElementById("feed-attacker");

const candidatesById = new Map();   // id -> candidate row
const sessionsById = new Map();     // id -> {row, recon, vuln, loot, flags, cardEl, headerEl, timelineEl, lastActivity}

let eventTimes = [];   // epoch ms, trimmed to last 60s -- "events/min"
let alertTimes = [];   // epoch ms, trimmed to last 60min -- "alerts (1h)"
let flagsTotal = 0;

// ---------- small helpers ----------

function toEpoch(ts) {
  const s = /[zZ]|[+-]\d\d:\d\d$/.test(ts) ? ts : ts + "Z";
  return new Date(s).getTime();
}

function fmtTime(ts) {
  if (!ts) return "--:--:--";
  return new Date(toEpoch(ts)).toLocaleTimeString("en-US", { hour12: false });
}

function escapeHtml(s) {
  if (s === null || s === undefined) return "";
  return String(s).replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

function truncate(s, n) {
  if (!s) return "";
  return s.length > n ? s.slice(0, n) + "\u2026" : s;
}

function updateStat(id, value) {
  document.getElementById(id).textContent = value;
}

function isNearBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < 60;
}

function appendLine(feedEl, innerHtml, statusClass, cap = 400) {
  const placeholder = feedEl.querySelector(".empty");
  if (placeholder) placeholder.remove();
  const wasNear = isNearBottom(feedEl);
  const div = document.createElement("div");
  div.className = "line" + (statusClass ? " " + statusClass : "");
  div.innerHTML = innerHtml;
  feedEl.appendChild(div);
  while (feedEl.children.length > cap) feedEl.removeChild(feedEl.firstChild);
  if (wasNear) feedEl.scrollTop = feedEl.scrollHeight;
}

function buildEntry(ts, headHtml, bodyHtml) {
  return `<div class="line-head"><span class="ts">${fmtTime(ts)}</span>${headHtml}</div>` +
    (bodyHtml ? `<div class="rationale">${bodyHtml}</div>` : "");
}

function verdictStatusClass(verdict) {
  return { benign: "st-good", suspicious: "st-warning", malicious: "st-critical", needs_human: "st-serious", error: "st-muted" }[verdict] || "st-muted";
}

function severityStatusClass(sev) {
  return { info: "st-good", low: "st-good", medium: "st-warning", high: "st-serious", critical: "st-critical" }[(sev || "").toLowerCase()] || "st-muted";
}

function badgeClassForStatus(status) {
  if (status === "running") return "badge-running";
  if (status === "completed") return "badge-completed";
  if (status === "error" || status === "interrupted") return "badge-error";
  return "badge-incomplete";
}

// ---------- Live Telemetry (events table) ----------

function eventDetail(row) {
  if (row.source === "cowrie") {
    if (row.command) return { kind: "untrusted", text: "$ " + row.command };
    if (row.username || row.password) return { kind: "untrusted", text: `login ${row.username ?? ""}:${row.password ?? ""}` };
    if (row.client_version) return { kind: "untrusted", text: row.client_version };
    return { kind: "plain", text: row.message || "" };
  }
  if (row.source === "nginx") {
    const path = `${row.http_method || ""} ${row.url_path || ""}${row.url_query ? "?" + row.url_query : ""}`;
    return { kind: "untrusted", text: path.trim(), extra: row.http_status != null ? `\u2192 ${row.http_status}` : null };
  }
  if (row.source === "suricata") {
    return { kind: "detection", text: row.ids_signature || row.message || "", extra: row.ids_severity != null ? `sev ${row.ids_severity}` : null };
  }
  if (row.source === "wazuh") {
    return { kind: "detection", text: row.siem_description || row.message || "", extra: row.siem_level != null ? `lvl ${row.siem_level}` : null };
  }
  return { kind: "plain", text: row.message || "" };
}

function renderEventLine(row) {
  const d = eventDetail(row);
  const bodyClass = d.kind === "untrusted" ? "untrusted" : d.kind === "detection" ? "detection" : "";
  const head = `<span class="tag src-${escapeHtml(row.source)}">${escapeHtml(row.source)}</span>` +
    `<span class="ctx">${escapeHtml(row.src_ip || "")}</span>` +
    `<span class="body"><span class="${bodyClass}">${escapeHtml(d.text)}</span>${d.extra ? ` <span class="ctx">${escapeHtml(d.extra)}</span>` : ""}</span>`;
  appendLine(feedEvents, buildEntry(row.ts, head, null), null, 400);
}

// ---------- Defender Log (triage / alerts / block actions) ----------

function candidateCtx(candidateId) {
  const c = candidatesById.get(candidateId);
  if (!c) return `#${candidateId}`;
  return `#${candidateId} ${escapeHtml(c.src_ip || "?")} \u00b7 ${escapeHtml(c.rule || "")}`;
}

function renderDefenderRow(table, row) {
  let statusClass, head, body, ts = row.created;

  if (table === "triage") {
    statusClass = verdictStatusClass(row.verdict);
    const conf = row.confidence != null ? Math.round(row.confidence * 100) + "%" : "\u2014";
    head = `<span class="action-icon">\u{1F9E0}</span><span class="tag ${statusClass}">${escapeHtml(row.verdict)}</span>` +
      `<span class="ctx">${candidateCtx(row.candidate_id)} \u00b7 conf ${conf}${row.attack_technique ? " \u00b7 " + escapeHtml(row.attack_technique) : ""}</span>`;
    body = escapeHtml(row.rationale || row.error || "");
  } else if (table === "agent_alerts") {
    statusClass = severityStatusClass(row.severity);
    head = `<span class="action-icon">\u{1F514}</span><span class="tag ${statusClass}">alert \u00b7 ${escapeHtml(row.severity)}</span>` +
      `<span class="ctx">${candidateCtx(row.candidate_id)} \u00b7 paging on-call</span>`;
    body = escapeHtml(row.summary || "");
    alertTimes.push(toEpoch(row.created));
  } else if (table === "block_recommendations") {
    statusClass = "st-warning";
    head = `<span class="action-icon">\u{1F6E1}</span><span class="tag st-warning">block recommended</span>` +
      `<span class="ctx">${escapeHtml(row.src_ip)} \u00b7 awaiting human approval</span>`;
    body = escapeHtml(row.reason || "");
  } else if (table === "block_ip_calls") {
    statusClass = "st-critical";
    head = `<span class="action-icon">\u26D4</span><span class="tag st-critical">block_ip() called</span>` +
      `<span class="ctx">${escapeHtml(row.src_ip)} \u00b7 logged only, no real firewall change</span>`;
    body = escapeHtml(row.reason || "");
  } else {
    return;
  }
  appendLine(feedDefender, buildEntry(ts, head, body), statusClass, 400);
}

// ---------- Attacker Campaigns (redteam_sessions + children) ----------

function correlationBadge(attackerIp) {
  if (!attackerIp) return "";
  let match = null;
  for (const c of candidatesById.values()) {
    if (c.src_ip === attackerIp && (!match || c.id > match.id)) match = c;
  }
  if (!match) return "";
  return `<span class="badge flagged-badge">\u{1F50E} flagged: ${escapeHtml(match.rule)} (${escapeHtml(match.severity)})</span>`;
}

function renderCampaignHeader(s) {
  const r = s.row;
  s.headerEl.innerHTML =
    `<span class="campaign-id">#${r.id}</span>` +
    `<span class="badge ${badgeClassForStatus(r.status)}">${escapeHtml(r.stage)} \u00b7 ${escapeHtml(r.status)}</span>` +
    `<span class="campaign-meta">${escapeHtml(r.provider)}/${escapeHtml(r.model)}</span>` +
    `<span class="campaign-meta">ip ${escapeHtml(r.attacker_ip || "?")}</span>` +
    `<span class="campaign-meta">started ${fmtTime(r.started || r.created)}</span>` +
    correlationBadge(r.attacker_ip);
}

function ensureCampaign(row) {
  let s = sessionsById.get(row.id);
  if (!s) {
    const placeholder = feedAttacker.querySelector(".empty");
    if (placeholder) placeholder.remove();
    const card = document.createElement("div");
    card.className = "campaign";
    card.innerHTML = `<div class="campaign-header"></div><div class="campaign-timeline"></div>`;
    s = {
      row, recon: [], vuln: [], loot: [], flags: [],
      cardEl: card,
      headerEl: card.querySelector(".campaign-header"),
      timelineEl: card.querySelector(".campaign-timeline"),
      lastActivity: Date.now(),
    };
    sessionsById.set(row.id, s);
    feedAttacker.appendChild(card);
    appendLine(s.timelineEl, buildEntry(row.created,
      `<span class="tag badge-running">campaign started</span><span class="ctx">${escapeHtml(row.provider)}/${escapeHtml(row.model)}</span>`, null),
      null, 80);
  } else {
    const old = s.row;
    if (old.stage !== row.stage || old.status !== row.status) {
      appendLine(s.timelineEl, buildEntry(new Date().toISOString(),
        `<span class="tag ${badgeClassForStatus(row.status)}">${escapeHtml(old.stage)}/${escapeHtml(old.status)} \u2192 ${escapeHtml(row.stage)}/${escapeHtml(row.status)}</span>`, null),
        null, 80);
    }
    s.row = row;
    s.lastActivity = Date.now();
  }
  renderCampaignHeader(s);
}

function onReconFinding(row) {
  const s = sessionsById.get(row.session_id);
  if (!s) return;
  s.recon.push(row);
  s.lastActivity = Date.now();
  const head = `<span class="tag detection">recon</span><span class="ctx">${escapeHtml(row.target)} \u00b7 ${escapeHtml(row.finding_type)} \u00b7 ${escapeHtml(row.source_tool)}</span>`;
  appendLine(s.timelineEl, buildEntry(row.created, head, escapeHtml(truncate(row.detail, 220))), null, 80);
}

function onVulnFinding(row) {
  const s = sessionsById.get(row.session_id);
  if (!s) return;
  s.vuln.push(row);
  s.lastActivity = Date.now();
  const cls = severityStatusClass(row.severity);
  const head = `<span class="tag ${cls}">vuln \u00b7 ${escapeHtml(row.severity)}</span><span class="ctx">${escapeHtml(row.target)} \u00b7 ${escapeHtml(row.category)}</span>`;
  appendLine(s.timelineEl, buildEntry(row.created, head, escapeHtml(row.description || "")), cls, 80);
}

function onPendingAction(row) {
  const s = sessionsById.get(row.session_id);
  if (!s) return;
  s.lastActivity = Date.now();
  let label, cls, ts;
  if (row.executed) { label = "executed"; cls = "st-critical"; ts = row.executed_at || row.created; }
  else if (row.approved) { label = "approved"; cls = "st-warning"; ts = row.approved_at || row.created; }
  else { label = "proposed"; cls = "st-muted"; ts = row.created; }
  const approver = row.approved_by ? ` \u00b7 ${escapeHtml(row.approved_by)}` : "";
  const head = `<span class="tag ${cls}">${label}</span><span class="ctx">${escapeHtml(row.tool)} \u2192 ${escapeHtml(row.target)}${approver}</span>`;
  appendLine(s.timelineEl, buildEntry(ts, head, escapeHtml(row.rationale || "")), cls, 80);
}

function onLoot(row) {
  const s = sessionsById.get(row.session_id);
  if (!s) return;
  s.loot.push(row);
  s.lastActivity = Date.now();
  const head = `<span class="tag detection">loot</span><span class="ctx">${escapeHtml(row.tool)} \u00b7 ${escapeHtml(row.target || "")} \u00b7 exit ${row.exit_code}</span>`;
  appendLine(s.timelineEl, buildEntry(row.created, head, escapeHtml(truncate(row.summary, 220))), null, 80);
}

function onCapturedFlag(row) {
  const s = sessionsById.get(row.session_id);
  if (!s) return;
  s.flags.push(row);
  s.lastActivity = Date.now();
  flagsTotal++;
  const head = `<span class="tag st-critical">\u{1F6A9} flag captured</span><span class="ctx">${escapeHtml(row.target)} \u00b7 ${escapeHtml(row.method || "")}</span>`;
  appendLine(s.timelineEl, buildEntry(row.created, head, escapeHtml(row.flag_value || "")), "st-critical", 80);
  updateStat("stat-flags", flagsTotal);
}

function resortCampaigns() {
  const arr = [...sessionsById.values()];
  arr.sort((a, b) => {
    const aRun = a.row.status === "running" ? 0 : 1;
    const bRun = b.row.status === "running" ? 0 : 1;
    if (aRun !== bRun) return aRun - bRun;
    return (b.lastActivity || 0) - (a.lastActivity || 0);
  });
  for (const s of arr) feedAttacker.appendChild(s.cardEl);
}

// ---------- candidates (context lookup, not its own visual feed) ----------

function onCandidate(row) {
  candidatesById.set(row.id, row);
}

function recomputeOpenCandidates() {
  let n = 0;
  for (const c of candidatesById.values()) if (c.status === "new") n++;
  updateStat("stat-open-candidates", n);
}

function recomputeActiveCampaigns() {
  let n = 0;
  for (const s of sessionsById.values()) if (s.row.status === "running") n++;
  updateStat("stat-active-campaigns", n);
}

// ---------- message routing ----------

function handleMessage(msg) {
  const { table, row } = msg;
  switch (table) {
    case "events": renderEventLine(row); eventTimes.push(toEpoch(row.ts)); break;
    case "candidates": onCandidate(row); break;
    case "triage": renderDefenderRow("triage", row); break;
    case "agent_alerts": renderDefenderRow("agent_alerts", row); break;
    case "block_recommendations": renderDefenderRow("block_recommendations", row); break;
    case "block_ip_calls": renderDefenderRow("block_ip_calls", row); break;
    case "redteam_sessions": ensureCampaign(row); break;
    case "recon_findings": onReconFinding(row); break;
    case "vuln_findings": onVulnFinding(row); break;
    case "pending_actions": onPendingAction(row); break;
    case "loot": onLoot(row); break;
    case "captured_flags": onCapturedFlag(row); break;
    case "_error": console.error("poll error:", row.detail); break;
  }
}

function byCreatedAsc(a, b) {
  return a.row.created < b.row.created ? -1 : a.row.created > b.row.created ? 1 : 0;
}

async function loadBootstrap() {
  const res = await fetch("/api/bootstrap");
  const data = await res.json();

  for (const row of data.events.rows) handleMessage({ table: "events", row });
  for (const row of data.candidates.rows) handleMessage({ table: "candidates", row });

  const defenderRows = [];
  for (const t of ["triage", "agent_alerts", "block_recommendations", "block_ip_calls"]) {
    for (const row of data[t].rows) defenderRows.push({ table: t, row });
  }
  defenderRows.sort(byCreatedAsc);
  defenderRows.forEach(handleMessage);

  for (const row of data.redteam_sessions.rows) handleMessage({ table: "redteam_sessions", row });

  const campaignRows = [];
  for (const t of ["recon_findings", "vuln_findings", "pending_actions", "loot", "captured_flags"]) {
    for (const row of data[t].rows) campaignRows.push({ table: t, row });
  }
  campaignRows.sort(byCreatedAsc);
  campaignRows.forEach(handleMessage);

  recomputeOpenCandidates();
  recomputeActiveCampaigns();
  resortCampaigns();
}

// ---------- periodic recompute (rates, sort order) ----------

setInterval(() => {
  const cutoff60s = Date.now() - 60000;
  eventTimes = eventTimes.filter((t) => t >= cutoff60s);
  updateStat("stat-eventrate", eventTimes.length);

  const cutoff1h = Date.now() - 3600000;
  alertTimes = alertTimes.filter((t) => t >= cutoff1h);
  updateStat("stat-alerts-1h", alertTimes.length);
}, 2000);

setInterval(resortCampaigns, 3000);

// ---------- websocket ----------

function setConn(up) {
  const el = document.getElementById("conn");
  el.textContent = up ? "live" : "reconnecting\u2026";
  el.className = "conn-badge " + (up ? "conn-up" : "conn-down");
}

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(connectWS, 2000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    try { handleMessage(JSON.parse(ev.data)); } catch (e) { console.error(e); }
  };
}

// ---------- init ----------

document.querySelectorAll(".feed").forEach((f) => {
  f.innerHTML = '<div class="empty">waiting for data\u2026</div>';
});

loadBootstrap().catch((e) => console.error("bootstrap failed", e)).finally(connectWS);
