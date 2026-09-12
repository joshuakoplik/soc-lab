// Live client for the SOC lab dashboard. Read-only: renders whatever
// /api/bootstrap + the /ws stream hand it, never writes anything back.

const feedEvents = document.getElementById("feed-events");
const timelineEl = document.getElementById("timeline");   // the unified defender|attacker time axis
const feedDiary = document.getElementById("feed-diary");  // attacker's own reasoning, streamed unedited
const diariedIds = new Set();  // pending_action ids already narrated (they re-fire on approve/execute)

const candidatesById = new Map();   // id -> candidate row
const sessionsById = new Map();     // id -> {row}  (kept for stats + correlation, no per-campaign DOM anymore)
const inflightById = new Map();     // llm_calls.id -> {row, cardEl}

// Every row this client has seen, so a click on any rendered line can pull
// up its full record -- keyed "table:id", populated centrally in
// handleMessage rather than by each render function, so nothing that
// renders a line has to remember to also register it.
const detailStore = new Map();

let eventTimes = [];   // epoch ms, trimmed to last 60s -- "events/min"
let alertTimes = [];   // epoch ms, trimmed to last 60min -- "alerts (1h)"
let flagsTotal = 0;

// ---------- small helpers ----------

function toEpoch(ts) {
  const s = /[zZ]|[+-]\d\d:\d\d$/.test(ts) ? ts : ts + "Z";
  return new Date(s).getTime();
}

function fmtTime(ts) {
  // Always UTC, always this exact shape -- every source (cowrie/nginx/
  // suricata/wazuh containers, this dashboard's host) agrees on UTC, but
  // toLocaleTimeString was rendering in the *viewer's* browser TZ, which is
  // what actually made timestamps look like they didn't line up. DD/MM/YY
  // HH:MM:SS.UUU UTC removes that ambiguity outright.
  if (!ts) return "--/--/-- --:--:--.--- UTC";
  const d = new Date(toEpoch(ts));
  const pad = (n, len = 2) => String(n).padStart(len, "0");
  return `${pad(d.getUTCDate())}/${pad(d.getUTCMonth() + 1)}/${pad(d.getUTCFullYear() % 100)} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}.${pad(d.getUTCMilliseconds(), 3)} UTC`;
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

function appendLine(feedEl, innerHtml, statusClass, cap = 400, ts = null, detailKey = null) {
  // Newest at the top, always -- inserted by actual timestamp rather than
  // arrival order, because suricata and wazuh are independently-polled
  // tailers with different latency, so "just arrived" and "actually most
  // recent" aren't the same thing. Trimming (when capped) drops from the
  // bottom, i.e. the oldest entries, which is now the opposite end from
  // before.
  const placeholder = feedEl.querySelector(".empty");
  if (placeholder) placeholder.remove();
  const div = document.createElement("div");
  div.className = "line" + (statusClass ? " " + statusClass : "");
  div.innerHTML = innerHtml;
  const epoch = ts != null ? toEpoch(ts) : Date.now();
  div.dataset.epoch = epoch;
  if (detailKey) {
    div.classList.add("clickable");
    div.dataset.detailKey = detailKey;
  }

  let ref = feedEl.firstChild;
  while (ref && ref.dataset && Number(ref.dataset.epoch) > epoch) ref = ref.nextSibling;
  feedEl.insertBefore(div, ref);

  while (feedEl.children.length > cap) feedEl.removeChild(feedEl.lastChild);
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

// ---------- unified Defender | Attacker timeline ----------
// One time-sorted stream (newest at top). Each activity is an icon chip on
// its own side; the other side is left blank so both columns read against a
// single UTC time axis. Tap a chip -> the same generic detail modal.

const TL_CAP = 500;

function fmtClock(ts) {
  // Compact HH:MM:SS for the center rail (full timestamp is in the modal).
  if (!ts) return "--:--:--";
  const d = new Date(toEpoch(ts));
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function addTimelineEntry(side, ts, icon, statusClass, label, detailKey) {
  const placeholder = timelineEl.querySelector(".empty");
  if (placeholder) placeholder.remove();

  const row = document.createElement("div");
  row.className = `tl-row ${side}${statusClass ? " " + statusClass : ""}`;
  const epoch = ts != null ? toEpoch(ts) : Date.now();
  row.dataset.epoch = epoch;
  if (detailKey) row.dataset.detailKey = detailKey;
  row.innerHTML =
    `<span class="tl-ic">${icon}</span>` +
    `<span class="tl-tag">${side === "def" ? "DEF" : "ATK"}</span>` +
    `<span class="tl-label">${escapeHtml(label)}</span>` +
    `<span class="tl-time">${fmtClock(ts)}</span>`;

  // Insert by real timestamp, newest first -- defender/attacker streams and
  // bootstrap replays arrive out of order, so arrival order isn't time order.
  let ref = timelineEl.firstChild;
  while (ref && ref.dataset && Number(ref.dataset.epoch) > epoch) ref = ref.nextSibling;
  timelineEl.insertBefore(row, ref);

  while (timelineEl.children.length > TL_CAP) timelineEl.removeChild(timelineEl.lastChild);
}

// Defender-side verdict icon (colour comes from the chip's status class).
const VERDICT_ICON = {
  benign: "✅", suspicious: "⚠️", malicious: "⛔",
  needs_human: "\u{1F575}️", error: "❓",
};

// ---------- Attacker Diary (streamed rationales) ----------
// The attacker's own reasoning, unedited, in the order it happened. Sourced
// straight from pending_actions.rationale (the "why" it wrote before each
// action) and vuln_findings.description (what it judged worth exploiting) --
// no model call added, just surfacing text the agent already produces. Read
// top-to-bottom like a diary (oldest first); tap a line for the real action.

function addDiaryEntry(ts, kind, kindClass, context, text, detailKey) {
  if (!text) return;
  const placeholder = feedDiary.querySelector(".empty");
  if (placeholder) placeholder.remove();

  const entry = document.createElement("div");
  entry.className = "diary-entry" + (kindClass ? " " + kindClass : "");
  const epoch = ts != null ? toEpoch(ts) : Date.now();
  entry.dataset.epoch = epoch;
  if (detailKey) { entry.dataset.detailKey = detailKey; entry.classList.add("clickable"); }
  entry.innerHTML =
    `<div class="diary-meta"><span class="diary-time">${fmtClock(ts)}</span>` +
    `<span class="diary-kind ${kindClass || ""}">${escapeHtml(kind)}</span>` +
    (context ? `<span class="diary-ctx">${escapeHtml(context)}</span>` : "") + `</div>` +
    `<div class="diary-text">${escapeHtml(text)}</div>`;

  // Newest at top, inserted by real timestamp (bootstrap replays sorted, live
  // pushes interleave). No inner scrollbox -- the whole page scrolls, so a new
  // entry appears at the top without moving the reader's scroll position.
  let ref = feedDiary.firstChild;
  while (ref && ref.dataset && Number(ref.dataset.epoch) > epoch) ref = ref.nextSibling;
  feedDiary.insertBefore(entry, ref);

  while (feedDiary.children.length > 600) feedDiary.removeChild(feedDiary.lastChild);
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
  appendLine(feedEvents, buildEntry(row.ts, head, null), null, 400, row.ts, `events:${row.id}`);
}

// ---------- Defender Log (triage / alerts / block actions) ----------

function candidateCtx(candidateId) {
  const c = candidatesById.get(candidateId);
  if (!c) return `#${candidateId}`;
  return `#${candidateId} ${escapeHtml(c.src_ip || "?")} \u00b7 ${escapeHtml(c.rule || "")}`;
}

function candShort(candidateId) {
  const c = candidatesById.get(candidateId);
  return c ? (c.src_ip || `#${candidateId}`) : `#${candidateId}`;
}

function renderDefenderRow(table, row) {
  let icon, statusClass, label, ts = row.created;

  if (table === "triage") {
    statusClass = verdictStatusClass(row.verdict);
    icon = VERDICT_ICON[row.verdict] || "\u{1F9E0}";
    const conf = row.confidence != null ? Math.round(row.confidence * 100) + "%" : "\u2014";
    label = `${row.verdict} \u00b7 ${candShort(row.candidate_id)} \u00b7 ${conf}`;
  } else if (table === "agent_alerts") {
    statusClass = severityStatusClass(row.severity);
    icon = "\u{1F514}";
    label = `alert \u00b7 ${row.severity} \u00b7 ${candShort(row.candidate_id)}`;
    alertTimes.push(toEpoch(row.created));
  } else if (table === "human_pages") {
    // page_oncall() -- loudest tool the defender has (test stand-in, no real page).
    statusClass = "st-critical";
    icon = "\u{1F4DF}";
    label = `PAGE on-call \u00b7 ${candShort(row.candidate_id)}`;
    alertTimes.push(toEpoch(row.created));
  } else if (table === "block_recommendations") {
    statusClass = "st-warning";
    icon = "\u{1F6A7}";
    label = `block rec \u00b7 ${row.src_ip || ""}`;
  } else if (table === "block_ip_calls") {
    // REAL enforcement (iptables DROP, hard-fenced to the lab subnet). executed
    // vs a call the fence rejected (src_ip outside the lab's own docker subnet).
    const executed = !!row.executed;
    statusClass = executed ? "st-critical" : "st-muted";
    icon = executed ? "\u26D4" : "\ud83d\udeab";
    label = executed ? `IP BLOCKED \u00b7 ${row.src_ip || ""}` : `block rejected \u00b7 ${row.src_ip || ""}`;
  } else {
    return;
  }
  addTimelineEntry("def", ts, icon, statusClass, label, `${table}:${row.id}`);
}

// ---------- Attacker Campaigns (redteam_sessions + children) ----------

// Each attacker activity is one chip on the right column, labelled with its
// session (S<id>) so campaign context survives without grouping the stream
// into per-campaign cards (which is what cost the time-alignment before).

function ensureCampaign(row) {
  const prev = sessionsById.get(row.id);
  if (!prev) {
    addTimelineEntry("atk", row.created, "\u2694\ufe0f", "badge-running",
      `S${row.id} campaign \u00b7 ${row.model}`, `redteam_sessions:${row.id}`);
  } else if (prev.row.stage !== row.stage || prev.row.status !== row.status) {
    const cls = row.status === "completed" ? "st-good"
      : (row.status === "error" || row.status === "incomplete") ? "st-critical" : "";
    addTimelineEntry("atk", new Date().toISOString(), "\u{1F504}", cls,
      `S${row.id} ${row.stage}/${row.status}`, `redteam_sessions:${row.id}`);
  }
  sessionsById.set(row.id, { row });
}

function onReconFinding(row) {
  addTimelineEntry("atk", row.created, "\u{1F50D}", "",
    `S${row.session_id} recon: ${row.target} \u00b7 ${row.finding_type}`, `recon_findings:${row.id}`);
}

function onVulnFinding(row) {
  addTimelineEntry("atk", row.created, "\u{1F41B}", severityStatusClass(row.severity),
    `S${row.session_id} vuln ${row.severity}: ${row.category}`, `vuln_findings:${row.id}`);
  // Diary: what it judged worth exploiting, in its own words.
  addDiaryEntry(row.created, "found", "kind-found", `${row.severity} · ${row.category}`,
    row.description, `vuln_findings:${row.id}`);
}

function onPendingAction(row) {
  let icon, cls, verb, ts;
  if (row.executed) { icon = "\u{1F4A5}"; cls = "st-critical"; verb = "exec"; ts = row.executed_at || row.created; }
  else if (row.approved) { icon = "\u2705"; cls = "st-warning"; verb = "approved"; ts = row.approved_at || row.created; }
  else { icon = "\u{1F3AF}"; cls = "st-muted"; verb = "propose"; ts = row.created; }
  addTimelineEntry("atk", ts, icon, cls,
    `S${row.session_id} ${verb}: ${row.tool}\u2192${row.target}`, `pending_actions:${row.id}`);
  // Diary: the "why" it wrote before acting. Once per action (pending_actions
  // re-fire on approve/execute), timestamped at propose so it reads in order.
  if (row.rationale && !diariedIds.has(row.id)) {
    diariedIds.add(row.id);
    addDiaryEntry(row.created, "action", "kind-action", `${row.tool} \u2192 ${row.target}`,
      row.rationale, `pending_actions:${row.id}`);
  }
}

function onLoot(row) {
  addTimelineEntry("atk", row.created, "\u{1F4E6}", "",
    `S${row.session_id} loot: ${row.tool}${row.target ? " \u00b7 " + row.target : ""}`, `loot:${row.id}`);
}

function onCapturedFlag(row) {
  flagsTotal++;
  addTimelineEntry("atk", row.created, "\u{1F6A9}", "st-critical",
    `S${row.session_id} FLAG: ${row.target}`, `captured_flags:${row.id}`);
  updateStat("stat-flags", flagsTotal);
}

// wins are the attacker's OWN milestone claims (record_win) -- the diary's
// climax, in its own words. Shown as-is: the whole point is to see them next
// to the hard facts, overclaims and all, not to reconcile them.
function winTierClass(tier) {
  return { shell_or_creds: "st-critical", exploit_confirmed: "st-serious",
    vuln_identified: "st-warning", unconfirmed: "st-muted" }[tier] || "st-muted";
}

function onWin(row) {
  const cls = winTierClass(row.evidence_tier);
  addTimelineEntry("atk", row.created, "\u{1F3C6}", cls,
    `S${row.session_id} WIN [${row.evidence_tier}]: ${truncate(row.description, 70)}`,
    `wins:${row.id}`);
  addDiaryEntry(row.created, "milestone", "kind-milestone",
    `claims: ${row.evidence_tier}`, row.description, `wins:${row.id}`);
}

// ---------- In-Flight LLM Calls ----------
// llm_calls rows come from pipeline/llm_call_tracker.py: 'running' the
// instant a provider.complete()/run_stage_turn() call starts, flipped to
// 'completed'/'error' the instant it returns. GMI/local-model calls have
// been observed taking 10+ minutes with nothing else in the UI moving --
// this bar exists so that wait is visible, with the exact prompt behind it
// one click away, instead of looking indistinguishable from a hang.

const inflightBar = document.getElementById("inflight-bar");
// Two columns, not one flat wrap -- laid out (see style.css) to land under
// the exact same left/right split as Defender Log / Attacker Campaigns
// below, so a card's column tells you which side it's blocking at a
// glance, and the whole bar visually lines up with the columns it sits
// above instead of wrapping cards independently of them.
const inflightColsByComponent = {
  triage: document.getElementById("inflight-cards-defender"),
};
const inflightDefaultCol = document.getElementById("inflight-cards-attacker"); // redteam-recon / redteam-assess

function inflightColFor(component) {
  return inflightColsByComponent[component] || inflightDefaultCol;
}

const STALE_AFTER_S = 1800; // 30min -- past this, flag as possibly orphaned
                             // (e.g. the process that started it was killed)
                             // rather than genuinely still working.

function componentLabel(component) {
  return { "triage": "Triage", "redteam-recon": "Red-team · Recon", "redteam-assess": "Red-team · Assess" }[component] || component;
}

function fmtElapsed(seconds) {
  const s = Math.max(0, Math.floor(seconds));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  if (m >= 60) return `${Math.floor(m / 60)}h ${m % 60}m`;
  return `${m}:${String(rem).padStart(2, "0")}`;
}

function renderInflightCard(entry) {
  const { row, cardEl } = entry;
  const elapsedS = (Date.now() - toEpoch(row.started)) / 1000;
  const stale = elapsedS > STALE_AFTER_S;
  cardEl.classList.toggle("inflight-stale", stale);
  cardEl.innerHTML =
    `<div class="inflight-card-top">` +
    `<span class="inflight-dot"></span>` +
    `<span class="inflight-component">${escapeHtml(componentLabel(row.component))}</span>` +
    `<span class="inflight-elapsed">${fmtElapsed(elapsedS)}${stale ? " — stalled?" : ""}</span>` +
    `</div>` +
    `<div class="inflight-context">${escapeHtml(row.context_label)}</div>` +
    `<div class="inflight-meta">${escapeHtml(row.provider)}/${escapeHtml(row.model)}</div>`;
}

function onLlmCall(row) {
  if (row.status !== "running") {
    const existing = inflightById.get(row.id);
    if (existing) {
      existing.cardEl.remove();
      inflightById.delete(row.id);
    }
    inflightBar.classList.toggle("hidden", inflightById.size === 0);
    return;
  }
  let entry = inflightById.get(row.id);
  if (!entry) {
    const cardEl = document.createElement("div");
    cardEl.className = "inflight-card";
    cardEl.dataset.detailKey = `llm_calls:${row.id}`;
    cardEl.addEventListener("click", () => openDetailModal(cardEl.dataset.detailKey));
    inflightColFor(row.component).appendChild(cardEl);
    entry = { row, cardEl };
    inflightById.set(row.id, entry);
  } else {
    entry.row = row;
  }
  renderInflightCard(entry);
  inflightBar.classList.remove("hidden");
}

setInterval(() => {
  for (const entry of inflightById.values()) renderInflightCard(entry);
}, 1000);

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

// Server sends this when soc.db itself got replaced out from under it
// (reset.sh's --db wipe unlinks and recreates the file rather than
// clearing it in place -- see server.py's _db_identity docstring). Every
// id in the new file starts back at 1, which WOULD collide with whatever
// this tab already rendered from the pre-reset epoch, so the only correct
// move is to wipe all local state and pull a fresh /api/bootstrap rather
// than let old and new rows with the same id overwrite each other.
function resetLocalState() {
  feedEvents.innerHTML = "";
  timelineEl.innerHTML = "";
  feedDiary.innerHTML = "";
  diariedIds.clear();
  candidatesById.clear();
  sessionsById.clear();
  inflightById.clear();
  inflightColsByComponent.triage.innerHTML = "";
  inflightDefaultCol.innerHTML = "";
  inflightBar.classList.add("hidden");
  detailStore.clear();
  closeDetailModal();
  eventTimes = [];
  alertTimes = [];
  flagsTotal = 0;
  updateStat("stat-flags", 0);
}

function handleMessage(msg) {
  const { table, row } = msg;
  if (table === "_reset") { resetLocalState(); loadBootstrap(); return; }
  if (table !== "_error" && row && row.id != null) detailStore.set(`${table}:${row.id}`, { table, row });
  switch (table) {
    case "events": renderEventLine(row); eventTimes.push(toEpoch(row.ts)); break;
    case "candidates": onCandidate(row); break;
    case "triage": renderDefenderRow("triage", row); break;
    case "agent_alerts": renderDefenderRow("agent_alerts", row); break;
    case "human_pages": renderDefenderRow("human_pages", row); break;
    case "block_recommendations": renderDefenderRow("block_recommendations", row); break;
    case "block_ip_calls": renderDefenderRow("block_ip_calls", row); break;
    case "redteam_sessions": ensureCampaign(row); break;
    case "recon_findings": onReconFinding(row); break;
    case "vuln_findings": onVulnFinding(row); break;
    case "pending_actions": onPendingAction(row); break;
    case "loot": onLoot(row); break;
    case "captured_flags": onCapturedFlag(row); break;
    case "wins": onWin(row); break;
    case "llm_calls": onLlmCall(row); break;
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
  for (const t of ["triage", "agent_alerts", "human_pages", "block_recommendations", "block_ip_calls"]) {
    for (const row of data[t].rows) defenderRows.push({ table: t, row });
  }
  defenderRows.sort(byCreatedAsc);
  defenderRows.forEach(handleMessage);

  for (const row of data.redteam_sessions.rows) handleMessage({ table: "redteam_sessions", row });

  const campaignRows = [];
  for (const t of ["recon_findings", "vuln_findings", "pending_actions", "loot", "captured_flags", "wins"]) {
    for (const row of data[t].rows) campaignRows.push({ table: t, row });
  }
  campaignRows.sort(byCreatedAsc);
  campaignRows.forEach(handleMessage);

  for (const row of data.llm_calls.rows) handleMessage({ table: "llm_calls", row });

  recomputeOpenCandidates();
  recomputeActiveCampaigns();
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

// ---------- websocket ----------

function setConn(up) {
  const el = document.getElementById("conn");
  el.textContent = up ? "live" : "reconnecting\u2026";
  el.className = "conn-badge " + (up ? "conn-up" : "conn-down");
}

// Set once the very first connection succeeds, so a later reconnect can
// tell itself apart from the initial page load -- the initial load already
// gets a full bootstrap via the sequential loadBootstrap().finally(connectWS)
// call below, so re-triggering one in onopen there too would just be a
// redundant, wasted fetch. A RECONNECT is different: the socket was down
// for some stretch of real time (a network blip, laptop sleep, a server
// restart -- doesn't matter which) and this tab has no idea what it missed,
// because nothing here previously re-synced on reconnect. New live pushes
// resumed fine (this is a plain reconnect, not a "the db got replaced"
// _reset scenario), so it LOOKED healthy -- "live" badge and all -- while
// silently missing every row that arrived during the gap, forever, until
// someone thought to hit refresh. Treating a reconnect like a lighter-weight
// version of resetLocalState()'s resync closes that gap the same way.
let wsConnectedOnce = false;

function connectWS() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => {
    setConn(true);
    if (wsConnectedOnce) {
      resetLocalState();
      loadBootstrap().catch((e) => console.error("resync bootstrap failed", e));
    }
    wsConnectedOnce = true;
  };
  ws.onclose = () => { setConn(false); setTimeout(connectWS, 2000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    try { handleMessage(JSON.parse(ev.data)); } catch (e) { console.error(e); }
  };
}

// ---------- detail modal (click any line to drill in) ----------
// One generic renderer for every table: short scalar fields go in a
// definition list, anything long or multi-line (raw event lines, JSON
// blobs, LLM system/user prompts) gets its own <pre> block below it. Works
// unmodified for every row shape in detailStore -- there's no per-table
// special case because every table is just "a row of named fields," and
// that's all this needs to show.

const TABLE_LABELS = {
  events: "Event", candidates: "Candidate", triage: "Triage Verdict", agent_alerts: "Alert",
  human_pages: "Page On-Call", block_recommendations: "Block Recommendation",
  block_ip_calls: "Block IP Call", redteam_sessions: "Campaign Session",
  recon_findings: "Recon Finding", vuln_findings: "Vuln Finding", pending_actions: "Pending Action",
  loot: "Loot", captured_flags: "Captured Flag", wins: "Milestone / Win", llm_calls: "In-Flight LLM Call",
};

function looksLikeJson(s) {
  const t = s.trim();
  return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
}

function renderDetailBody(row) {
  // The attacker's rationale (or a finding's description) is the "why" behind
  // the row -- pull it out and show it prominently at the top instead of
  // buried alphabetically among input_json/result_json/etc.
  const why = row.rationale || row.description || null;
  const whyField = row.rationale ? "rationale" : row.description ? "description" : null;

  const dlRows = [];
  const blocks = [];
  for (const [k, v] of Object.entries(row)) {
    if (k === whyField) continue;  // shown prominently below, don't repeat it in the field list
    if (v === null || v === undefined || v === "") { dlRows.push([k, "—"]); continue; }
    let sv = typeof v === "string" ? v : JSON.stringify(v);
    if (typeof v === "string" && looksLikeJson(sv)) {
      try { sv = JSON.stringify(JSON.parse(sv), null, 2); } catch (e) { /* not actually JSON, leave as-is */ }
    }
    if (sv.length > 160 || sv.includes("\n")) blocks.push([k, sv]);
    else dlRows.push([k, sv]);
  }
  let html = "";
  if (why) {
    html += `<div class="detail-why"><div class="detail-why-label">` +
      `${row.rationale ? "why the attacker did this" : "reasoning"}</div>` +
      `<div class="detail-why-text">${escapeHtml(why)}</div></div>`;
  }
  html += "<dl>" + dlRows.map(([k, v]) => `<dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd>`).join("") + "</dl>";
  for (const [k, v] of blocks) html += `<h4>${escapeHtml(k)}</h4><pre>${escapeHtml(v)}</pre>`;
  return html;
}

const detailModal = document.getElementById("detail-modal");
const detailModalTitle = document.getElementById("modal-title");
const detailModalBody = document.getElementById("modal-body");

function closeDetailModal() {
  detailModal.classList.add("hidden");
}

function openDetailModal(key) {
  if (!key) return;
  const entry = detailStore.get(key);
  if (!entry) return;
  const { table, row } = entry;
  detailModalTitle.textContent = `${TABLE_LABELS[table] || table} #${row.id}`;
  detailModalBody.innerHTML = renderDetailBody(row);
  detailModal.classList.remove("hidden");
}

document.getElementById("modal-close").addEventListener("click", closeDetailModal);
detailModal.addEventListener("click", (e) => { if (e.target === detailModal) closeDetailModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDetailModal(); });

document.body.addEventListener("click", (e) => {
  // Telemetry feed lines and timeline rows both drill into the same modal.
  const target = e.target.closest(".line.clickable, .tl-row[data-detail-key], .diary-entry.clickable");
  if (!target) return;
  openDetailModal(target.dataset.detailKey);
});

// ---------- legend + side filter ----------

document.getElementById("legend-toggle").addEventListener("click", () => {
  document.getElementById("legend").classList.toggle("hidden");
});

// Segmented All / Defender / Attacker filter -- collapses the stream to one
// side (CSS hides the other's rows via timeline[data-filter]). "all" clears
// the attribute so both show.
document.querySelectorAll(".seg-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".seg-btn").forEach((b) => b.classList.toggle("active", b === btn));
    const f = btn.dataset.filter;
    if (f === "all") timelineEl.removeAttribute("data-filter");
    else timelineEl.setAttribute("data-filter", f);
  });
});

// ---------- tabs ----------

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.toggle("active", p.dataset.tab === target));
  });
});

// ---------- init ----------

document.querySelectorAll(".feed").forEach((f) => {
  f.innerHTML = '<div class="empty">waiting for data\u2026</div>';
});
timelineEl.innerHTML = '<div class="empty">waiting for data\u2026</div>';
feedDiary.innerHTML = '<div class="empty">waiting for the attacker to reason\u2026</div>';

loadBootstrap().catch((e) => console.error("bootstrap failed", e)).finally(connectWS);
