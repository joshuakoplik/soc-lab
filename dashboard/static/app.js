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

function addTimelineEntry(side, ts, icon, statusClass, label, detailKey, tool) {
  const placeholder = timelineEl.querySelector(".empty");
  if (placeholder) placeholder.remove();

  const row = document.createElement("div");
  row.className = `tl-row ${side}${statusClass ? " " + statusClass : ""}`;
  const epoch = ts != null ? toEpoch(ts) : Date.now();
  row.dataset.epoch = epoch;
  if (detailKey) row.dataset.detailKey = detailKey;
  row.dataset.etype = (detailKey || "").split(":")[0];
  if (tool) row.dataset.tool = tool;
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

// ---------- Timeline filters (show/hide event types) ----------
// Chips over the timeline toggle whole categories. Implemented as one generated
// <style> hiding [data-etype] selectors, so it applies to live-pushed rows too,
// not just the ones already on screen when you click.
const TL_FILTERS = [
  { key: "campaign", label: "campaign", etypes: ["redteam_sessions"] },
  { key: "recon",    label: "recon",    etypes: ["recon_findings"] },
  { key: "vuln",     label: "vuln",     etypes: ["vuln_findings"] },
  { key: "exploit",  label: "exploit",  etypes: ["pending_actions"] },
  { key: "loot",     label: "loot",     etypes: ["loot"] },
  { key: "win",      label: "win",      etypes: ["wins"] },
  { key: "flag",     label: "flag",     etypes: ["captured_flags"] },
  { key: "defender", label: "defender", etypes: ["triage", "agent_alerts", "human_pages", "block_recommendations", "block_ip_calls", "incidents", "leads", "hunt_notes", "hunt_sessions", "incident_handoffs", "chat_actions"] },
];
const hiddenFilters = new Set();

function rebuildFilterStyle() {
  const sel = [];
  for (const f of TL_FILTERS) {
    if (hiddenFilters.has(f.key)) {
      for (const e of (f.etypes || [])) sel.push(`#timeline [data-etype="${e}"]`);
      for (const t of (f.tools || [])) sel.push(`#timeline [data-tool="${t}"]`);
    }
  }
  let st = document.getElementById("tl-filter-style");
  if (!st) { st = document.createElement("style"); st.id = "tl-filter-style"; document.head.appendChild(st); }
  st.textContent = sel.length ? sel.join(",") + "{display:none!important}" : "";
}

function buildFilterBar() {
  const bar = document.getElementById("tl-filters");
  if (!bar) return;
  bar.innerHTML = "";
  for (const f of TL_FILTERS) {
    const b = document.createElement("button");
    b.className = "chip";
    b.type = "button";
    b.textContent = f.label;
    b.addEventListener("click", () => {
      if (hiddenFilters.has(f.key)) { hiddenFilters.delete(f.key); b.classList.remove("off"); }
      else { hiddenFilters.add(f.key); b.classList.add("off"); }
      rebuildFilterStyle();
    });
    bar.appendChild(b);
  }
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

// Recon/loot commentary is HARNESS-generated (deterministic templating of the
// recorded fields -- no model call, no narrative construction). Two tiers,
// kept visually distinct from the model's own voice:
//   kind-recon    -- carries the attacker's OWN text (its search query, its
//                    stated fetch reason, the exploit it chose to stage)
//   kind-observed -- plain facts the harness logged (nmap ran, a loot result)
function _parseDetail(s) { try { return JSON.parse(s || "{}"); } catch (e) { return {}; } }
function _shortUrl(u) { return (u || "").replace(/^https?:\/\/(www\.)?/, "").replace(/\/$/, ""); }
function _firstLine(s) {
  const line = (s || "").split("\n").map((x) => x.trim()).find((x) => x.length);
  return truncate(line || "", 100);
}

function addReconDiary(row) {
  const d = _parseDetail(row.detail);
  switch (row.finding_type) {
    case "port_scan":
      return addDiaryEntry(row.created, "scan", "kind-observed", row.target,
        `Ran nmap against ${row.target}`, `recon_findings:${row.id}`);
    case "web_search":
      return addDiaryEntry(row.created, "search", "kind-recon", null,
        `Searched: "${d.query || ""}"`, `recon_findings:${row.id}`);
    case "fetch_url":
      return addDiaryEntry(row.created, "fetch", "kind-recon", _shortUrl(d.url),
        d.reason || `Fetched ${_shortUrl(d.url)}`, `recon_findings:${row.id}`);
    case "stage_artifact":
      return addDiaryEntry(row.created, "staged", "kind-recon", `${d.file_count || "?"} files`,
        `Pulled in exploit code: ${_shortUrl(d.url)}`, `recon_findings:${row.id}`);
    // http_path probes (dozens per run) stay on the timeline only -- too
    // low-signal individually to belong in a readable diary.
    default:
      return;
  }
}

// Attach a loot result to the diary entry of the action that produced it (its
// rationale is already the diary line), so an action reads "why -> got what".
// Falls back to a standalone observed line when there's no owning action
// (recon-stage nmap loot) or its entry isn't present.
function addLootDiary(row) {
  const got = _firstLine(row.summary);
  if (!got) return;
  if (row.pending_action_id) {
    const host = feedDiary.querySelector(`.diary-entry[data-detail-key="pending_actions:${row.pending_action_id}"]`);
    if (host) {
      const t = host.querySelector(".diary-text");
      if (t && !t.querySelector(".diary-got")) {
        const g = document.createElement("div");
        g.className = "diary-got";
        g.textContent = "→ got: " + got;
        t.appendChild(g);
      }
      return;
    }
  }
  addDiaryEntry(row.created, "loot", "kind-observed", row.tool, "→ got: " + got, `loot:${row.id}`);
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
  addReconDiary(row);
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
    `S${row.session_id} ${verb}: ${row.tool}\u2192${row.target}`, `pending_actions:${row.id}`, row.tool);
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
    `S${row.session_id} loot: ${row.tool}${row.target ? " \u00b7 " + row.target : ""}`, `loot:${row.id}`, row.tool);
  addLootDiary(row);
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
  incidentRowById.clear();
  incidentEvById.clear();
  _incState.clear();
  _leadState.clear();
  _huntState.clear();
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
  resetChatState();
}

// ---------- Threat Hunter (incidents / notebook / leads) ----------
// The hunter is the operational defender now; its incidents, notebook and
// leads render into the Defender panel alongside the response actions
// (alerts/blocks/pages) it takes. Incidents and leads UPDATE in place (status
// firms up over the hunt); notebook entries are an append-only timeline.

const incidentRowById = new Map();   // id -> latest incident row
const incidentEvById = new Map();    // incident id -> Set("kind:ref_id")
const _incState = new Map();   // id -> "severity/status" last shown (no-op-update guard)
const _leadState = new Map();  // id -> status last shown
const _huntState = new Map();  // id -> status last shown

// Threat-hunter activity renders as single-line DEF entries INTERLEAVED into the
// unified timeline (not a separate card feed), so the hunt unfolds against the
// attacker's moves in real time -- tap any line for the full row. State maps keep
// a line from re-firing on a no-op update: only a genuine status/severity change
// adds a new line, so an incident's evolution reads as a short thread, not a flood.
function onHuntSession(row) {
  if (_huntState.get(row.id) === row.status) return;
  _huntState.set(row.id, row.status);
  const cls = row.status === "running" ? "badge-running" : row.status === "stopped" ? "st-muted" : "st-warning";
  addTimelineEntry("def", row.updated || row.created, "\u{1F9ED}", cls,
    `HUNT #${row.id} ${row.status} \u00b7 ${row.model || ""}`, `hunt_sessions:${row.id}`);
}

function onIncident(row) {
  incidentRowById.set(row.id, row);
  const key = `${row.severity}/${row.status}`;
  if (_incState.get(row.id) === key) return;
  _incState.set(row.id, key);
  const closed = row.status === "closed" || row.status === "false_positive";
  addTimelineEntry("def", row.updated_at || row.created, "\u{1F6A8}",
    closed ? "st-muted" : severityStatusClass(row.severity),
    `INCIDENT #${row.id} [${row.severity}/${row.status}]${row.entity ? " \u00b7 " + row.entity : ""} \u00b7 ${row.title || ""}`,
    `incidents:${row.id}`);
}

function onIncidentEvidence(row) {
  let set = incidentEvById.get(row.incident_id);
  if (!set) { set = new Set(); incidentEvById.set(row.incident_id, set); }
  set.add(`${row.kind}:${row.ref_id}`);
  // Evidence count shows in the incident's detail modal; no separate timeline line.
}

function onHuntNote(row) {
  const cls = { finding: "st-serious", decision: "st-info", hypothesis: "st-warning",
    lead: "st-info", observation: "st-muted" }[row.note_type] || "st-muted";
  addTimelineEntry("def", row.created, "\u{1F4DD}", cls,
    `note[${row.note_type || "note"}]${row.incident_id ? " inc#" + row.incident_id : ""}: ${truncate(row.body, 90)}`,
    `hunt_notes:${row.id}`);
}

function onLead(row) {
  if (_leadState.get(row.id) === row.status) return;
  _leadState.set(row.id, row.status);
  const sc = row.status === "dead" ? "st-muted" : row.status === "resolved" ? "st-good" : "st-info";
  addTimelineEntry("def", row.updated || row.created, "\u{1F9F5}", sc,
    `LEAD #${row.id} ${row.status}${row.incident_id ? " inc#" + row.incident_id : ""}: ${truncate(row.description, 80)}`,
    `leads:${row.id}`);
}

function handleMessage(msg) {
  const { table, row } = msg;
  if (table === "_reset") { resetLocalState(); loadBootstrap(); return; }
  if (table !== "_error" && row && row.id != null) detailStore.set(`${table}:${row.id}`, { table, row });
  if (window.mapConsume) window.mapConsume(table, row);   // live attack map (Attack Map tab)
  switch (table) {
    case "events": renderEventLine(row); eventTimes.push(toEpoch(row.ts)); break;
    case "candidates": onCandidate(row); break;
    case "triage": renderDefenderRow("triage", row); break;
    case "agent_alerts": renderDefenderRow("agent_alerts", row); break;
    case "human_pages": renderDefenderRow("human_pages", row); break;
    case "block_recommendations": renderDefenderRow("block_recommendations", row); break;
    case "block_ip_calls": renderDefenderRow("block_ip_calls", row); break;
    case "hunt_sessions": onHuntSession(row); break;
    case "incidents": onIncident(row); break;
    case "incident_evidence": onIncidentEvidence(row); break;
    case "hunt_notes": onHuntNote(row); break;
    case "leads": onLead(row); break;
    case "incident_handoffs": onIncidentHandoff(row); break;
    case "chat_sessions": onChatSession(row); break;
    case "chat_turns": onChatTurn(row); break;
    case "chat_actions": onChatAction(row); break;
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

  // Hunt state, in dependency order (session -> incidents -> evidence/notes/
  // leads). Rows arrive oldest-first from bootstrap; optional-chained so an
  // older server without these tables can't break the load.
  for (const t of ["hunt_sessions", "incidents", "incident_evidence", "hunt_notes", "leads",
                   "incident_handoffs"]) {
    for (const row of (data[t] && data[t].rows) || []) handleMessage({ table: t, row });
  }

  for (const t of ["chat_sessions", "chat_turns", "chat_actions"]) {
    for (const row of (data[t] && data[t].rows) || []) handleMessage({ table: t, row });
  }
  pickActiveChatIfNone();

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
  chat_turns: "Chat Turn", chat_sessions: "Chat Session", chat_actions: "Chat Action", chat_notes: "Chat Note",
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
  const target = e.target.closest(".line.clickable, .tl-row[data-detail-key], .diary-entry.clickable, .chat-turn[data-detail-key]");
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
    if (target === "map" && window.initMap) window.initMap();   // build/refresh the attack map on open
  });
});

// ---------- init ----------

document.querySelectorAll(".feed").forEach((f) => {
  f.innerHTML = '<div class="empty">waiting for data\u2026</div>';
});
timelineEl.innerHTML = '<div class="empty">waiting for data\u2026</div>';
feedDiary.innerHTML = '<div class="empty">waiting for the attacker to reason\u2026</div>';

buildFilterBar();
loadBootstrap().catch((e) => console.error("bootstrap failed", e)).finally(() => { connectWS(); initChat(); initLab(); });


// ---------- Analyst Chat ----------
// The interactive analyst tab. Unlike the rest of this client (which only
// renders), this one WRITES: it POSTs the operator's messages to /api/chat/*.
// It does NOT render the reply from that POST -- the agent logs each turn/tool
// row to chat_turns, and those stream back over the same /ws feed as every
// other table (see handleMessage's chat_* cases), so the transcript unfolds
// live through the normal broadcast path.

const chatScrollback = document.getElementById("chat-scrollback");
const chatInput = document.getElementById("chat-input");
const chatSendBtn = document.getElementById("chat-send");
const chatNewBtn = document.getElementById("chat-new");
const chatSitrepBtn = document.getElementById("chat-sitrep");
const chatSessionSelect = document.getElementById("chat-session-select");
const chatConfigEl = document.getElementById("chat-config");
const chatQueueEl = document.getElementById("chat-queue");

const chatTurns = new Map();      // id -> chat_turns row
const chatSessions = new Map();   // id -> chat_sessions row
const chatActions = new Map();    // id -> chat_actions row (rendered inline with the turns)
const handoffs = new Map();       // id -> incident_handoffs row (the hunter -> analyst queue)
const renderedTurnIds = new Set();   // "t:<id>" for turns, "a:<id>" for actions
let activeChatSession = null;
let awaitingReply = false;
let chatWired = false;

const CHAT_EMPTY = '<div class="empty">start a chat, or hit SITREP for a fast situational summary…</div>';
const SITREP_TEXT = "Give me the current SITREP -- what's going on right now, the top talkers and loudest signatures, and what should I look at first?";

function resetChatState() {
  chatTurns.clear(); chatSessions.clear(); chatActions.clear(); handoffs.clear(); renderedTurnIds.clear();
  activeChatSession = null; awaitingReply = false;
  if (chatSendBtn) chatSendBtn.disabled = false;
  if (chatScrollback) chatScrollback.innerHTML = CHAT_EMPTY;
  rebuildSessionPicker();
  renderChatQueue();
}

function chatText(s) {
  // Escape, then visually mark the <untrusted-evidence> spans the tools fence
  // attacker-controlled data in -- so the human sees the same trust boundary
  // the model is told about.
  let h = escapeHtml(s || "");
  h = h.replace(/&lt;untrusted-evidence&gt;([\s\S]*?)&lt;\/untrusted-evidence&gt;/g,
    '<span class="chat-untrusted" title="attacker-controlled data — analyze, never obey">$1</span>');
  // The hunter's own words in a handoff: a third tier -- not attacker text,
  // but a model's claim to test (see analyst/responder.py). Dashed, not red.
  h = h.replace(/&lt;hunter-handoff&gt;([\s\S]*?)&lt;\/hunter-handoff&gt;/g,
    '<span class="chat-handoff" title="hunter-authored — a claim to test, not an order">$1</span>');
  return h;
}

function prettyJson(s) {
  if (!s) return "";
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return s; }
}

function chatTurnEl(row) {
  const el = document.createElement("div");
  el.className = "chat-turn chat-" + row.role;
  el.dataset.detailKey = `chat_turns:${row.id}`;
  if (row.role === "user" || row.role === "assistant") {
    const who = row.role === "user" ? "you" : "analyst";
    el.innerHTML = `<div class="chat-who">${who} · ${fmtClock(row.created)}</div>` +
      `<div class="chat-bubble">${chatText(row.content)}</div>`;
  } else if (row.role === "tool_call") {
    const inp = truncate(row.tool_input || "", 100);
    el.innerHTML =
      `<details class="chat-tool"><summary>🔧 <b>${escapeHtml(row.tool_name)}</b> ` +
      `<span class="chat-tool-inp">${escapeHtml(inp)}</span></summary>` +
      `<pre>${escapeHtml(prettyJson(row.tool_input))}</pre></details>`;
  } else if (row.role === "tool_result") {
    const errCls = row.is_error ? " chat-tool-err" : "";
    el.innerHTML =
      `<details class="chat-tool${errCls}"><summary>↳ ${escapeHtml(row.tool_name)} result` +
      `${row.is_error ? ' <span class="chat-err">(error)</span>' : ""}</summary>` +
      `<div class="chat-tool-result">${chatText(row.tool_result_preview)}</div></details>`;
  } else {
    el.innerHTML = `<div class="chat-bubble">${chatText(row.content)}</div>`;
  }
  return el;
}

function chatActionEl(row) {
  const el = document.createElement("div");
  const failed = !row.executed && /"error"\s*:\s*"[^"]/.test(row.result_json || "");
  el.className = "chat-turn chat-action" + (failed ? " chat-action-err" : "");
  el.dataset.detailKey = `chat_actions:${row.id}`;
  const target = row.src_ip || row.target_ref || "";
  const state = row.executed ? "executed" : (failed ? "REJECTED" : "not executed");
  const inc = row.incident_id ? ` · inc#${row.incident_id}` : "";
  el.innerHTML = `<div class="chat-who">action · ${fmtClock(row.created)}</div>` +
    `<div class="chat-bubble chat-action-bubble">⚡ <b>${escapeHtml(row.kind)}</b> ${escapeHtml(target)} · ${state}${inc}` +
    (row.reason ? ` — ${escapeHtml(truncate(row.reason, 140))}` : "") + `</div>`;
  return el;
}

function chatAtBottom() {
  return chatScrollback.scrollHeight - chatScrollback.scrollTop - chatScrollback.clientHeight < 60;
}

function bumpWorkingToBottom() {
  const w = chatScrollback.querySelector(".chat-working");
  if (w) chatScrollback.appendChild(w);
}

function appendChatEl(key, el) {
  if (renderedTurnIds.has(key)) return;
  const stick = chatAtBottom();
  const placeholder = chatScrollback.querySelector(".empty");
  if (placeholder) placeholder.remove();
  chatScrollback.appendChild(el);
  renderedTurnIds.add(key);
  if (stick) chatScrollback.scrollTop = chatScrollback.scrollHeight;
}

function appendChatTurnEl(row) { appendChatEl(`t:${row.id}`, chatTurnEl(row)); }
function appendChatActionEl(row) { appendChatEl(`a:${row.id}`, chatActionEl(row)); }

function renderActiveChat() {
  renderedTurnIds.clear();
  chatScrollback.innerHTML = "";
  // Turns and response actions interleave by wall clock so an action shows
  // where in the conversation it happened; ties fall back to turn order.
  const items = [];
  for (const r of chatTurns.values()) {
    if (r.session_id === activeChatSession) items.push({ key: `t:${r.id}`, ts: r.created, seq: r.seq, el: () => chatTurnEl(r) });
  }
  for (const a of chatActions.values()) {
    if (a.session_id === activeChatSession) items.push({ key: `a:${a.id}`, ts: a.created, seq: Number.MAX_SAFE_INTEGER, el: () => chatActionEl(a) });
  }
  if (!items.length) { chatScrollback.innerHTML = CHAT_EMPTY; return; }
  items.sort((x, y) => (x.ts < y.ts ? -1 : x.ts > y.ts ? 1 : x.seq - y.seq));
  items.forEach((it) => { chatScrollback.appendChild(it.el()); renderedTurnIds.add(it.key); });
  chatScrollback.scrollTop = chatScrollback.scrollHeight;
}

function setActiveChat(id) {
  activeChatSession = id;
  if (chatSessionSelect) chatSessionSelect.value = String(id);
  setAwaiting(false);
  renderActiveChat();
  renderChatQueue();
}

function pickActiveChatIfNone() {
  if (activeChatSession !== null && chatSessions.has(activeChatSession)) return;
  let best = null;
  for (const r of chatSessions.values()) {
    if (r.status === "active" && (best === null || r.id > best)) best = r.id;
  }
  if (best !== null) setActiveChat(best);
  else rebuildSessionPicker();
}

function sessionLabel(r) {
  let t = r.title ? truncate(r.title, 40) : "(untitled)";
  if (r.incident_id) {
    // responder-opened session: title is "Incident #N -- <title>"; keep it short
    const rest = (r.title || "").replace(/^Incident #\d+\s*(--|—)\s*/, "");
    t = `Incident #${r.incident_id}` + (rest ? ` — ${truncate(rest, 32)}` : "");
  }
  return `#${r.id} ${t}${r.status !== "active" ? " · closed" : ""}`;
}

function rebuildSessionPicker() {
  if (!chatSessionSelect) return;
  const rows = [...chatSessions.values()].sort((a, b) => b.id - a.id);
  chatSessionSelect.innerHTML = "";
  if (!rows.length) {
    const o = document.createElement("option");
    o.value = ""; o.textContent = "no chats yet";
    chatSessionSelect.appendChild(o);
    return;
  }
  for (const r of rows) {
    const o = document.createElement("option");
    o.value = String(r.id); o.textContent = sessionLabel(r);
    if (r.id === activeChatSession) o.selected = true;
    chatSessionSelect.appendChild(o);
  }
}

function onChatSession(row) {
  chatSessions.set(row.id, row);
  rebuildSessionPicker();
}

function onChatTurn(row) {
  chatTurns.set(row.id, row);
  if (row.session_id !== activeChatSession) return;
  appendChatTurnEl(row);
  if (row.role === "assistant") setAwaiting(false);
  else if (awaitingReply) bumpWorkingToBottom();
  // A turn the responder started from its own process (or one we started)
  // shows the working indicator until the assistant row lands.
  else if (row.role === "user") setAwaiting(true);
}

function onChatAction(row) {
  chatActions.set(row.id, row);
  if (row.session_id === activeChatSession) {
    appendChatActionEl(row);
    if (awaitingReply) bumpWorkingToBottom();
  }
  // Mirror onto the Defender timeline: the hunter's own action tables no
  // longer receive rows, so this is where response actions are visible.
  const failed = !row.executed && /"error"\s*:\s*"[^"]/.test(row.result_json || "");
  addTimelineEntry("def", row.created, "\u26A1",
    row.executed ? (row.kind === "block_ip" ? "st-critical" : "st-serious") : "st-muted",
    `ANALYST ${row.kind}${row.src_ip ? " " + row.src_ip : ""}${row.incident_id ? " · inc#" + row.incident_id : ""}` +
    ` · ${row.executed ? "executed" : (failed ? "REJECTED" : "not executed")}` +
    (row.reason ? " · " + truncate(row.reason, 80) : ""),
    `chat_actions:${row.id}`);
}

function handoffStatusLabel(h) {
  if (h.status === "queued") return "queued";
  if (h.status === "in_progress") return "in progress";
  if (h.status === "unresolved") return "unresolved";
  const conf = h.confidence != null ? ` (${Number(h.confidence).toFixed(2)})` : "";
  return `resolved: ${h.verdict || "?"}${conf}`;
}

const _hoState = new Map();   // handoff id -> status last shown on the timeline

function onIncidentHandoff(row) {
  const prev = handoffs.get(row.id);
  handoffs.set(row.id, row);
  renderChatQueue();
  if (_hoState.get(row.id) !== row.status) {
    _hoState.set(row.id, row.status);
    const inc = incidentRowById.get(row.incident_id) || {};
    const label = row.status === "resolved"
      ? `HANDOFF #${row.id} inc#${row.incident_id} · verdict ${row.verdict}${row.confidence != null ? " (" + Number(row.confidence).toFixed(2) + ")" : ""} · ${inc.title || ""}`
      : `HANDOFF #${row.id} inc#${row.incident_id} · ${handoffStatusLabel(row)} · ${inc.title || ""}`;
    addTimelineEntry("def", row.updated_at || row.handed_at, "\u{1F4E8}",
      row.status === "resolved" ? (row.verdict === "confirmed" ? "st-serious" : "st-muted") : severityStatusClass(row.severity),
      label, `incident_handoffs:${row.id}`);
  }
  // The responder just finished this session's turn (its resolve/unresolved
  // flip lands with the assistant row, but be safe if that arrives later).
  if (prev && prev.status === "in_progress" && row.status !== "in_progress"
      && row.session_id === activeChatSession) setAwaiting(false);
}

const HANDOFF_LIVE_RANK = { in_progress: 0, queued: 1, unresolved: 2, resolved: 3 };
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function renderChatQueue() {
  if (!chatQueueEl) return;
  const rows = [...handoffs.values()];
  if (!rows.length) { chatQueueEl.innerHTML = '<div class="empty">no incidents handed off yet</div>'; return; }
  rows.sort((a, b) => {
    const la = HANDOFF_LIVE_RANK[a.status] ?? 9, lb = HANDOFF_LIVE_RANK[b.status] ?? 9;
    if (la !== lb) return la - lb;
    if (la <= 1) {   // live: brightest first, then oldest (the responder's own claim order)
      const sa = SEV_RANK[a.severity] ?? -1, sb = SEV_RANK[b.severity] ?? -1;
      if (sa !== sb) return sb - sa;
      return a.id - b.id;
    }
    return (b.updated_at || "") < (a.updated_at || "") ? -1 : 1;   // done: most recent first
  });
  const live = rows.filter((r) => r.status === "queued" || r.status === "in_progress").length;
  let html = `<div class="chat-queue-head">incident queue <span class="lab-dim">${live} live · ${rows.length - live} done</span></div>`;
  for (const r of rows.slice(0, 30)) {
    const inc = incidentRowById.get(r.incident_id) || {};
    const active = r.session_id != null && r.session_id === activeChatSession;
    const dot = `<span class="chat-queue-dot ${severityStatusClass(r.severity)}"></span>`;
    const title = escapeHtml(truncate(inc.title || "(incident)", 50));
    const entity = inc.entity ? ` <span class="lab-dim">${escapeHtml(inc.entity)}</span>` : "";
    const st = handoffStatusLabel(r);
    const stCls = r.status === "resolved" ? (r.verdict === "confirmed" ? "st-serious" : r.verdict === "false_positive" ? "st-good" : "st-warning")
                : r.status === "in_progress" ? "st-info" : r.status === "unresolved" ? "st-muted" : "st-warning";
    html += `<div class="chat-queue-item${active ? " is-active" : ""}${r.session_id == null ? " no-session" : ""}" ` +
      `data-session="${r.session_id != null ? r.session_id : ""}" data-detail-key="incident_handoffs:${r.id}">` +
      `${dot}<span class="chat-queue-inc">#${r.incident_id}</span> <span class="chat-queue-sev">${escapeHtml(r.severity)}</span> ` +
      `<span class="chat-queue-title">${title}</span>${entity}` +
      `<span class="chat-queue-status ${stCls}">${escapeHtml(st)}</span></div>`;
  }
  chatQueueEl.innerHTML = html;
}

function setAwaiting(on) {
  awaitingReply = on;
  if (chatSendBtn) chatSendBtn.disabled = on;
  const existing = chatScrollback.querySelector(".chat-working");
  if (on && !existing) {
    const w = document.createElement("div");
    w.className = "chat-working";
    w.textContent = "analyst is working…";
    chatScrollback.appendChild(w);
    chatScrollback.scrollTop = chatScrollback.scrollHeight;
  } else if (!on && existing) {
    existing.remove();
  }
}

async function chatPost(path, body) {
  const res = await fetch(path, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  if (!res.ok) {
    let detail = res.status;
    try { detail = (await res.json()).detail || detail; } catch (e) { /* keep status */ }
    throw new Error(detail);
  }
  return res.json();
}

async function newChat(sitrep) {
  try {
    const r = await chatPost("/api/chat/sessions", { sitrep: !!sitrep });
    // The chat_sessions row also arrives via /ws; seed a stub now so its
    // streamed turns render immediately against the right active session.
    chatSessions.set(r.session_id, { id: r.session_id, status: "active", title: null });
    setActiveChat(r.session_id);
    rebuildSessionPicker();
    if (sitrep) setAwaiting(true);
  } catch (e) { console.error("newChat failed", e); }
}

async function sendChat() {
  const text = chatInput.value.trim();
  if (!text || awaitingReply) return;
  let sid = activeChatSession;
  if (sid === null) { await newChat(false); sid = activeChatSession; }
  if (sid === null) return;
  chatInput.value = "";
  setAwaiting(true);
  try {
    await chatPost("/api/chat/messages", { session_id: sid, text });
  } catch (e) {
    setAwaiting(false);
    console.error("sendChat failed:", e.message);
  }
}

async function loadChatConfig() {
  if (!chatConfigEl) return;
  try {
    const c = await (await fetch("/api/chat/config")).json();
    const egress = c.egress ? '<span class="chat-egress on">egress ON</span>'
                            : '<span class="chat-egress">egress off</span>';
    chatConfigEl.innerHTML = `${escapeHtml(c.provider)}/${escapeHtml(c.model || "?")} · ${egress}`;
  } catch (e) {
    chatConfigEl.textContent = "chat unavailable";
  }
}

function initChat() {
  if (chatWired) { pickActiveChatIfNone(); return; }
  chatWired = true;
  loadChatConfig();
  pickActiveChatIfNone();
  chatSendBtn.addEventListener("click", sendChat);
  chatNewBtn.addEventListener("click", () => newChat(false));
  chatSitrepBtn.addEventListener("click", () => {
    if (activeChatSession === null) { newChat(true); return; }
    if (awaitingReply) return;
    setAwaiting(true);
    chatPost("/api/chat/messages", { session_id: activeChatSession, text: SITREP_TEXT })
      .catch((e) => { setAwaiting(false); console.error(e); });
  });
  chatSessionSelect.addEventListener("change", () => {
    const v = chatSessionSelect.value;
    if (v) setActiveChat(Number(v));
  });
  if (chatQueueEl) chatQueueEl.addEventListener("click", (e) => {
    const item = e.target.closest(".chat-queue-item");
    if (!item) return;
    const sid = item.dataset.session;
    if (sid) setActiveChat(Number(sid));
    else if (item.dataset.detailKey) openDetailModal(item.dataset.detailKey);
  });
  renderChatQueue();
  chatInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
}

// ======================================================================
// Lab Manager tab -- Phase 2. Shows lab state and drives it. Does NOT
// auto-refresh (that fights with typing/clicking): status is loaded on tab
// open, after each action, and via the Refresh button. Powerful pickers
// (dealer catalog, hunter/attacker launch) open modals. Mirrors the chat
// tab's action shape: POST an action, then re-fetch status.
// ======================================================================
const labBody = document.getElementById("lab-body");
const labConfigEl = document.getElementById("lab-config");
let labWired = false;
let labConfig = null;          // GET /api/lab/config (modes, templates, timers, hunter defaults)
let labBusy = false;
let labSelectedMode = null;    // mode chosen in the dropdown (persists across re-renders)
let labDealerTarget = "";      // dealer target picked from the catalog modal
let dealerCatalog = null;      // cached {cached, count, entries}
let labLastStatus = null;      // last status payload, for local re-render without a fetch

const LAB_PROVIDERS = ["gmi", "claude", "local", "fireworks"];

function labPanelActive() {
  const p = document.getElementById("panel-lab");
  return p && p.classList.contains("active");
}

async function labPost(path, body) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}

async function loadLabConfig() {
  try {
    labConfig = await (await fetch("/api/lab/config")).json();
    if (labConfigEl) labConfigEl.textContent = `modes: ${labConfig.modes.join(", ")}`;
  } catch (e) {
    if (labConfigEl) labConfigEl.textContent = "lab manager unavailable";
  }
}

function procRow(name, p) {
  const pid = p.pid ? ` <span class="lab-dim">pid ${p.pid}${p.adopted ? " · adopted" : ""}</span>` : "";
  const dot = p.up ? '<span class="lab-dot up"></span>' : '<span class="lab-dot"></span>';
  const launchable = (name === "hunter" || name === "analyst" || name === "attacker");
  let btns;
  if (p.up) {
    btns = `<button class="lab-btn" data-act="proc" data-name="${name}" data-op="stop">stop</button>`;
    if (launchable) btns += ` <button class="lab-btn" data-act="proc-launch" data-name="${name}">relaunch…</button>`;
    else btns += ` <button class="lab-btn" data-act="proc" data-name="${name}" data-op="restart">restart</button>`;
  } else if (launchable) {
    btns = `<button class="lab-btn" data-act="proc-launch" data-name="${name}">launch…</button>`;
  } else {
    btns = `<button class="lab-btn" data-act="proc" data-name="${name}" data-op="start">start</button>`;
  }
  return `<div class="lab-row">${dot}<span class="lab-name">${escapeHtml(name)}</span>
            <span class="lab-state">${p.up ? "up" : "down"}${pid}</span>
            <span class="lab-actions">${btns}</span></div>`;
}

function renderLab(s) {
  if (!labBody) return;
  labLastStatus = s;
  const modes = (labConfig && labConfig.modes) || ["easy", "hard", "wordpress", "northwind", "dealer"];
  const selMode = labSelectedMode || s.mode || modes[0];
  const modeOpts = modes.map((m) => `<option value="${m}"${m === selMode ? " selected" : ""}>${m}</option>`).join("");
  // Per-mode running-state view (from s.mode_state) -- what's ACTUALLY up, not
  // just the primary-mode label in lab_mode.json.
  // Single active-mode view: the SELECTED mode + one line for its target(s), with
  // a colored dot and up/down. (Only one mode runs at a time.) `up` = make this
  // the active mode (switch, exclusive); `down` = stop it. For dealer, `up` uses
  // the chosen target and cleanly replaces any running one (up.py --remove-orphans).
  const ms = s.mode_state || {};
  const shortLabel = (t) => { t = String(t || ""); return t.length > 46 ? t.slice(0, 46) + "…" : t; };
  const selSt = ms[selMode] || { up: false, containers: 0 };
  const selDot = `<span class="lab-dot${selSt.up ? " up" : ""}"></span>`;
  let targetSummary;
  if (selMode === "dealer") {
    const running = (selSt.targets || [])[0];
    if (selSt.up && running) {
      targetSummary = `<b>${escapeHtml(running.hostname || "?")}</b>${running.label ? ` <span class="lab-dim">(${escapeHtml(shortLabel(running.label))})</span>` : ""}`;
    } else if (labDealerTarget) {
      targetSummary = `<span class="lab-dim">down · chosen</span> ${escapeHtml(shortLabel(labDealerTarget))}`;
    } else {
      targetSummary = `<em class="lab-dim">down · no target chosen</em>`;
    }
  } else {
    targetSummary = selSt.up
      ? `<span class="lab-dim">up · ${selSt.containers} container${selSt.containers === 1 ? "" : "s"}</span>`
      : `<span class="lab-dim">down</span>`;
  }
  const otherUp = modes.filter((m) => m !== selMode && (ms[m] || {}).up);
  const otherUpNote = otherUp.length
    ? `<div class="lab-line lab-dim">also running: ${otherUp.map(escapeHtml).join(", ")}</div>` : "";
  const posture = s.posture || "insider";
  const postureBtns = ["remote", "insider"].map((p) =>
    `<button class="lab-btn${p === posture ? " lab-btn-on" : ""}" data-act="posture" data-posture="${p}">${p}</button>`).join("");
  const templates = (labConfig && labConfig.flock_templates) || [];
  const tmplOpts = ['<option value="">template…</option>']
    .concat(templates.map((t) => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`)).join("");
  const liveFlocks = s.flocks || [];
  const flockRows = liveFlocks.length ? liveFlocks.map((f) => {
    const dot = f.traffic ? '<span class="lab-dot up"></span>' : '<span class="lab-dot"></span>';
    const trafBtn = f.clients > 0
      ? (f.traffic
          ? `<button class="lab-btn" data-act="flock-traffic" data-op="stop" data-flock="${escapeHtml(f.name)}">traffic off</button>`
          : `<button class="lab-btn" data-act="flock-traffic" data-op="start" data-flock="${escapeHtml(f.name)}">traffic on</button>`)
      : '<span class="lab-dim">no clients</span>';
    return `<div class="lab-row">${dot}<span class="lab-name">${escapeHtml(f.name)}</span>
              <span class="lab-state">clients ${f.clients} · traffic ${f.traffic ? "on" : "off"}</span>
              <span class="lab-actions">${trafBtn}
                <button class="lab-btn" data-act="flock-down" data-flock="${escapeHtml(f.name)}">down</button></span></div>`;
  }).join("") : '<div class="lab-dim" style="padding:4px 0">no live flocks</div>';

  const pol = s.policies || {};
  const polBoxes = Object.keys(pol).map((k) => {
    const label = k.replace("policy_", "");
    return `<label class="lab-toggle"><input type="checkbox" data-act="policy" data-key="${k}"${pol[k] ? " checked" : ""}> ${label}</label>`;
  }).join("");
  const sup = s.supervisor || {};
  const cfg = s.config || {};
  const h = s.signals && s.signals.hunter;
  const ho = s.signals && s.signals.handoffs;
  const runs = (s.signals && s.signals.active_attack_runs) || [];

  let procs = "";
  Object.keys(s.processes || {}).forEach((name) => { procs += procRow(name, s.processes[name]); });

  labBody.innerHTML = `
    <div class="lab-topbar">
      <button class="lab-btn" data-act="refresh">refresh</button>
      <span class="lab-dim">no auto-refresh &middot; updates after each action</span>
    </div>
    <div class="lab-grid">
      <div class="lab-card">
        <h3>Mode</h3>
        <div class="lab-controls"><select id="lab-mode-select">${modeOpts}</select></div>
        <div class="lab-mode-target">${selDot}<span class="lab-mode-tsummary">${targetSummary}</span></div>
        <div class="lab-controls">
          ${selMode === "dealer"
            ? `<button class="lab-btn" data-act="dealer-pick" title="pick a Vulhub or designed target">choose target…</button>`
            : ""}
          <button class="lab-btn lab-btn-primary" data-act="mode" data-verb="up" title="${selMode === "dealer" ? "start the chosen dealer target" : "bring this mode up"}">up</button>
          <button class="lab-btn" data-act="mode" data-verb="switch" title="make this the only active mode (tears down every other)">switch</button>
          <button class="lab-btn lab-btn-danger" data-act="mode" data-verb="down" title="tear this mode down">down</button>
        </div>
        ${otherUpNote}
        <div class="lab-line lab-dim">up = start ${selMode === "dealer" ? "chosen target" : "this mode"} · switch = make exclusive · down = stop</div>
        <div class="lab-posture">posture: <b>${escapeHtml(posture)}</b> ${postureBtns}</div>
      </div>

      <div class="lab-card">
        <h3>Processes</h3>
        ${procs}
      </div>

      <div class="lab-card">
        <h3>Supervisor <span class="lab-dim">${sup.up ? "running · pid " + sup.pid : "stopped"}</span></h3>
        <div class="lab-controls">
          ${sup.up
            ? '<button class="lab-btn" data-act="sup" data-op="stop">stop watch</button>'
            : '<button class="lab-btn" data-act="sup" data-op="start">start watch</button>'}
        </div>
        <div class="lab-policies">${polBoxes}</div>
        <div class="lab-line lab-dim">idle_timeout ${cfg.idle_timeout || "?"}s · drain_max ${cfg.attack_drain_max || "?"}s
          <button class="lab-btn lab-btn-sm" data-act="timers">edit…</button></div>
      </div>

      <div class="lab-card">
        <h3>NPC flocks <span class="lab-dim">traffic = benign client generator</span></h3>
        <div class="lab-controls">
          <select id="lab-flock-template">${tmplOpts}</select>
          <button class="lab-btn" data-act="flock" data-op="up">up</button>
        </div>
        ${flockRows}
      </div>

      <div class="lab-card">
        <h3>Signals</h3>
        <div class="lab-line">${h ? `hunt #${h.hunt_id} · ${escapeHtml(h.status)} · ${h.chunk_count} chunks · ${escapeHtml(h.provider)}/${escapeHtml(h.model)}` : "no active hunt"}</div>
        <div class="lab-line">${ho ? `handoffs: ${ho.queued} queued · ${ho.in_progress} in progress · ${ho.resolved} resolved · ${ho.unresolved} unresolved` : "no handoffs"}</div>
        <div class="lab-line">${runs.length ? "attack runs: " + runs.map((r) => `#${r.id}(${escapeHtml(r.stage)})`).join(", ") : "no active attack runs"}</div>
      </div>

      <div class="lab-card lab-danger">
        <h3>Reset</h3>
        <div class="lab-reset-opts">
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--network" checked> network <span class="lab-reset-hint">undo block_ip rules</span></label>
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--queue" checked> queue <span class="lab-reset-hint">reseed ingest to EOF</span></label>
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--attacker" checked> attacker <span class="lab-reset-hint">rebuild kali + clear loot</span></label>
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--target" checked> target <span class="lab-reset-hint">rebuild active target</span></label>
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--hunt" checked> hunt <span class="lab-reset-hint">clear standing hunt state</span></label>
          <label class="lab-reset-opt"><input type="checkbox" class="lab-reset-flag" value="--db" data-destructive="1" checked> db <span class="lab-reset-hint">wipe soc.db (destructive)</span></label>
        </div>
        <div class="lab-controls">
          <button class="lab-btn lab-btn-danger" data-act="reset-all">Reset checked</button>
        </div>
      </div>
    </div>
    <div id="lab-msg" class="lab-msg"></div>`;
}

function labMsg(text, isErr) {
  const el = document.getElementById("lab-msg");
  if (el) { el.textContent = text; el.className = "lab-msg" + (isErr ? " err" : ""); }
}

async function refreshLab() {
  if (!labBody) return;
  try {
    const s = await (await fetch("/api/lab/status?docker=false")).json();
    renderLab(s);
  } catch (e) {
    labBody.innerHTML = `<div class="empty">lab status failed: ${escapeHtml(String(e))}</div>`;
  }
}

async function labAction(fn) {
  if (labBusy) return;
  labBusy = true;
  try {
    await fn();
  } catch (e) {
    labMsg(String(e.message || e), true);
  } finally {
    try { await refreshLab(); } catch (_) { /* keep the error message visible */ }
    labBusy = false;
  }
}

// POST a process action and raise if the process crashed on launch, so the
// operator sees WHY instead of a silent "started" that's already gone.
async function postProc(body) {
  const r = await labPost("/api/lab/process", body);
  if (r && r.crashed) {
    const tail = (r.error || "").split("\n").slice(-6).join("\n");
    throw new Error(`${body.name} launched but exited immediately -- see ${body.name}.log:\n${tail}`);
  }
  return r;
}

// ---------- modal helper ----------
function closeLabModal() {
  const m = document.getElementById("lab-modal");
  if (m) m.remove();
}

function openLabModal(title, bodyHtml) {
  closeLabModal();
  const overlay = document.createElement("div");
  overlay.id = "lab-modal";
  overlay.className = "lab-modal-overlay";
  overlay.innerHTML = `
    <div class="lab-modal-card" role="dialog" aria-modal="true">
      <div class="lab-modal-head">
        <h3>${escapeHtml(title)}</h3>
        <button class="lab-btn" data-modal="close">close</button>
      </div>
      <div class="lab-modal-body">${bodyHtml}</div>
    </div>`;
  overlay.addEventListener("click", (e) => { if (e.target === overlay) closeLabModal(); });
  overlay.querySelector('[data-modal="close"]').addEventListener("click", closeLabModal);
  document.body.appendChild(overlay);
  return overlay.querySelector(".lab-modal-card");
}

// ---------- dealer target picker ----------
function catalogListHtml(entries, filter) {
  const f = (filter || "").toLowerCase();
  const rows = entries.filter((e) =>
    !f || e.target.toLowerCase().includes(f) || (e.title || "").toLowerCase().includes(f) ||
    (e.description || "").toLowerCase().includes(f)
  ).slice(0, 400).map((e) => `
    <div class="lab-cat-row" data-target="${escapeHtml(e.target)}">
      <div class="lab-cat-target">${escapeHtml(e.target)}</div>
      <div class="lab-cat-desc">${escapeHtml(e.description || e.title || "")}</div>
    </div>`).join("");
  return rows || '<div class="lab-dim" style="padding:8px">no matches</div>';
}

async function openDealerPicker() {
  const card = openLabModal("Choose a Vulhub target",
    '<input id="lab-cat-search" class="lab-input lab-cat-search" placeholder="filter by software / CVE / text, or type a target ref…">' +
    '<div id="lab-cat-list"><div class="lab-dim" style="padding:8px">loading catalog…</div></div>' +
    '<div id="lab-cat-foot" class="lab-modal-foot"></div>');
  const listEl = card.querySelector("#lab-cat-list");
  const footEl = card.querySelector("#lab-cat-foot");
  const searchEl = card.querySelector("#lab-cat-search");

  function choose(target) {
    if (!target) return;
    labDealerTarget = target;
    closeLabModal();
    if (labLastStatus) renderLab(labLastStatus);
    labMsg(`dealer target set: ${target}`);
  }

  function wireList() {
    listEl.querySelectorAll(".lab-cat-row").forEach((row) => {
      row.addEventListener("click", () => choose(row.dataset.target));
    });
  }

  function renderCat() {
    if (!dealerCatalog) return;
    if (dealerCatalog.cached && dealerCatalog.entries.length) {
      listEl.innerHTML = catalogListHtml(dealerCatalog.entries, searchEl.value);
      footEl.innerHTML = `<span class="lab-dim">${dealerCatalog.count} targets in local cache</span>`;
      wireList();
    } else {
      const sugg = (labConfig && labConfig.dealer_suggestions) || [];
      listEl.innerHTML =
        '<div class="lab-dim" style="padding:8px">Vulhub catalog not fetched yet. Fetch it (a shallow git clone; takes a minute), or pick a well-known target below.</div>' +
        sugg.map((t) => `<div class="lab-cat-row" data-target="${escapeHtml(t)}"><div class="lab-cat-target">${escapeHtml(t)}</div></div>`).join("");
      footEl.innerHTML = '<button class="lab-btn" id="lab-cat-fetch">fetch Vulhub catalog</button>';
      wireList();
      const fetchBtn = footEl.querySelector("#lab-cat-fetch");
      if (fetchBtn) fetchBtn.addEventListener("click", async () => {
        fetchBtn.disabled = true; fetchBtn.textContent = "fetching… (git clone)";
        try {
          await labPost("/api/lab/dealer_catalog/fetch", {});
          dealerCatalog = await (await fetch("/api/lab/dealer_catalog")).json();
          renderCat();
        } catch (e) {
          footEl.innerHTML = `<span class="lab-msg err">${escapeHtml(String(e.message || e))}</span>`;
        }
      });
    }
  }

  // "type a target ref" free-text: Enter accepts whatever's typed (any Vulhub
  // software/CVE or image ref stays valid even if it's not in the cache).
  searchEl.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      const v = searchEl.value.trim();
      if (v && dealerCatalog && dealerCatalog.cached &&
          !dealerCatalog.entries.some((x) => x.target === v)) { choose(v); return; }
      if (v && (!dealerCatalog || !dealerCatalog.cached)) { choose(v); return; }
    }
  });
  searchEl.addEventListener("input", () => { if (dealerCatalog && dealerCatalog.cached) renderCat(); });

  try {
    dealerCatalog = await (await fetch("/api/lab/dealer_catalog")).json();
  } catch (e) {
    dealerCatalog = { cached: false, entries: [] };
  }
  renderCat();
  searchEl.focus();
}

// ---------- hunter / attacker launch ----------
function providerSelect(id, current) {
  const provs = (labConfig && labConfig.providers) || LAB_PROVIDERS;
  return `<select id="${id}">` + provs.map((p) =>
    `<option value="${p}"${p === current ? " selected" : ""}>${p}</option>`).join("") + "</select>";
}

// A provider-aware model <select> + a hidden "custom" input for anything not in
// the list (the agents accept any model string, so the list is a convenience).
function modelOptionsHtml(provider, current) {
  const models = (labConfig && labConfig.models && labConfig.models[provider]) || [];
  const def = (labConfig && labConfig.default_model && labConfig.default_model[provider]) || "";
  const sel = current || def;
  const seen = new Set();
  let opts = "";
  models.forEach((m) => {
    if (m && !seen.has(m)) { seen.add(m); opts += `<option value="${escapeHtml(m)}"${m === sel ? " selected" : ""}>${escapeHtml(m)}</option>`; }
  });
  if (sel && !seen.has(sel)) opts = `<option value="${escapeHtml(sel)}" selected>${escapeHtml(sel)}</option>` + opts;
  opts += '<option value="__custom__">custom…</option>';
  return opts;
}

function modelFieldHtml(prefix, provider, current) {
  return `<span class="lab-model-field">` +
         `<select id="${prefix}-model">${modelOptionsHtml(provider, current)}</select>` +
         `<button type="button" class="lab-btn lab-btn-sm" id="${prefix}-model-refresh" title="re-query providers">↻</button>` +
         `<input id="${prefix}-model-custom" class="lab-input lab-hidden" placeholder="custom model id"></span>`;
}

// Wire a modal's provider+model selects: switching provider repopulates the
// model list; choosing "custom..." reveals the free-text input.
function wireModelControls(card, prefix) {
  const provSel = card.querySelector(`#${prefix}-provider`);
  const modelSel = card.querySelector(`#${prefix}-model`);
  const customIn = card.querySelector(`#${prefix}-model-custom`);
  function syncCustom() {
    const isCustom = modelSel.value === "__custom__";
    customIn.classList.toggle("lab-hidden", !isCustom);
    if (isCustom) customIn.focus();
  }
  provSel.addEventListener("change", () => {
    modelSel.innerHTML = modelOptionsHtml(provSel.value, null);
    syncCustom();
  });
  modelSel.addEventListener("change", syncCustom);
  const refreshBtn = card.querySelector(`#${prefix}-model-refresh`);
  if (refreshBtn) refreshBtn.addEventListener("click", async () => {
    refreshBtn.disabled = true; const prev = refreshBtn.textContent; refreshBtn.textContent = "…";
    try {
      await labPost("/api/lab/models/refresh", {});
      await loadLabConfig();                       // pull the fresh catalog into labConfig
      modelSel.innerHTML = modelOptionsHtml(provSel.value, null);
      syncCustom();
    } catch (e) {
      labMsg(String(e.message || e), true);
    } finally {
      refreshBtn.disabled = false; refreshBtn.textContent = prev;
    }
  });
}

function readModel(card, prefix) {
  const sel = card.querySelector(`#${prefix}-model`).value;
  if (sel === "__custom__") return card.querySelector(`#${prefix}-model-custom`).value.trim() || null;
  return sel || null;
}

function openHunterLaunch() {
  const hp = (labConfig && labConfig.hunter) || {};
  const tm = (labConfig && labConfig.timers) || {};
  const card = openLabModal("Launch threat hunter", `
    <div class="lab-form">
      <label>provider ${providerSelect("hl-provider", hp.provider || "gmi")}</label>
      <label>model ${modelFieldHtml("hl", hp.provider || "gmi", hp.model)}</label>
      <label>max iterations <input id="hl-maxiter" class="lab-input" type="number" placeholder="15"></label>
      <label>context budget <input id="hl-ctxbudget" class="lab-input" type="number" placeholder="70000"></label>
      <label class="lab-toggle"><input id="hl-new" type="checkbox"> start a fresh hunt (--new)</label>
      <hr class="lab-hr">
      <div class="lab-dim">supervisor auto-stop (labctl policy):</div>
      <label>idle timeout (s) <input id="hl-idle" class="lab-input" type="number" value="${tm.idle_timeout || ""}"></label>
      <label>attack drain max (s) <input id="hl-drain" class="lab-input" type="number" value="${tm.attack_drain_max || ""}"></label>
      <div class="lab-modal-foot"><button class="lab-btn" id="hl-go">launch hunter</button></div>
    </div>`);
  wireModelControls(card, "hl");
  card.querySelector("#hl-go").addEventListener("click", async () => {
    const provider = card.querySelector("#hl-provider").value;
    const model = readModel(card, "hl");
    const extra = [];
    const mi = card.querySelector("#hl-maxiter").value.trim();
    if (mi) extra.push("--max-iterations", mi);
    const cb = card.querySelector("#hl-ctxbudget").value.trim();
    if (cb) extra.push("--context-budget", cb);
    if (card.querySelector("#hl-new").checked) extra.push("--new");
    const updates = {};
    const idle = card.querySelector("#hl-idle").value.trim();
    if (idle) updates.idle_timeout = Number(idle);
    const drain = card.querySelector("#hl-drain").value.trim();
    if (drain) updates.attack_drain_max = Number(drain);
    closeLabModal();
    labMsg(`launching hunter (${provider}${model ? "/" + model : ""})…`);
    labAction(async () => {
      if (Object.keys(updates).length) await labPost("/api/lab/config", { updates });
      await postProc({ name: "hunter", action: "restart", provider, model, extra });
    });
  });
}

function openAnalystLaunch() {
  const ap = (labConfig && labConfig.analyst) || (labConfig && labConfig.hunter) || {};
  const card = openLabModal("Launch analyst responder", `
    <div class="lab-form">
      <label>provider ${providerSelect("an-provider", ap.provider || "gmi")}</label>
      <label>model ${modelFieldHtml("an", ap.provider || "gmi", ap.model)}</label>
      <label>max iterations <input id="an-maxiter" class="lab-input" type="number" placeholder="24"></label>
      <label>poll interval (s) <input id="an-poll" class="lab-input" type="number" placeholder="5"></label>
      <div class="lab-dim">drains the hunter's incident handoffs: one chat session per incident, verdict + response. Idle costs no tokens; no supervisor auto-stop.</div>
      <div class="lab-modal-foot"><button class="lab-btn" id="an-go">launch analyst</button></div>
    </div>`);
  wireModelControls(card, "an");
  card.querySelector("#an-go").addEventListener("click", async () => {
    const provider = card.querySelector("#an-provider").value;
    const model = readModel(card, "an");
    const extra = [];
    const mi = card.querySelector("#an-maxiter").value.trim();
    if (mi) extra.push("--max-iterations", mi);
    const pi = card.querySelector("#an-poll").value.trim();
    if (pi) extra.push("--poll-interval", pi);
    closeLabModal();
    labMsg(`launching analyst (${provider}${model ? "/" + model : ""})…`);
    labAction(() => postProc({ name: "analyst", action: "restart", provider, model, extra }));
  });
}

function openAttackerLaunch() {
  const hp = (labConfig && labConfig.hunter) || {};
  const card = openLabModal("Launch red-team attacker", `
    <div class="lab-form">
      <label>provider ${providerSelect("al-provider", hp.provider || "gmi")}</label>
      <label>model ${modelFieldHtml("al", hp.provider || "gmi", hp.model)}</label>
      <label>max iterations <input id="al-maxiter" class="lab-input" type="number" placeholder="30"></label>
      <label>global token budget <input id="al-budget" class="lab-input" type="number" placeholder="2000000"></label>
      <label class="lab-toggle"><input id="al-loop" type="checkbox"> loop assess until done (--loop)</label>
      <div class="lab-dim">runs a campaign against the active mode's target(s). Gated tools still need approval unless the target is auto-whitelisted.</div>
      <div class="lab-modal-foot"><button class="lab-btn" id="al-go">launch attacker</button></div>
    </div>`);
  wireModelControls(card, "al");
  card.querySelector("#al-go").addEventListener("click", async () => {
    const provider = card.querySelector("#al-provider").value;
    const model = readModel(card, "al");
    const extra = [];
    const mi = card.querySelector("#al-maxiter").value.trim();
    if (mi) extra.push("--max-iterations", mi);
    const b = card.querySelector("#al-budget").value.trim();
    if (b) extra.push("--global-token-budget", b);
    if (card.querySelector("#al-loop").checked) extra.push("--loop");
    closeLabModal();
    labMsg(`launching attacker (${provider}${model ? "/" + model : ""})…`);
    labAction(() => postProc({ name: "attacker", action: "restart", provider, model, extra }));
  });
}

function openTimersModal() {
  const tm = (labConfig && labConfig.timers) || (labLastStatus && labLastStatus.config) || {};
  const card = openLabModal("Supervisor timers", `
    <div class="lab-form">
      <label>idle timeout (s) <input id="tm-idle" class="lab-input" type="number" value="${tm.idle_timeout || ""}"></label>
      <label>attack drain max (s) <input id="tm-drain" class="lab-input" type="number" value="${tm.attack_drain_max || ""}"></label>
      <label>poll interval (s) <input id="tm-poll" class="lab-input" type="number" value="${tm.poll_interval || ""}"></label>
      <label>detect interval (s) <input id="tm-detect" class="lab-input" type="number" value="${tm.detect_interval || ""}"></label>
      <div class="lab-modal-foot"><button class="lab-btn" id="tm-go">save</button></div>
    </div>`);
  card.querySelector("#tm-go").addEventListener("click", () => {
    const updates = {};
    const map = { "tm-idle": "idle_timeout", "tm-drain": "attack_drain_max",
                  "tm-poll": "poll_interval", "tm-detect": "detect_interval" };
    Object.keys(map).forEach((id) => {
      const v = card.querySelector("#" + id).value.trim();
      if (v) updates[map[id]] = Number(v);
    });
    closeLabModal();
    labMsg("saving supervisor timers…");
    labAction(async () => {
      if (Object.keys(updates).length) await labPost("/api/lab/config", { updates });
      await loadLabConfig();
    });
  });
}

function onLabClick(ev) {
  const t = ev.target.closest("[data-act]");
  if (!t) return;
  const act = t.dataset.act;

  if (act === "refresh") {
    refreshLab();
  } else if (act === "mode") {
    const mode = document.getElementById("lab-mode-select").value;
    labSelectedMode = mode;
    const target = mode === "dealer" ? (labDealerTarget || null) : null;
    if (mode === "dealer" && t.dataset.verb !== "down" && !target) {
      labMsg("choose a dealer target first", true); return;
    }
    labMsg(`running: ${t.dataset.verb} ${mode}${target ? " " + target : ""}…`);
    labAction(() => labPost("/api/lab/mode", { verb: t.dataset.verb, mode, target }));
  } else if (act === "dealer-pick") {
    openDealerPicker();
  } else if (act === "posture") {
    const p = t.dataset.posture;
    labMsg(`setting posture → ${p}…`);
    labAction(() => labPost("/api/lab/mode", { verb: "posture", mode: p }));
  } else if (act === "proc-launch") {
    if (t.dataset.name === "hunter") openHunterLaunch();
    else if (t.dataset.name === "analyst") openAnalystLaunch();
    else openAttackerLaunch();
  } else if (act === "proc") {
    labMsg(`${t.dataset.op} ${t.dataset.name}…`);
    labAction(() => postProc({ name: t.dataset.name, action: t.dataset.op }));
  } else if (act === "sup") {
    labMsg(`supervisor ${t.dataset.op}…`);
    labAction(() => labPost("/api/lab/supervisor", { action: t.dataset.op }));
  } else if (act === "policy") {
    const policies = {}; policies[t.dataset.key] = t.checked;
    labMsg(`policy ${t.dataset.key} → ${t.checked}`);
    labAction(() => labPost("/api/lab/supervisor", { action: "policies", policies }));
  } else if (act === "timers") {
    openTimersModal();
  } else if (act === "flock") {
    const template = document.getElementById("lab-flock-template").value;
    if (!template) { labMsg("pick a flock template", true); return; }
    labMsg(`flock up ${template}…`);
    labAction(() => labPost("/api/lab/flock", { action: "up", name: template }));
  } else if (act === "flock-traffic") {
    const action = t.dataset.op === "start" ? "traffic-start" : "traffic-stop";
    labMsg(`${action} ${t.dataset.flock}…`);
    labAction(() => labPost("/api/lab/flock", { action, name: t.dataset.flock }));
  } else if (act === "flock-down") {
    labMsg(`flock down ${t.dataset.flock}…`);
    labAction(() => labPost("/api/lab/flock", { action: "down", name: t.dataset.flock }));
  } else if (act === "reset-all") {
    const boxes = Array.from(labBody.querySelectorAll(".lab-reset-flag:checked"));
    if (!boxes.length) { labMsg("check at least one reset option", true); return; }
    const flags = boxes.map((b) => b.value);
    // reset.sh gates --db behind confirm (orchestrate.DESTRUCTIVE_RESET_FLAGS);
    // pass confirm=true only when a destructive box is checked.
    const destructive = boxes.some((b) => b.dataset.destructive === "1");
    if (destructive && !window.confirm(`Run reset.sh ${flags.join(" ")}? This wipes soc.db and rebuilds containers.`)) return;
    labMsg(`reset ${flags.join(" ")}…`);
    labAction(() => labPost("/api/lab/reset", { flags, confirm: destructive }));
  }
}

function onLabChange(ev) {
  const el = ev.target;
  if (el.id === "lab-mode-select") {
    labSelectedMode = el.value;
    if (labLastStatus) renderLab(labLastStatus);   // toggle the dealer row locally
  }
}

function initLab() {
  if (labWired) return;
  labWired = true;
  loadLabConfig().then(() => { if (labPanelActive()) refreshLab(); });
  if (labBody) {
    labBody.addEventListener("click", onLabClick);
    labBody.addEventListener("change", onLabChange);
  }
  // load status when the Lab tab is opened; NO interval poll.
  const labTabBtn = document.querySelector('.tab-btn[data-tab="lab"]');
  if (labTabBtn) labTabBtn.addEventListener("click", () => refreshLab());
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeLabModal(); });
}
