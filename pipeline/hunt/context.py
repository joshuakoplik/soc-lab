#!/usr/bin/env python3
"""
The hunter's context/compaction layer -- the blue-team mirror of the red-team
agent's _persistent_context_block / _write_handoff / mandatory-first-action
machinery (pipeline/redteam/agent.py). This is where "the DB is the memory"
becomes a prompt: every chunk starts from a fresh conversation, and these
functions rebuild the evolving picture from soc.db rows.

Three things get rendered into every chunk's opening prompt:
  1. persistent_context_block: open incidents, HANDED OFF incidents (with the
     analyst responder, plus its verdict once there is one -- so the hunter
     stops circling what is no longer its to work), active leads, recent
     notebook findings/decisions -- the standing state, always present, zero
     tool calls.
  2. hunt_board_block: the shift-start dashboard -- new high/crit candidates,
     top talkers, loudest signatures, busiest dst ports, feed shape -- rendered
     from trusted columns as counts, so the hunter starts at altitude and never
     has to page candidate rows just to see what's happening. (It supersedes
     feed_delta_block, which is kept only for reference / poll-style reads.)
  3. mandatory_first_action_block: the NEXT STEP from the last handoff, hoisted
     to a leading imperative, escalating if the hunter keeps deferring it.

At a chunk boundary, write_handoff() distills the state into a compaction note
via one cheap no-tools completion (or the loop prefers a checkpoint the model
wrote itself mid-chunk -- see agent.run_hunt).

TRUST BOUNDARY: the feed and candidate detail are attacker-controlled text
(normalize.ATTACKER_CONTROLLED). The feed one-liners here render only
infrastructure/detection-asserted columns (id, rule, severity, src_ip,
counts, timestamps) -- never raw attacker fields -- so they need no fence.
Any tool that surfaces attacker-controlled content (get_candidate,
query_events, ...) fences it in <untrusted-evidence> in agent.py, exactly as
triage/agent.py's build_user_turn does. See CLAUDE.md's trust-labeling rule.
"""

import re
from datetime import datetime, timedelta

import store
from providers.base import ProviderError
from providers.claude import ClaudeProvider

PREVIEW_CHARS = 240
FEED_DELTA_CAP = store.FEED_DELTA_DEFAULT_CAP

# The hunt board (hunt_board_block) -- the hunter's shift-start dashboard.
BOARD_WINDOW_MIN = 30      # "recent" window for the by-src_ip/signature/port panels
BOARD_TOP_TALKERS = 8
BOARD_TOP_SIGS = 8
BOARD_TOP_PORTS = 6
BOARD_NEW_CRIT = 5


def _preview(text, n=PREVIEW_CHARS):
    if not text:
        return ""
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[:n] + f"... [+{len(text) - n} chars]"


# ---------------------------------------------------------------------------
# provider adapter (shared by the loop and by write_handoff)
# ---------------------------------------------------------------------------

def run_stage_turn(provider, system, user, tools, execute_tool, max_iterations, token_budget=None):
    """Uniform call across providers whose run_agentic_turn() signatures
    legitimately differ (Claude keeps `system` top-level; Ollama/OpenAI-compat
    embed it as a message). Identical shape to redteam/agent.py's
    run_stage_turn -- the hunter is the same pattern one module over."""
    if isinstance(provider, ClaudeProvider):
        messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]
        return provider.run_agentic_turn(system, messages, tools, execute_tool, max_iterations,
                                          token_budget=token_budget)
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    return provider.run_agentic_turn(messages, tools, execute_tool, max_iterations,
                                      token_budget=token_budget)


def _no_tools_execute(name, tool_input):
    # Handoff/compaction calls pass no tools; this only fires if a model
    # hallucinates a tool call anyway, and tells it plainly there are none.
    return ('{"error": "no tools available in this turn -- just write the note"}', True)


# ---------------------------------------------------------------------------
# standing context block
# ---------------------------------------------------------------------------

def _incidents_block(conn, hunt_id):
    # Handed-off incidents are the analyst's; they render under HANDED OFF.
    rows = store.list_incidents(conn, hunt_id, open_only=True, exclude_handed_off=True)
    if not rows:
        return None
    lines = []
    for r in rows:
        ev = store.incident_evidence_count(conn, r["id"])
        hyp = f" -- hypothesis: {_preview(r['hypothesis'], 160)}" if r["hypothesis"] else ""
        entity = f" entity={r['entity']}" if r["entity"] else ""
        lines.append(
            f"[incident {r['id']}] ({r['severity']}/{r['status']}) {r['title']}"
            f"{entity} -- {ev} evidence link(s){hyp}"
        )
    return "\n".join(lines)


def _handoffs_block(conn, hunt_id):
    """Incidents the hunter has handed to the analyst responder, latest
    handoff per incident: awaiting / in progress / the verdict. Each line ends
    with what the hunter should DO about that state, so the verdict actually
    changes its behaviour rather than just being reported."""
    rows = store.list_handoffs(conn, hunt_id)
    if not rows:
        return None
    lines = []
    for r in rows:
        entity = f" entity={r['inc_entity']}" if r["inc_entity"] else ""
        head = f"[incident {r['incident_id']}] ({r['inc_severity']}) {r['inc_title']}{entity}"
        if r["status"] == "queued":
            tail = f"handed off {r['handed_at']} -- awaiting analyst"
        elif r["status"] == "in_progress":
            tail = "analyst is working it now -- do not touch"
        elif r["status"] == "unresolved":
            tail = ("analyst could not reach a verdict; re-hand off with a sharper brief "
                    "if still active")
        else:  # resolved
            conf = f" ({r['confidence']:.2f})" if r["confidence"] is not None else ""
            why = f': "{_preview(r["rationale"], 140)}"' if r["rationale"] else ""
            v = r["verdict"]
            if v == "false_positive":
                guidance = "CLOSED; do not re-open for this entity unless materially different"
            elif v == "confirmed":
                guidance = (f"incident now {r['inc_status']} -- monitor only; re-hand off only "
                            "on NEW signal")
            else:
                guidance = "keep gathering evidence; hand off again when you have more"
            tail = f"analyst verdict: {v}{conf}{why} -- {guidance}"
        lines.append(f"{head} -- {tail}")
    return "\n".join(lines)


def _leads_block(conn, hunt_id):
    rows = store.active_leads(conn, hunt_id)
    if not rows:
        return None
    lines = []
    for r in rows:
        inc = f" (incident {r['incident_id']})" if r["incident_id"] else ""
        fails = f" fails={r['fail_count']}" if r["fail_count"] else ""
        lines.append(f"[lead {r['id']}] ({r['status']}{fails}){inc} {_preview(r['description'], 160)}")
    return "\n".join(lines)


def _notebook_block(conn, hunt_id, limit=10):
    """Recent notebook entries, oldest-first, findings/decisions/hypotheses
    surfaced (routine observations are excluded here to keep the standing
    block sharp -- they're still retrievable via search_notebook). Preview-
    capped; the hunter pulls a full note via search_notebook(ids=[N])."""
    rows = store.recent_notes(conn, hunt_id, limit=limit,
                              note_types=("finding", "decision", "hypothesis"))
    if not rows:
        return None
    lines = []
    for r in rows:
        inc = f" (incident {r['incident_id']})" if r["incident_id"] else ""
        lines.append(f"[note {r['id']}] ({r['note_type']}){inc} {_preview(r['body'])}")
    return "\n".join(lines)


def persistent_context_block(conn, hunt_id):
    """Open incidents + active leads + recent notebook, the standing state that
    belongs in EVERY chunk's opening prompt. Returns '' (not None) so callers
    concatenate unconditionally -- mirror of redteam _persistent_context_block."""
    parts = []
    inc = _incidents_block(conn, hunt_id)
    if inc:
        parts.append("OPEN INCIDENTS (investigations you have opened):\n" + inc)
    ho = _handoffs_block(conn, hunt_id)
    if ho:
        parts.append("HANDED OFF (with the analyst -- not yours to work):\n" + ho)
    leads = _leads_block(conn, hunt_id)
    if leads:
        parts.append(
            "ACTIVE LEADS (threads you are pursuing -- close a dead one with "
            "close_lead so you stop circling it):\n" + leads
        )
    nb = _notebook_block(conn, hunt_id)
    if nb:
        parts.append("RECENT NOTEBOOK (your own findings/decisions/hypotheses):\n" + nb)
    if not parts:
        return ""
    return "\n\n".join(parts) + "\n\n"


# ---------------------------------------------------------------------------
# the real-time feed
# ---------------------------------------------------------------------------

def feed_delta_block(conn, cursor_id, cursor_ts, cap=FEED_DELTA_CAP):
    """New/changed candidates since the hunter's cursor, brightest first. Only
    trusted columns are rendered (see the module trust note), so this needs no
    <untrusted-evidence> fence -- the hunter pulls the attacker-controlled
    detail on demand via get_candidate/query_events, which DO fence it.

    Returns (block_text, shown_rows). An empty feed still returns a one-line
    'quiet' note (not '') because the loop enters a chunk when there is EITHER
    new feed OR open work -- the hunter needs to be told which."""
    rows, total = store.read_feed_delta(conn, cursor_id, cursor_ts, limit=cap)
    if not rows:
        return "NEW/CHANGED SIGNALS SINCE YOUR LAST LOOK: none -- the feed is quiet.", 0
    lines = []
    for r in rows:
        ip = r["src_ip"] or "-"
        lines.append(
            f"[candidate {r['id']}] {r['severity']:<8} {r['rule']:<28} "
            f"src_ip={ip:<15} events={r['event_count']} last_seen={r['last_seen']}"
        )
    header = f"NEW/CHANGED SIGNALS SINCE YOUR LAST LOOK ({len(rows)} shown"
    overflow = ""
    if total > len(rows):
        # severity breakdown of the overflow so a flood is legible, not silent
        rank = store.SEVERITY_RANK_SQL
        brk = conn.execute(
            f"SELECT severity, COUNT(*) AS n FROM candidates "
            f"WHERE (id > ? OR updated > ?) GROUP BY severity ORDER BY {rank} DESC",
            (cursor_id, cursor_ts or ""),
        ).fetchall()
        by_sev = ", ".join(f"{b['n']} {b['severity']}" for b in brk)
        overflow = (
            f"\n... +{total - len(rows)} more not shown ({by_sev} total in backlog). "
            f"Use poll_feed to pull more before the cursor advances past them."
        )
        header += f" of {total}"
    header += "):"
    return header + "\n" + "\n".join(lines) + overflow, len(rows)


# ---------------------------------------------------------------------------
# the hunt board (the shift-start dashboard that opens every chunk)
# ---------------------------------------------------------------------------

def _board_window_lb(conn, window_min):
    """Lower bound (ISO ts) for the board's 'recent' panels, anchored to the
    NEWEST event ts in the DB rather than wall-clock now(). For replayed/batch
    telemetry (how the lab is usually driven) the max-ts anchor is the only one
    that yields a meaningful window; for a live-follow hunt the two coincide.
    Returns (lb_iso, max_ts); (None, None) when there are no events, and
    (None, max_ts) when the ts can't be parsed (panels then count over all
    events rather than silently emptying)."""
    row = conn.execute("SELECT MAX(ts) AS mx FROM events").fetchone()
    mx = row["mx"] if row else None
    if not mx:
        return None, None
    try:
        dt = datetime.fromisoformat(mx.replace("Z", "+00:00"))
        lb = (dt - timedelta(minutes=window_min)).isoformat().replace("+00:00", "Z")
    except (ValueError, AttributeError):
        lb = None
    return lb, mx


def hunt_board_block(conn, cursor_id, cursor_ts, window_min=BOARD_WINDOW_MIN):
    """The hunter's shift-start dashboard, rendered fresh into every chunk's
    opening prompt -- the altitude view that REPLACES the old candidate-row
    feed dump (feed_delta_block). A human hunter starts a shift at a board (the
    loudest alerts, who is noisy, what is firing), prioritises from it, and
    only pulls detail to run down a specific thread. This renders that board
    deterministically -- a handful of GROUP BY queries, zero tool calls -- so
    the hunter never has to page rows just to see the shape of what is
    happening, and can't drown in a flood the way a row dump makes it.

    TRUST: every column rendered is infrastructure- or detection-asserted (ids,
    counts, signature NAMES, severities, ports, timestamps, src_ips) -- never
    an ATTACKER_CONTROLLED field -- so the whole board sits on the safe side of
    the trust boundary and needs no <untrusted-evidence> fence, exactly the
    reasoning in this module's trust note for feed_delta_block. Attacker text
    enters only when the hunter deliberately descends via a fenced tool
    (get_candidate / query_events); pivot_events keeps to trusted group keys.

    Returns (block_text, new_count), new_count being the number of new/changed
    candidates since the cursor, so the loop keeps the same 'is there fresh
    signal' return the feed block provided."""
    lb, mx = _board_window_lb(conn, window_min)
    win = f"last {window_min}m" if lb else "all time"
    ev_where = "ts >= ?" if lb else "1=1"
    ev_params = [lb] if lb else []
    rank = store.SEVERITY_RANK_SQL
    sections = [f"=== YOUR BOARD (as of {mx or 'n/a'}; 'recent' = {win}, "
                f"anchored to the newest event) ==="]

    # NEW HIGH/CRIT since the cursor -- the alerts a hunter opens the shift on.
    hi_rows, hi_total = store.read_feed_delta(conn, cursor_id, cursor_ts,
                                              min_severity="high", limit=BOARD_NEW_CRIT)
    if hi_rows:
        lines = []
        for r in hi_rows:
            ip = r["src_ip"] or "-"
            lines.append(f"  [candidate {r['id']}] {r['severity']:<8} {r['rule']:<26} "
                         f"src_ip={ip:<15} events={r['event_count']} last={r['last_seen']}")
        extra = (f"\n  ... +{hi_total - len(hi_rows)} more high/critical not shown"
                 if hi_total > len(hi_rows) else "")
        sections.append("NEW HIGH/CRIT SINCE LAST LOOK:\n" + "\n".join(lines) + extra)

    # What changed since last chunk (all severities), as counts not rows.
    _, new_total = store.read_feed_delta(conn, cursor_id, cursor_ts, limit=1)
    if new_total:
        brk = conn.execute(
            f"SELECT severity, COUNT(*) AS n FROM candidates WHERE (id > ? OR updated > ?) "
            f"GROUP BY severity ORDER BY {rank} DESC", (cursor_id, cursor_ts or "")).fetchall()
        by_sev = ", ".join(f"{b['n']} {b['severity']}" for b in brk)
        sections.append(f"NEW/CHANGED SINCE LAST CHUNK: {new_total} candidate(s) ({by_sev}).")
    else:
        sections.append("NEW/CHANGED SINCE LAST CHUNK: none.")

    # Recent-window aggregates over the raw events -- who's noisy, what's firing.
    talkers = conn.execute(
        f"SELECT src_ip, COUNT(*) AS n FROM events WHERE {ev_where} AND src_ip IS NOT NULL "
        f"GROUP BY src_ip ORDER BY n DESC LIMIT ?", ev_params + [BOARD_TOP_TALKERS]).fetchall()
    if talkers:
        sections.append(f"TOP TALKERS ({win}, by event volume):\n" +
                        "\n".join(f"  {r['src_ip']:<15} {r['n']}" for r in talkers))

    sigs = conn.execute(
        f"SELECT ids_signature AS s, COUNT(*) AS n FROM events "
        f"WHERE {ev_where} AND ids_signature IS NOT NULL "
        f"GROUP BY ids_signature ORDER BY n DESC LIMIT ?", ev_params + [BOARD_TOP_SIGS]).fetchall()
    if sigs:
        sections.append(f"LOUDEST SIGNATURES ({win}):\n" +
                        "\n".join(f"  {r['n']:>8}  {r['s']}" for r in sigs))

    ports = conn.execute(
        f"SELECT dst_port AS p, COUNT(*) AS n FROM events WHERE {ev_where} AND dst_port IS NOT NULL "
        f"GROUP BY dst_port ORDER BY n DESC LIMIT ?", ev_params + [BOARD_TOP_PORTS]).fetchall()
    if ports:
        sections.append(f"BY DST PORT ({win}):  " + "  ".join(f"{r['p']}->{r['n']}" for r in ports))

    # Feed shape + event totals -- the whole backlog at a glance.
    cand = conn.execute(
        f"SELECT severity, COUNT(*) AS n FROM candidates GROUP BY severity "
        f"ORDER BY {rank} DESC").fetchall()
    cand_total = sum(r["n"] for r in cand)
    cand_sev = ", ".join(f"{r['n']} {r['severity']}" for r in cand) or "none"
    ev = conn.execute("SELECT COUNT(*) AS n, MIN(ts) AS lo, MAX(ts) AS hi FROM events").fetchone()
    sections.append(f"FEED SHAPE: {cand_total} candidates ({cand_sev}); "
                    f"{ev['n']} events total, span {ev['lo']} .. {ev['hi']}.")

    sections.append("This board is your starting point. A dominating IP, signature, or rule count "
                    "is itself the thread -- pick the brightest one, then descend with pivot_events "
                    "/ query_events / get_candidate ONLY for that thread.")
    return "\n\n".join(sections), new_total


# ---------------------------------------------------------------------------
# anti-perseveration
# ---------------------------------------------------------------------------

_NEXT_STEP_RE = re.compile(r'(?im)^\s*next step:\s*(.+)$')


def split_next_step(text):
    matches = _NEXT_STEP_RE.findall(text or "")
    return matches[-1].strip() if matches else None


def mandatory_first_action_block(next_step, streak):
    """Front-loads the last handoff's NEXT STEP as a leading imperative so a
    fresh chunk doesn't quietly deprioritize it, escalating once the same step
    has been named 3+ times running. Mirror of redteam
    _mandatory_first_action_block."""
    if not next_step:
        return ""
    if streak >= 3:
        return (
            f"\n\nMANDATORY FIRST ACTION -- you have named this exact step as next "
            f"{streak} times running without completing it. Do not write another "
            f"plan and do not re-read state first: make this your very first tool "
            f"call this turn, then continue from there:\n{next_step}"
        )
    return f"\n\nMANDATORY FIRST ACTION -- do this before anything else this turn:\n{next_step}"


# ---------------------------------------------------------------------------
# chunk-boundary compaction
# ---------------------------------------------------------------------------

HUNTER_HANDOFF_SYSTEM = (
    "You are writing a concise handoff note between two turns of the same "
    "ongoing threat hunt in a security lab you are authorized to monitor. "
    "The next turn starts with a blank conversation -- no memory of anything "
    "said or reasoned about in this one -- and only this note (plus the "
    "standing incident/lead/notebook state it is shown, and whatever it "
    "independently re-checks) to pick up from. You may be shown your own last "
    "several handoff notes below, oldest first -- if they show the same lead "
    "or hypothesis being chased across multiple turns without real progress, "
    "SAY SO EXPLICITLY and either mark that lead dead or name a genuinely "
    "different next step, rather than restating the same plan again. You may "
    "also be shown a one-line index of recent notebook entries -- if one holds "
    "the detail the next turn needs, NAME ITS ID (e.g. \"see note #47\") so the "
    "next turn retrieves it via search_notebook(ids=[47]) instead of "
    "re-deriving it. Only name tools that are actually in your own tool list. "
    "Write a SHORT note: a few sentences to a short paragraph, not a report. "
    "Cover what you have confirmed, which incident(s) it belongs to, your "
    "current best hypothesis, and the SPECIFIC next step. Keep exact detail "
    "that would otherwise be re-derived -- candidate ids, src_ips, endpoints, "
    "what a query showed -- and drop anything generic. This is working memory "
    "for yourself a moment from now, not a summary for a human. Do NOT get "
    "lost in the backlog: the point of the hunt is what is happening now, so "
    "if a fresh high-severity signal arrived, that likely outranks finishing "
    "an old low-severity thread. "
    "End with one final line, exactly in this form, naming the SINGLE concrete "
    "action the next turn should take FIRST -- a tool call it can make "
    "immediately, not \"investigate X\":\n"
    "NEXT STEP: <the specific action>\n"
    "This line is pulled out and shown to the next turn as its mandatory first "
    "action; if your prior notes show the same next step named repeatedly "
    "without being done, name what actually needs to happen instead."
)


def _notebook_index(conn, hunt_id, limit=30):
    rows = store.recent_notes(conn, hunt_id, limit=limit)
    if not rows:
        return None
    return "\n".join(f"[{r['id']}] ({r['note_type']}) {_preview(r['body'], 120)}" for r in rows)


def gather_state(conn, hunt_id):
    """Assemble the state the handoff writer distills -- open incidents, active
    leads, a notebook index, and the trail of prior handoff notes. Mirror of
    redteam _gather_handoff_state."""
    parts = []
    inc = _incidents_block(conn, hunt_id)
    parts.append("Open incidents:\n" + inc if inc else "Open incidents: none.")
    ho = _handoffs_block(conn, hunt_id)
    if ho:
        parts.append("Handed off to the analyst (not the hunter's to work):\n" + ho)
    leads = _leads_block(conn, hunt_id)
    parts.append("Active leads:\n" + leads if leads else "Active leads: none.")
    idx = _notebook_index(conn, hunt_id)
    if idx:
        parts.append("Notebook index (id -- type -- preview):\n" + idx)
    prior = conn.execute(
        "SELECT chunk, note FROM hunt_handoff_notes WHERE hunt_id=? ORDER BY id DESC LIMIT 8",
        (hunt_id,),
    ).fetchall()
    if prior:
        trail = "\n".join(f"[after chunk {r['chunk']}] {r['note']}" for r in reversed(prior))
        parts.append("Your recent handoff notes (oldest first):\n" + trail)
    return "\n\n".join(parts)


def write_handoff(conn, hunt_id, provider, chunk):
    """One cheap no-tools completion distilling the DB state into a compaction
    note, persisted so the next chunk (and the next --continue) can reorient.
    Returns (note_text, next_step); (None, None) on any failure -- a hiccup
    here must never block a restart. Mirror of redteam _write_handoff."""
    state = gather_state(conn, hunt_id)
    user = f"{state}\n\nWrite the handoff note now."
    try:
        result = run_stage_turn(provider, HUNTER_HANDOFF_SYSTEM, user, [], _no_tools_execute, 1)
    except ProviderError:
        return None, None
    text = (result.final_text or "").strip()
    if not text:
        return None, None
    next_step = split_next_step(text)
    store.add_handoff(conn, hunt_id, chunk, text, next_step)
    return text, next_step
