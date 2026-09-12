#!/usr/bin/env python3
"""
The hunter's context/compaction layer -- the blue-team mirror of the red-team
agent's _persistent_context_block / _write_handoff / mandatory-first-action
machinery (pipeline/redteam/agent.py). This is where "the DB is the memory"
becomes a prompt: every chunk starts from a fresh conversation, and these
functions rebuild the evolving picture from soc.db rows.

Three things get rendered into every chunk's opening prompt:
  1. persistent_context_block: open incidents, active leads, recent notebook
     findings/decisions -- the standing state, always present, zero tool calls.
  2. feed_delta_block: new/changed candidates since the hunter's cursor -- the
     real-time intel stream ("what's burning brightest"), the piece that makes
     the hunter reactive instead of a queue drainer.
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

import store
from providers.base import ProviderError
from providers.claude import ClaudeProvider

PREVIEW_CHARS = 240
FEED_DELTA_CAP = store.FEED_DELTA_DEFAULT_CAP


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
    rows = store.list_incidents(conn, hunt_id, open_only=True)
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
