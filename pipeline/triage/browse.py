#!/usr/bin/env python3
"""
Terminal browser for pipeline/agent.py's output -- a curses TUI over the
`triage` table joined back to `candidates`.

    python3 pipeline/browse.py

Up/Down or j/k to move, Enter or Right to drill into a candidate, Esc/
Backspace/Left to go back, q to quit. PageUp/PageDown jump a screenful.

Read-only, deliberately: opens soc.db with SQLite's URI ?mode=ro, so this can
run safely while pipeline/agent.py is mid-batch (WAL mode allows concurrent
readers) and can never be the thing that corrupts a triage run.

stdlib only. `curses` is the standard toolkit for arrow-key navigation in a
terminal and ships with Python everywhere this lab runs -- no dependency to
justify.
"""

import curses
import json
import os
import sqlite3
import sys
import textwrap
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))       # pipeline/triage
ROOT = os.path.dirname(os.path.dirname(HERE))              # soc-lab root
DB_PATH = os.path.join(ROOT, "soc.db")

# curses.color_pair() indices, set up once in init_colors(). Keyed by verdict
# since that's the actionable outcome of triage -- what you scan the list
# for -- more than severity, which the rules tier already summarized.
VERDICT_COLOR = {
    "malicious":    1,  # red, bold
    "suspicious":   2,  # yellow
    "needs_human":  3,  # blue, bold
    "benign":       4,  # green
    "error":        5,  # white-on-red
}


# ---------------------------------------------------------------------------
# Data layer. No curses in here -- kept importable and testable without a
# terminal attached (curses.wrapper() needs a real tty; this doesn't).
# ---------------------------------------------------------------------------

def connect():
    if not os.path.exists(DB_PATH):
        sys.exit(f"no database at {DB_PATH} -- run ingest.py / rules.py / agent.py first")
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def load_rows(conn):
    """One row per triage verdict, newest activity first -- this is a
    security-event browser, so "when did it happen" (candidates.first_seen)
    ranks it, not "when did the batch run" (triage.created)."""
    return conn.execute(
        "SELECT t.id AS triage_id, t.candidate_id, t.verdict, t.confidence, "
        "t.rationale, t.recommended_action, t.attack_technique, t.model, "
        "t.provider, t.tool_calls, t.error, t.created AS triaged_at, "
        "c.rule, c.severity, c.src_ip, c.first_seen, c.last_seen, "
        "c.event_count, c.evidence, c.detail, c.dedupe_key "
        "FROM triage t JOIN candidates c ON c.id = t.candidate_id "
        "ORDER BY c.first_seen DESC"
    ).fetchall()


def load_related(conn, candidate_id):
    alerts = conn.execute(
        "SELECT severity, summary, created FROM agent_alerts "
        "WHERE candidate_id=? ORDER BY created", (candidate_id,)
    ).fetchall()
    blocks = conn.execute(
        "SELECT src_ip, reason, approved, created FROM block_recommendations "
        "WHERE candidate_id=? ORDER BY created", (candidate_id,)
    ).fetchall()
    return alerts, blocks


def short_ts(ts):
    """ISO8601 'Z' timestamp -> compact 'MM-DD HH:MM' for the list column."""
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%m-%d %H:%M")
    except (ValueError, AttributeError, TypeError):
        return (ts or "-")[:11]


def first_words(text, n=10):
    if not text:
        return ""
    words = text.split()
    out = " ".join(words[:n])
    return out + ("..." if len(words) > n else "")


def row_description(row):
    """The "description" column: the model's own rationale is the closest
    thing to a human-readable summary of a triaged candidate we have. Fall
    back to the error detail for rows that never got a real verdict."""
    return row["rationale"] or row["error"] or "(no rationale recorded)"


# ---------------------------------------------------------------------------
# curses UI.
# ---------------------------------------------------------------------------

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_RED, -1)
    curses.init_pair(2, curses.COLOR_YELLOW, -1)
    curses.init_pair(3, curses.COLOR_BLUE, -1)
    curses.init_pair(4, curses.COLOR_GREEN, -1)
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_RED)


def safe_addnstr(stdscr, y, x, s, n, attr=0):
    """addnstr throws curses.error when asked to write the terminal's very
    last cell (a long-standing curses quirk) or when the window shrank out
    from under a stale y/x -- neither is a bug worth crashing the browser
    over, so swallow it and move on to the next line."""
    try:
        stdscr.addnstr(y, x, s, n, attr)
    except curses.error:
        pass


def draw_list(stdscr, rows, selected, top):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    title = f" SOC Triage Browser -- {len(rows)} triaged candidate(s) "
    safe_addnstr(stdscr, 0, 0, title.ljust(w), w, curses.A_REVERSE)

    header = f"  {'TIME':<12} {'SEV':<9} {'VERDICT':<12} DESCRIPTION"
    safe_addnstr(stdscr, 1, 0, header.ljust(w), w, curses.A_BOLD)

    body_h = max(0, h - 3)
    for i, r in enumerate(rows[top:top + body_h]):
        y = 2 + i
        idx = top + i
        sev = (r["severity"] or "-").upper()
        verdict = r["verdict"] or "-"
        desc = first_words(row_description(r), 10)
        line = f"{'>' if idx == selected else ' '} {short_ts(r['first_seen']):<12} {sev:<9} {verdict:<12} {desc}"

        if idx == selected:
            attr = curses.A_REVERSE
        else:
            attr = curses.color_pair(VERDICT_COLOR.get(r["verdict"], 0))
            if r["verdict"] == "malicious":
                attr |= curses.A_BOLD
        safe_addnstr(stdscr, y, 0, line.ljust(w), w, attr)

    footer = "up/down or j/k: move   enter: details   q: quit"
    safe_addnstr(stdscr, h - 1, 0, footer.ljust(w - 1), w - 1, curses.A_DIM)
    stdscr.refresh()


def build_detail_lines(row, alerts, blocks, w):
    detail = json.loads(row["detail"]) if row["detail"] else {}
    evidence = json.loads(row["evidence"]) if row["evidence"] else []
    wrap_w = max(20, w - 4)

    lines = [
        f"verdict:            {row['verdict']}  (confidence {row['confidence']})",
        f"severity:           {row['severity']}",
        f"src_ip:             {row['src_ip'] or '-'}",
        f"first_seen:         {row['first_seen']}",
        f"last_seen:          {row['last_seen']}",
        f"event_count:        {row['event_count']}  (evidence event ids: {evidence})",
        f"dedupe_key:         {row['dedupe_key']}",
        f"attack_technique:   {row['attack_technique'] or '-'}",
        f"model / provider:   {row['model']} / {row['provider']}  "
        f"({row['tool_calls']} tool call(s))",
        f"triaged_at:         {row['triaged_at']}",
    ]
    if row["error"]:
        lines.append(f"error:              {row['error']}")

    lines += ["", "rationale:"]
    lines += [f"  {l}" for l in textwrap.wrap(row["rationale"] or "-", wrap_w)] or ["  -"]

    lines += ["", "recommended_action:"]
    lines += [f"  {l}" for l in textwrap.wrap(row["recommended_action"] or "-", wrap_w)] or ["  -"]

    lines += ["", "rules-tier detail (from candidates.detail):"]
    lines += [f"  {l}" for l in json.dumps(detail, indent=2).splitlines()]

    if alerts:
        lines += ["", "agent_alerts:"]
        lines += [f"  [{a['severity']}] {a['summary']}  ({a['created']})" for a in alerts]

    if blocks:
        lines += ["", "block_recommendations (recommend-only -- never executed):"]
        for b in blocks:
            approved = "approved" if b["approved"] else "pending human approval"
            lines.append(f"  {b['src_ip']} -- {b['reason']}  [{approved}]  ({b['created']})")

    return lines


def draw_detail(stdscr, row, alerts, blocks, scroll):
    stdscr.erase()
    h, w = stdscr.getmaxyx()

    title = f" candidate #{row['candidate_id']} -- {row['rule']} "
    safe_addnstr(stdscr, 0, 0, title.ljust(w), w, curses.A_REVERSE)

    lines = build_detail_lines(row, alerts, blocks, w)
    body_h = max(0, h - 2)
    scroll = max(0, min(scroll, max(0, len(lines) - body_h)))
    for i, l in enumerate(lines[scroll:scroll + body_h]):
        safe_addnstr(stdscr, 1 + i, 0, l, w)

    footer = "up/down: scroll   esc/backspace/left: back   q: quit"
    safe_addnstr(stdscr, h - 1, 0, footer.ljust(w - 1), w - 1, curses.A_DIM)
    stdscr.refresh()
    return scroll, len(lines)


def run(stdscr):
    curses.curs_set(0)
    stdscr.keypad(True)
    init_colors()

    conn = connect()
    rows = load_rows(conn)

    if not rows:
        stdscr.erase()
        safe_addnstr(stdscr, 0, 0, "No triaged candidates yet.", 40)
        safe_addnstr(stdscr, 1, 0, "Run pipeline/agent.py first, then come back.", 60)
        safe_addnstr(stdscr, 3, 0, "Press any key to exit.", 30)
        stdscr.refresh()
        stdscr.getch()
        conn.close()
        return

    selected = 0
    top = 0
    mode = "list"
    detail_scroll = 0

    while True:
        h, w = stdscr.getmaxyx()
        body_h = max(1, h - 3)

        if selected < top:
            top = selected
        elif selected >= top + body_h:
            top = selected - body_h + 1

        if mode == "list":
            draw_list(stdscr, rows, selected, top)
        else:
            row = rows[selected]
            alerts, blocks = load_related(conn, row["candidate_id"])
            detail_scroll, _ = draw_detail(stdscr, row, alerts, blocks, detail_scroll)

        key = stdscr.getch()

        if key in (ord("q"), ord("Q")):
            break
        if key == curses.KEY_RESIZE:
            continue

        if mode == "list":
            if key in (curses.KEY_UP, ord("k")):
                selected = max(0, selected - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                selected = min(len(rows) - 1, selected + 1)
            elif key == curses.KEY_NPAGE:
                selected = min(len(rows) - 1, selected + body_h)
            elif key == curses.KEY_PPAGE:
                selected = max(0, selected - body_h)
            elif key == curses.KEY_HOME:
                selected = 0
            elif key == curses.KEY_END:
                selected = len(rows) - 1
            elif key in (curses.KEY_ENTER, 10, 13, curses.KEY_RIGHT, ord("l")):
                mode = "detail"
                detail_scroll = 0
        else:
            if key in (27, curses.KEY_BACKSPACE, 127, curses.KEY_LEFT, ord("h")):
                mode = "list"
            elif key in (curses.KEY_UP, ord("k")):
                detail_scroll = max(0, detail_scroll - 1)
            elif key in (curses.KEY_DOWN, ord("j")):
                detail_scroll += 1
            elif key == curses.KEY_NPAGE:
                detail_scroll += body_h
            elif key == curses.KEY_PPAGE:
                detail_scroll = max(0, detail_scroll - body_h)

    conn.close()


def main():
    curses.wrapper(run)


if __name__ == "__main__":
    main()
