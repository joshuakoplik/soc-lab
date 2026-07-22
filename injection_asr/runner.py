"""
Drives each harness case's real candidate through the real triage loop --
agent.triage_one, agent.TOOLS, agent.dispatch_tool, provider.complete -- via
an instrumented tool executor that records every call's name/args/result.
Nothing here reimplements triage; it wraps the exact functions agent.py's
own main() loop calls, using the additive `controls`/`execute` hooks added
to agent.py for this harness (both default to production behavior when
omitted -- see agent.py's build_user_turn/triage_one docstrings).
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRIAGE = os.path.join(ROOT, "pipeline", "triage")
if TRIAGE not in sys.path:
    sys.path.insert(0, TRIAGE)
import agent  # noqa: E402 -- pipeline/triage/agent.py, found via TRIAGE above


def _instrumented_execute(conn, candidate_id, call_log):
    def execute(name, tool_input):
        text, is_error = agent.dispatch_tool(conn, candidate_id, name, tool_input)
        call_log.append({
            "name": name,
            "input": tool_input or {},
            "result": text,
            "is_error": is_error,
        })
        return text, is_error
    return execute


def run_one(conn, provider, provider_name, cand_row, controls):
    """Triages ONE candidate under ONE controls arm. Returns verdict/
    confidence/rationale, any raise_alert/recommend_block calls, the full
    tool-call log, and elapsed time.

    Reads alert severity / block src_ip straight out of call_log (the exact
    args the model passed to raise_alert/recommend_block) rather than
    re-querying agent_alerts/block_recommendations by candidate_id: both
    controls arms triage the SAME candidate_id (by design -- see
    run_asr.py), so a post-hoc query can't tell which arm's row is which,
    but the call_log captured live during THIS call unambiguously can."""
    call_log = []
    execute = _instrumented_execute(conn, cand_row["id"], call_log)
    outcome, elapsed_s, _usage = agent.triage_one(
        conn, provider, provider_name, cand_row, controls=controls, execute=execute
    )
    conn.commit()

    triage_row = conn.execute(
        "SELECT * FROM triage WHERE candidate_id=? ORDER BY id DESC LIMIT 1",
        (cand_row["id"],),
    ).fetchone()

    alerts = [c["input"] for c in call_log if c["name"] == "raise_alert" and not c["is_error"]]
    blocks = [c["input"] for c in call_log if c["name"] == "recommend_block" and not c["is_error"]]
    # block_ip is the ungated, "executes immediately" tool (see agent.py's
    # tool_block_ip docstring -- test-only no-op, never touches real
    # infrastructure). Kept in its own list, not merged into `blocks`: an
    # agent that calls block_ip on the wrong target believes it just took
    # irreversible action, which scorer.py treats as more severe than a
    # merely-recommended block sitting behind the human gate.
    block_ip_calls = [c["input"] for c in call_log if c["name"] == "block_ip" and not c["is_error"]]

    return {
        "outcome": outcome,
        "elapsed_s": elapsed_s,
        "verdict": triage_row["verdict"] if triage_row else outcome,
        "confidence": triage_row["confidence"] if triage_row else None,
        "rationale": triage_row["rationale"] if triage_row else None,
        "recommended_action": triage_row["recommended_action"] if triage_row else None,
        "attack_technique": triage_row["attack_technique"] if triage_row else None,
        "alerts": alerts,
        "blocks": blocks,
        "block_ip_calls": block_ip_calls,
        "tool_calls": call_log,
    }


def run_suite(conn, cases, provider, provider_name, controls):
    """cases: list of dicts from injector.inject_cases (candidate_id already
    resolved). Skips any case the rules tier didn't promote to a candidate,
    logging that plainly rather than guessing at a result."""
    results = []
    for case in cases:
        if not case.get("candidate_id"):
            print(f"  [!] {case['payload'].variant_id}: no candidate produced, skipping")
            continue
        cand_row = conn.execute(
            "SELECT * FROM candidates WHERE id=?", (case["candidate_id"],)
        ).fetchone()
        result = run_one(conn, provider, provider_name, cand_row, controls)
        results.append({**case, "controls": controls, "result": result})
    return results
