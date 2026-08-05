"""
Real enforcement backend for the defender's harden_northwind_controls tool.
Northwind (northwind-range/) is a separate, adapter-backed target -- no
docker-network identity the way easy/hard/wordpress have (see
net_topology.py; there is no Northwind entry there), so block_enforcer.py's
IP/subnet fence has no meaning here. The lever that exists instead is
Northwind's own already-built control-state API (SPEC.md §5,
services/portal-api/app.py's PUT/POST /api/controls[/reset]) -- live,
unauthenticated, and capable of turning on any of the app's off-by-default
security controls (injection classifier, PII/secret filters, retrieval
scanning, tool gating, ...).

Hard fencing, same two-stage shape block_enforcer.validate_lab_ip() uses,
adapted to this target's actual identity space (toggle names, not IPs):
  1. harden() rejects anything outside ALLOWED_TOGGLES, and rejects any
     value that isn't True (turning something OFF is never "hardening" --
     out of scope for this tool, full stop) -- before any HTTP call is
     made. A rejected request never reaches the network.
  2. ALLOWED_TOGGLES itself excludes every control that already defaults
     ON and is load-bearing for the app's baseline function
     (ENT_RETRIEVAL/ENT_TOOL/RET_PREFILTER/TOOL_ARG_VALIDATION/RATE_LIMIT)
     and every enum-valued control with no generic "on" direction
     (RET_PLACEMENT/SYS_PROMPT_VARIANT/TOOL_GATING_POLICY) -- so even a
     successful call is structurally incapable of doing anything other
     than strictly adding defensive controls the app already knows how to
     enforce.

No timer-based auto-revert: durable-until-explicit-undo, same posture
block_ip's iptables rules already have. See reset.sh --northwind-controls
to return every toggle to baseline.
"""

import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))       # pipeline/triage
PIPELINE = os.path.dirname(HERE)                          # pipeline
if os.path.join(PIPELINE, "redteam") not in sys.path:
    sys.path.insert(0, os.path.join(PIPELINE, "redteam"))
from northwind_adapter import base_url, NorthwindAdapterError  # noqa: E402

HTTP_TIMEOUT_S = 15

# The exact set of CONTROL_DEFAULTS-off booleans (SPEC.md §5,
# northwind-range/services/portal-api/app.py's CONTROL_DEFAULTS) that mean
# something as a one-way "turn this defense on" action. ENT_PROMPT is
# included -- it defaults off and SPEC.md §5.1 calls it weak alone, but
# it's still a legitimate control to enable, not a baseline-breaking one.
ALLOWED_TOGGLES = {
    "ENT_PROMPT", "RET_SOURCE_ALLOWLIST", "RET_SCORE_THRESHOLD", "RET_PROVENANCE",
    "IN_INJECTION_CLASSIFIER", "IN_RETRIEVED_SCAN", "OUT_PII_FILTER",
    "OUT_SECRET_FILTER", "OUT_GROUNDING_CHECK", "OUT_STRUCTURED", "TOOL_GATING",
}


class ControlsError(Exception):
    pass


def _fence_hit(updates, why):
    """Same "loud on rejection" discipline as block_enforcer._fence_hit --
    a rejected toggle request is the fence doing its job, worth being
    visible about rather than a silent no-op."""
    print(
        "\n" + "!" * 70 +
        f"\n[northwind_enforcer] FENCE HIT -- harden request rejected\n"
        f"  requested: {updates!r}\n"
        f"  reason:    {why}\n"
        f"  NOTHING WAS CHANGED. This is the hard fence doing its job.\n"
        + "!" * 70 + "\n",
        file=sys.stderr,
    )


def _request_json(method, url, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"} if data is not None else {},
        method=method,
    )
    try:
        resp = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S)
        return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raise ControlsError(f"{method} {url} -> {e.code}: {e.read().decode(errors='replace')}") from e
    except urllib.error.URLError as e:
        raise ControlsError(f"{method} {url} failed: {e}") from e


def validate_toggles(updates):
    """The primary fence. Raises ControlsError unless every key is on
    ALLOWED_TOGGLES and every value is exactly True -- runs before any HTTP
    call, so a rejected request never touches the network at all. Every
    rejection prints loudly first (see _fence_hit)."""
    if not updates:
        _fence_hit(updates, "no toggles given")
        raise ControlsError("no toggles given")
    bad_keys = set(updates) - ALLOWED_TOGGLES
    if bad_keys:
        why = f"not on the hardening allowlist: {sorted(bad_keys)}"
        _fence_hit(updates, why)
        raise ControlsError(why)
    non_true = {k: v for k, v in updates.items() if v is not True}
    if non_true:
        why = f"only True (turning ON) is accepted, got: {non_true}"
        _fence_hit(updates, why)
        raise ControlsError(why)


def harden(updates):
    """Validate, then PUT {base_url()}/api/controls with the validated
    body. base_url() resolves nw-edge-nginx's IP fresh on every call (see
    northwind_adapter.py) since it isn't stable across a container
    recreate -- never cache or hardcode it."""
    validate_toggles(updates)
    try:
        url = base_url()
    except NorthwindAdapterError as e:
        raise ControlsError(str(e)) from e
    return _request_json("PUT", f"{url}/api/controls", updates)


def reset():
    """POST {base_url()}/api/controls/reset -- portal-api's own
    reset_control_state(), a plain Redis DEL on the control_state hash,
    falling back to CONTROL_DEFAULTS. What reset.sh --northwind-controls
    calls; not wired to any triage tool (undoing a hardening action is an
    operator decision, same "no tool for this" posture block_enforcer.py's
    unblock() takes -- see its own docstring)."""
    try:
        url = base_url()
    except NorthwindAdapterError as e:
        raise ControlsError(str(e)) from e
    return _request_json("POST", f"{url}/api/controls/reset", {})


def status_line():
    """One-line summary of ALLOWED_TOGGLES' current state, in the same
    sentinel-string style block_enforcer.list_blocked()/'nothing currently
    blocked' uses, so reset.sh can string-compare it identically."""
    try:
        url = base_url()
    except NorthwindAdapterError as e:
        raise ControlsError(str(e)) from e
    state = _request_json("GET", f"{url}/api/controls")
    active = sorted(k for k in ALLOWED_TOGGLES if state.get(k) is True)
    if not active:
        return "[northwind_enforcer] all hardening toggles at baseline (off)"
    return f"[northwind_enforcer] {len(active)} toggle(s) active: {', '.join(active)}"


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--status", action="store_true", help="print current toggle state, then exit")
    ap.add_argument("--reset", action="store_true", help="reset every control to baseline, then exit")
    args = ap.parse_args()

    try:
        if args.reset:
            reset()
            print(status_line())
        elif args.status:
            print(status_line())
        else:
            ap.print_help()
            sys.exit(1)
    except ControlsError as e:
        print(f"[northwind_enforcer] ERROR: {e}", file=sys.stderr)
        sys.exit(1)
