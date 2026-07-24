"""
Runs commands inside the soc-attacker Kali container via `docker exec`.

The one execution primitive redteam_agent.py's tools are built on. Deliberately
NOT a subpackage like pipeline/providers/ -- there's exactly one backend here
(docker exec into one named container), nothing to swap, no Protocol to
justify the extra structure.

Scope fencing lives here, not just in tool schemas: validate_target() is the
check redteam_agent.py's dispatch_tool() calls BEFORE run() is ever reached
-- a JSON-schema "enum" on a tool's target parameter is advisory (models
don't always respect schema outside a grammar-locked call, see
providers/local.py), this is not. The allowed set itself is NOT a static
constant here -- it comes from lab_modes.active_config()["targets"], which
depends on lab_mode.json (see lab_modes.py). Easy mode allows cowrie/nginx/
metasploitable; hard mode allows nginx only, because cowrie and
metasploitable aren't even running in that mode. Re-read on every call
rather than cached at import time, so a mode switch mid-process (unlikely,
but --continue-assess resumes an old session) can't leave this checking
against a stale allowlist.

ALLOWED_NETWORKS is a separate, narrower question: not "can this name be
touched at all" but "is it fully inside our own lab, such that a gated
action against it is safe to run without a human approval round trip".
in_whitelisted_network() resolves the target the same way soc-attacker's
own DNS would and checks the result against ALLOWED_NETWORKS -- see
redteam_agent.py's tool_propose_action() and execute_pending_action() for
where that answer changes behavior. Unlike the target allowlist, this one
IS static across modes: it's the physical lab subnet, not a function of
which containers happen to be up.
"""

import ipaddress
import os
import subprocess
import sys
import time
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
import lab_modes  # noqa: E402

CONTAINER = "soc-attacker"

# The soclab bridge's subnet (confirmed via `docker network inspect
# soc-lab_soclab`; Docker assigns it, there's no static IPAM config in
# compose.yaml, so re-check if this ever looks stale). Every target reachable
# at all is already inside it -- the mode-specific target allowlist (see
# lab_modes.py) is always a subset of what's reachable here -- so this
# whitelist is what lets a gated action against a lab-internal target skip
# the human approval gate entirely: it's contained and reversible by
# construction, regardless of difficulty mode.
ALLOWED_NETWORKS = [ipaddress.ip_network("10.211.0.0/24")]

DEFAULT_TIMEOUT_S = 120
DEFAULT_MAX_OUTPUT_CHARS = 16000


class ScopeError(Exception):
    """Raised when a tool call names a target outside the active mode's
    allowed targets. Never reaches run() -- the whole point is that
    redteam_exec.run() only ever sees argv that already passed this check."""


def validate_target(target):
    allowed = lab_modes.active_config()["targets"]
    if target not in allowed:
        raise ScopeError(
            f"{target!r} is not an allowed target in {lab_modes.current_mode()!r} "
            f"mode (allowed: {sorted(allowed)})"
        )


def resolve_target_ip(target):
    """The host's resolver doesn't know soclab's service names -- ask
    soc-attacker, which is on the same bridge and shares Docker's embedded
    DNS. Returns None on any resolution failure rather than raising: an
    unresolvable target just means "not whitelisted", not a hard error."""
    result = run(["getent", "hosts", target], timeout_s=10)
    if result.exit_code != 0 or not result.stdout.strip():
        return None
    return result.stdout.split()[0]


def in_whitelisted_network(target):
    """True if `target` resolves to an address inside ALLOWED_NETWORKS.
    Distinct from ALLOWED_TARGETS/validate_target(): that's a name allowlist
    gating whether redteam_exec touches something at all; this is an IP-range
    check gating whether a gated action against it may skip human approval
    and run at full intensity."""
    ip_str = resolve_target_ip(target)
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in ALLOWED_NETWORKS)


@dataclass
class ExecResult:
    argv: list
    exit_code: "int | None"
    timed_out: bool
    stdout: str
    stderr: str
    truncated: bool
    elapsed_s: float


def _cap(text, max_chars):
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + f"\n...[truncated, {len(text) - max_chars} more chars]", True


def run(argv, timeout_s=DEFAULT_TIMEOUT_S, max_output_chars=DEFAULT_MAX_OUTPUT_CHARS):
    """Run argv inside soc-attacker. Never raises for a nonzero exit or a
    timeout -- always returns an ExecResult, same "never raises, let the
    caller decide is_error" contract as agent.py's dispatch_tool(). Only
    raises for things that are the CALLER's bug: an out-of-scope target
    should be caught by validate_target() before this is ever called.

    `timeout` wraps the command INSIDE the container (not just the local
    subprocess) -- killing the local `docker exec` client process does not
    reliably stop the remote process otherwise. Confirmed present in the
    provisioned Kali image: `docker exec soc-attacker which timeout`.
    """
    full_argv = ["docker", "exec", CONTAINER, "timeout", f"{timeout_s}s", *argv]
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            full_argv, capture_output=True, text=True, timeout=timeout_s + 10
        )
        elapsed_s = time.monotonic() - t0
        stdout, out_trunc = _cap(proc.stdout, max_output_chars)
        stderr, err_trunc = _cap(proc.stderr, max_output_chars)
        return ExecResult(
            argv=argv,
            exit_code=proc.returncode,
            timed_out=False,
            stdout=stdout,
            stderr=stderr,
            truncated=out_trunc or err_trunc,
            elapsed_s=elapsed_s,
        )
    except subprocess.TimeoutExpired as e:
        elapsed_s = time.monotonic() - t0
        stdout, out_trunc = _cap(e.stdout.decode("utf-8", "replace") if e.stdout else "", max_output_chars)
        stderr, err_trunc = _cap(e.stderr.decode("utf-8", "replace") if e.stderr else "", max_output_chars)
        return ExecResult(
            argv=argv,
            exit_code=None,
            timed_out=True,
            stdout=stdout,
            stderr=stderr,
            truncated=out_trunc or err_trunc,
            elapsed_s=elapsed_s,
        )


def attacker_ip():
    """soc-attacker's own bridge IP this run -- the join key that lets a
    later query correlate candidates.src_ip against this session."""
    result = run(["hostname", "-i"], timeout_s=10)
    if result.exit_code != 0:
        return None
    return result.stdout.strip() or None
