"""labctl configuration + repo-relative paths.

Knobs come from three layers, later wins: built-in defaults -> labctl.toml (repo
root, gitignored) -> LABCTL_* environment variables. The supervisor re-reads this
on every tick (via load()), so the Phase-2 dashboard can flip a policy by writing
labctl.toml and the running `watch` loop picks it up without a restart.

Stdlib-only. tomllib is 3.11+; if it's missing or the file is absent we run on
defaults + env, never a hard error -- same forgiving posture as lab_modes.py
reading a missing lab_mode.json.
"""

import os

try:
    import tomllib  # py3.11+
except ModuleNotFoundError:  # pragma: no cover - old interpreters
    tomllib = None

# Repo root = three levels up from this file: pipeline/labctl/config.py -> repo.
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

STATE_DIR = os.path.join(ROOT, ".labctl")          # gitignored process registry + logs
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LOG_DIR = os.path.join(STATE_DIR, "logs")
CONFIG_FILE = os.path.join(ROOT, "labctl.toml")     # gitignored, optional
SOC_DB = os.path.join(ROOT, "soc.db")
LAB_MODE_JSON = os.path.join(ROOT, "lab_mode.json")

# The process names labctl tracks. Order matters only for display.
MANAGED = ("dashboard", "ingest", "hunter", "attacker")

DEFAULTS = {
    # supervisor cadence
    "poll_interval": 20.0,        # seconds between watch ticks
    "detect_interval": 30.0,      # seconds between one-shot detect/rules.py runs
    # policy timers
    "idle_timeout": 600.0,        # stop the hunter after it's been idle this long
    "attack_drain_max": 900.0,    # hard ceiling on post-attack drain before forcing a stop
    "stop_timeout": 30.0,         # SIGTERM -> wait this long -> SIGKILL
    # which policies the watch loop enforces
    "policy_keep_infra": True,
    "policy_auto_detect": True,
    "policy_idle_hunter": True,
    "policy_attack_finish": True,
    # what an auto-(re)started hunter is launched as (user default: kimi-k3 on gmi)
    "hunter_provider": "gmi",
    "hunter_model": "moonshotai/kimi-k3",
}

_BOOL_KEYS = {k for k in DEFAULTS if k.startswith("policy_")}
_FLOAT_KEYS = {"poll_interval", "detect_interval", "idle_timeout", "attack_drain_max", "stop_timeout"}


def _coerce(key, val):
    if key in _BOOL_KEYS:
        if isinstance(val, str):
            return val.strip().lower() in ("1", "true", "yes", "on")
        return bool(val)
    if key in _FLOAT_KEYS:
        return float(val)
    return str(val)


def load():
    """Return the effective config dict: defaults <- labctl.toml <- LABCTL_* env."""
    cfg = dict(DEFAULTS)
    if tomllib is not None and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "rb") as f:
                data = tomllib.load(f)
            for k, v in data.items():
                if k in cfg:
                    cfg[k] = _coerce(k, v)
        except (OSError, ValueError):
            pass  # malformed toml -> ignore, stay on defaults+env
    for k in cfg:
        env = os.environ.get("LABCTL_" + k.upper())
        if env is not None and env != "":
            try:
                cfg[k] = _coerce(k, env)
            except ValueError:
                pass
    return cfg


def write_policies(policies):
    """Merge a {policy_*: bool, ...} dict into labctl.toml (create if absent).

    Used by the Phase-2 dashboard to toggle supervisor policy live. Only known
    keys are written; unknown keys are ignored so the UI can't inject junk.
    Best-effort atomic replace. Requires no tomllib to WRITE (we emit trivial
    TOML by hand), only to read it back.
    """
    known = set(DEFAULTS)
    merged = {}
    # preserve existing file contents we recognise
    if tomllib is not None and os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "rb") as f:
                for k, v in tomllib.load(f).items():
                    if k in known:
                        merged[k] = v
        except (OSError, ValueError):
            pass
    for k, v in policies.items():
        if k in known:
            merged[k] = _coerce(k, v)
    lines = []
    for k, v in merged.items():
        if isinstance(v, bool):
            lines.append(f"{k} = {'true' if v else 'false'}")
        elif isinstance(v, (int, float)):
            lines.append(f"{k} = {v}")
        else:
            lines.append(f'{k} = "{v}"')
    tmp = CONFIG_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, CONFIG_FILE)
