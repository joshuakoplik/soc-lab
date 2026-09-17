"""Per-provider model catalog for the dashboard launch dropdowns.

Hardcoded lists go stale and get things wrong -- e.g. offering "local kimi-k3",
which is a GMI-hosted model that never exists as an ollama tag. So instead we
query each provider's authoritative source and PERSIST the result to
.labctl/models.json:

  - local    -> ollama GET {OLLAMA_HOST}/api/tags        (what's actually pulled)
  - gmi      -> OpenAI-compatible GET {base}/models        (Bearer GMI_API_KEY)
  - fireworks-> OpenAI-compatible GET {base}/models        (Bearer FIREWORKS_API_KEY)
  - claude   -> Anthropic GET https://api.anthropic.com/v1/models (x-api-key)

Models rarely change, so the supervisor refreshes on a long interval
(models_refresh_interval) and /config reads the cached file, lazily refreshing
only when it's missing or older than the TTL. Stdlib-only (urllib); every network
call is best-effort with a short timeout and falls back to the last-known list
(then a tiny seed), so a provider being down or keyless never empties the dropdown
or blocks the page.
"""

import calendar
import json
import os
import time
import urllib.request

from . import config

PROVIDERS = ("claude", "gmi", "local", "fireworks")

PROVIDER_DEFAULT_MODEL = {
    "claude": "claude-sonnet-4-6",
    "gmi": "moonshotai/kimi-k3",   # this lab's default model, not the agents' bare gpt-4o-mini
    "local": "qwen3:8b",
    "fireworks": "",
}

# Fallback used when a live fetch fails AND nothing is cached. Deliberately tiny
# and CORRECT -- notably `local` is EMPTY (never seed a model that may not be
# pulled; that was the "local kimi-k3" bug). claude + local query live fine, but
# gmi's /models returns 403 and fireworks' returns 412 to our key, so those two
# effectively always use this seed -- the launch modal's "custom..." box is how
# you reach anything not listed.
SEED_MODELS = {
    "claude": ["claude-sonnet-4-6"],
    "gmi": ["moonshotai/kimi-k3", "openai/gpt-4o-mini"],
    "local": [],
    "fireworks": ["accounts/fireworks/models/glm-5p2"],
}

# OpenAI-compatible providers: (base-url env, default base, key env).
_OPENAI_COMPAT = {
    "gmi": ("GMI_OPENAPI_HOST", "https://api.gmi-serving.com/v1", "GMI_API_KEY"),
    "fireworks": ("FIREWORKS_OPENAPI_HOST", "https://api.fireworks.ai/inference/v1", "FIREWORKS_API_KEY"),
}

_HTTP_TIMEOUT = 3
_MAX_PER_PROVIDER = 300   # fireworks' /models can be large; keep the dropdown sane


def _now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _get_json(url, headers, timeout=_HTTP_TIMEOUT):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _fetch_ollama():
    host = os.environ.get("OLLAMA_HOST") or "http://127.0.0.1:11434"
    if not host.startswith(("http://", "https://")):
        host = "http://" + host
    data = _get_json(host.rstrip("/") + "/api/tags", {})
    return [m["name"] for m in data.get("models", []) if m.get("name")]


def _fetch_openai_compat(provider):
    base_env, default_base, key_env = _OPENAI_COMPAT[provider]
    base = os.environ.get(base_env) or default_base
    key = os.environ.get(key_env)
    if not key:
        return None  # no key -> can't list; caller keeps last-known/seed
    data = _get_json(base.rstrip("/") + "/models", {"Authorization": f"Bearer {key}"})
    return [m["id"] for m in data.get("data", []) if m.get("id")]


def _fetch_anthropic():
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        return None
    data = _get_json(
        "https://api.anthropic.com/v1/models?limit=100",
        {"x-api-key": key, "anthropic-version": "2023-06-01"},
    )
    return [m["id"] for m in data.get("data", []) if m.get("id")]


def fetch_provider_models(provider):
    """Live list for one provider, or None on any failure (down/keyless/timeout)."""
    try:
        if provider == "local":
            return _fetch_ollama()
        if provider in _OPENAI_COMPAT:
            return _fetch_openai_compat(provider)
        if provider == "claude":
            return _fetch_anthropic()
    except Exception:  # noqa: BLE001 - best-effort; any failure -> None
        return None
    return None


def _read_file():
    try:
        with open(config.MODELS_FILE) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def refresh_catalog():
    """Query every provider, persist, return {refreshed, providers}. A provider
    whose live fetch fails keeps its last-known list (else its seed) -- a flaky
    network never wipes a good catalog."""
    prev = (_read_file() or {}).get("providers", {})
    providers = {}
    for p in PROVIDERS:
        live = fetch_provider_models(p)
        if live:
            uniq = sorted(set(live))[:_MAX_PER_PROVIDER]
            providers[p] = uniq
        else:
            providers[p] = prev.get(p) or list(SEED_MODELS[p])
    data = {"refreshed": _now_iso(), "providers": providers}
    try:
        os.makedirs(config.STATE_DIR, exist_ok=True)
        tmp = config.MODELS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, config.MODELS_FILE)
    except OSError:
        pass
    return data


def _age_seconds(data):
    ts = (data or {}).get("refreshed")
    if not ts:
        return None
    try:
        epoch = calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))  # UTC struct -> epoch
        return max(0.0, time.time() - epoch)
    except (ValueError, OverflowError):
        return None


def load_catalog(max_age=None):
    """Cached catalog, lazily refreshed when missing or older than max_age.
    Returns {refreshed, providers}."""
    data = _read_file()
    if data is None:
        return refresh_catalog()
    if max_age is not None:
        age = _age_seconds(data)
        if age is None or age > max_age:
            return refresh_catalog()
    return data


def models_by_provider(max_age=None):
    """{provider: [model, ...]} for the dropdowns (from the cached catalog)."""
    cat = load_catalog(max_age)
    provs = cat.get("providers", {})
    # guarantee every known provider key is present
    return {p: provs.get(p, list(SEED_MODELS[p])) for p in PROVIDERS}
