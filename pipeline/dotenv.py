"""
Minimal, stdlib-only .env loader. Every provider needs at least one of
OLLAMA_HOST / GMI_API_KEY / FIREWORKS_API_KEY / ANTHROPIC_API_KEY, plus
redteam/agent.py's web_search and Juice Shop flag check need TAVILY_API_KEY /
CTF_KEY -- all of them live in .env, none of them are exported by the shell
by default. Before this, every provider/gmi/fireworks or redteam --provider
gmi run had to be preceded by manually `set -a; source .env; set +a`, which
is exactly the kind of thing that's forgotten right up until a run fails
with "GMI_API_KEY is not set" or silently connection-refuses against
localhost instead of the real OLLAMA_HOST.

load_dotenv() is called once, at import time, by pipeline/providers/__init__.py
-- the one module every provider-consuming entrypoint (triage/agent.py,
redteam/agent.py, injection_asr/run_asr.py) already imports before it reads
any of these vars. Real environment variables (already-exported shell vars,
CI secrets) always win: this only fills in what's missing, via setdefault,
so it can never override a deliberate override.
"""

import os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
DOTENV_PATH = os.path.join(ROOT, ".env")


def load_dotenv(path=None):
    path = path or DOTENV_PATH
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            os.environ.setdefault(key, value)
