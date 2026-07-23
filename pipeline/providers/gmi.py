"""
GMI Cloud backend. OpenAI-compatible /chat/completions -- a hosted catalog of
third-party models (GPT, Claude, Qwen, DeepSeek, etc.) behind one API, not a
single vendor. All protocol logic lives in openai_compat.py; this is just
GMI's host/key/timeout config -- see that file's docstring for why GMI and
Fireworks share one implementation.

Endpoint and key come from GMI_OPENAPI_HOST / GMI_API_KEY (see .env) --
overridable the same way OLLAMA_HOST overrides local.py's default. Model ids
are GMI's bare "vendor/model" shorthand, e.g. "moonshotai/kimi-k3" -- not
Fireworks' account-scoped path.
"""

from .openai_compat import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://api.gmi-serving.com/v1"


class GMIProvider(OpenAICompatibleProvider):
    def __init__(self, model):
        super().__init__(
            model,
            default_base_url=DEFAULT_BASE_URL,
            base_url_env="GMI_OPENAPI_HOST",
            api_key_env="GMI_API_KEY",
            timeout_env="GMI_TIMEOUT_S",
            # GMI proxies to third-party model backends of very different
            # speeds (a small model vs. e.g. a 1M-context frontier model) --
            # overridable the same way local.py's OLLAMA_TIMEOUT_S is,
            # rather than assuming one constant fits every model in the
            # catalog.
            default_timeout_s=120,
            error_prefix="GMI API",
        )
