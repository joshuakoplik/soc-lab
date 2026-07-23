"""
Fireworks AI backend. OpenAI-compatible /chat/completions -- all protocol
logic lives in openai_compat.py; this is just Fireworks' host/key/timeout
config. See that file's docstring for why GMI and Fireworks share one
implementation.

Endpoint and key come from FIREWORKS_OPENAPI_HOST / FIREWORKS_API_KEY (see
.env). Model ids are Fireworks' full account-scoped path, e.g.
"accounts/fireworks/models/glm-5p2" -- not a bare "vendor/model" shorthand
like GMI's catalog.
"""

from .openai_compat import OpenAICompatibleProvider

DEFAULT_BASE_URL = "https://api.fireworks.ai/inference/v1"


class FireworksProvider(OpenAICompatibleProvider):
    def __init__(self, model):
        super().__init__(
            model,
            default_base_url=DEFAULT_BASE_URL,
            base_url_env="FIREWORKS_OPENAPI_HOST",
            api_key_env="FIREWORKS_API_KEY",
            timeout_env="FIREWORKS_TIMEOUT_S",
            default_timeout_s=120,
            error_prefix="Fireworks API",
        )
