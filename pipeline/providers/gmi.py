"""
GMI Cloud backend. OpenAI-compatible /chat/completions -- a hosted catalog of
third-party models (GPT, Claude, Qwen, DeepSeek, etc.) behind one API, not a
single vendor. Raw HTTP, stdlib only, same discipline as claude.py/local.py:
no vendor SDK, key read from GMI_API_KEY at call time so --dry-run and
--stats work with no key configured at all.

Endpoint and key come from GMI_OPENAPI_HOST / GMI_API_KEY (see .env) --
overridable the same way OLLAMA_HOST overrides local.py's default.
"""

import json
import os
import urllib.error
import urllib.request

from .base import AgenticResult, Heartbeat, ProviderError, Verdict, parse_verdict_json

DEFAULT_BASE_URL = "https://api.gmi-serving.com/v1"
# Bounds the tool-use round trips for one candidate/stage turn, same role as
# claude.py's MAX_TOOL_ITERATIONS.
MAX_TOOL_ITERATIONS = 8
# GMI proxies to third-party model backends of very different speeds (a
# small model vs. e.g. a 1M-context frontier model) -- overridable the same
# way local.py's OLLAMA_TIMEOUT_S is, rather than assuming one constant fits
# every model in the catalog.
TIMEOUT_S = int(os.environ.get("GMI_TIMEOUT_S", "120"))


class GMIProvider:
    def __init__(self, model):
        self.model = model
        self.base_url = os.environ.get("GMI_OPENAPI_HOST", DEFAULT_BASE_URL).rstrip("/")
        # Read at call time, not here -- mirrors claude.py's ANTHROPIC_API_KEY
        # handling so --dry-run/--stats still work with no key configured.
        self._api_key_checked = False

    def _api_key(self):
        api_key = os.environ.get("GMI_API_KEY")
        if not api_key:
            raise ProviderError("GMI_API_KEY is not set")
        return api_key

    def run_agentic_turn(self, messages, tools, execute_tool, max_iterations):
        """Send `messages` (OpenAI chat-message shape), dispatching any
        tool_calls the model requests via execute_tool, until it stops
        requesting tools and gives a final text turn. Same loop mechanics
        as local.py's Ollama integration -- GMI's /chat/completions is
        OpenAI-shaped, and Ollama's /api/chat tool format already mirrors
        OpenAI's, so the request/response plumbing here is nearly identical,
        modulo auth and the response envelope (resp["choices"][0]["message"]
        vs. Ollama's resp["message"])."""
        openai_tools = [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                },
            }
            for t in tools
        ]
        tool_calls = 0
        api_key = self._api_key()

        for i in range(max_iterations):
            print(f"    [iter {i + 1}/{max_iterations}] calling model ({self.model})...")
            with Heartbeat(f"iter {i + 1}/{max_iterations} still waiting on {self.model}"):
                resp = self._call(api_key, messages, openai_tools)
            choice = resp["choices"][0]
            message = choice["message"]
            requested = message.get("tool_calls") or []

            if requested:
                messages.append(message)
                for call in requested:
                    tool_calls += 1
                    fn = call.get("function", {})
                    name = fn.get("name")
                    raw_args = fn.get("arguments") or "{}"
                    if isinstance(raw_args, str):
                        try:
                            args = json.loads(raw_args)
                        except json.JSONDecodeError:
                            args = {}
                    else:
                        args = raw_args
                    text, _is_error = execute_tool(name, args)
                    # OpenAI's tool-result contract requires the matching
                    # tool_call_id round-trip, unlike Ollama's simpler
                    # role:"tool" echo with no id.
                    messages.append({
                        "role": "tool",
                        "tool_call_id": call.get("id"),
                        "content": text,
                    })
                continue

            final_text = message.get("content") or ""
            messages.append(message)
            return AgenticResult(
                final_text=final_text,
                tool_calls=tool_calls,
                thinking=None,
                messages=messages,
                model=resp.get("model", self.model),
            )

        raise ProviderError(
            f"exceeded {max_iterations} tool-use iterations without a final turn"
        )

    def complete(self, system, user, tools, execute_tool):
        # Single-phase, like claude.py -- GMI's catalog is frontier-quality
        # models that reliably follow "respond with ONLY the JSON verdict"
        # directly, unlike local.py's smaller models which need the
        # separate unconstrained-analysis-then-forced-JSON split to reach
        # the same reliability.
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        result = self.run_agentic_turn(messages, tools, execute_tool, MAX_TOOL_ITERATIONS)
        parsed = parse_verdict_json(result.final_text)
        return Verdict(
            verdict=parsed["verdict"],
            confidence=parsed["confidence"],
            rationale=parsed["rationale"],
            recommended_action=parsed["recommended_action"],
            attack_technique=parsed.get("attack_technique"),
            model=result.model or self.model,
            tool_calls=result.tool_calls,
        )

    def _call(self, api_key, messages, tools):
        body = {"model": self.model, "messages": messages}
        if tools:
            body["tools"] = tools
        body = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "authorization": f"Bearer {api_key}",
                # urllib's default User-Agent ("Python-urllib/x.y") is a
                # known bot signature -- GMI's Cloudflare WAF blocks it
                # outright with a 403 (error code 1010) before the request
                # ever reaches their API, distinct from and easy to confuse
                # with an actual auth/API failure. Any non-default UA clears
                # it; curl's requests never hit this because curl's default
                # UA isn't on that blocklist.
                "user-agent": "soc-lab-agent/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"GMI API {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ProviderError(f"GMI API unreachable: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise ProviderError(f"GMI API request failed: {e}") from e
