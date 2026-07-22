"""
Fireworks AI backend. OpenAI-compatible /chat/completions, same shape and
same discipline as gmi.py: raw HTTP, stdlib only, key read from
FIREWORKS_API_KEY at call time so --dry-run/--stats work with no key
configured. See gmi.py's docstring for why this file looks nearly identical
to it -- both are OpenAI-compatible catalogs behind one auth header, just a
different host/key pair and model-id format.

Endpoint and key come from FIREWORKS_OPENAPI_HOST / FIREWORKS_API_KEY (see
.env). Model ids are Fireworks' full account-scoped path, e.g.
"accounts/fireworks/models/glm-5p2" -- not a bare "vendor/model" shorthand
like GMI's catalog.
"""

import json
import os
import urllib.error
import urllib.request

from .base import AgenticResult, Heartbeat, ProviderError, Verdict, parse_verdict_json

DEFAULT_BASE_URL = "https://api.fireworks.ai/inference/v1"
MAX_TOOL_ITERATIONS = 8
TIMEOUT_S = int(os.environ.get("FIREWORKS_TIMEOUT_S", "120"))


class FireworksProvider:
    def __init__(self, model):
        self.model = model
        self.base_url = os.environ.get("FIREWORKS_OPENAPI_HOST", DEFAULT_BASE_URL).rstrip("/")
        self._api_key_checked = False

    def _api_key(self):
        api_key = os.environ.get("FIREWORKS_API_KEY")
        if not api_key:
            raise ProviderError("FIREWORKS_API_KEY is not set")
        return api_key

    def run_agentic_turn(self, messages, tools, execute_tool, max_iterations):
        """Same loop mechanics as gmi.py's -- OpenAI-shaped request/response,
        the only real differences are the endpoint URL and auth header."""
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
        usage_totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        api_key = self._api_key()

        for i in range(max_iterations):
            print(f"    [iter {i + 1}/{max_iterations}] calling model ({self.model})...")
            with Heartbeat(f"iter {i + 1}/{max_iterations} still waiting on {self.model}"):
                resp = self._call(api_key, messages, openai_tools)
            usage = resp.get("usage") or {}
            for k in usage_totals:
                usage_totals[k] += usage.get(k, 0)
            print(f"       usage: +{usage.get('prompt_tokens', 0)} prompt / "
                  f"+{usage.get('completion_tokens', 0)} completion "
                  f"(running total: {usage_totals['total_tokens']})")
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
                # Some catalog models (GLM among them) return a separate
                # chain-of-thought field alongside content -- capture it
                # rather than silently drop it, matching local.py's
                # `thinking` field for Ollama's <think> models.
                thinking=message.get("reasoning_content"),
                messages=messages,
                model=resp.get("model", self.model),
                usage=usage_totals,
            )

        raise ProviderError(
            f"exceeded {max_iterations} tool-use iterations without a final turn"
        )

    def complete(self, system, user, tools, execute_tool):
        # Single-phase, like claude.py/gmi.py -- Fireworks' catalog here is
        # all tool-capable, instruction-following models, no need for
        # local.py's two-phase analysis-then-forced-JSON split.
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
            usage=result.usage,
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
                # See gmi.py -- urllib's default User-Agent gets blocked by
                # at least one of these hosted-model WAFs, so set one
                # everywhere on principle rather than waiting to hit it here.
                "user-agent": "soc-lab-agent/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"Fireworks API {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ProviderError(f"Fireworks API unreachable: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise ProviderError(f"Fireworks API request failed: {e}") from e
