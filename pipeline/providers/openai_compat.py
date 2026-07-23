"""
Shared client for OpenAI-compatible /chat/completions catalogs. GMI and
Fireworks are both this exact shape -- same request body, same response
envelope, same tool-call contract -- differing only in host, key, timeout
env var, and model-id format. Everything protocol-specific lives here once;
providers/gmi.py and providers/fireworks.py are now just config.

Ollama is NOT this shape (native /api/chat, different envelope, no key,
two-phase grammar-constrained completion) and stays its own file --
see providers/local.py.

Raw HTTP, stdlib only, same discipline as claude.py/local.py: no vendor SDK,
key read from the configured env var at call time so --dry-run/--stats work
with no key configured at all.
"""

import json
import os
import urllib.error
import urllib.request

from .base import AgenticResult, Heartbeat, ProviderError, Verdict, parse_verdict_json

MAX_TOOL_ITERATIONS = 8


class OpenAICompatibleProvider:
    def __init__(self, model, *, default_base_url, base_url_env, api_key_env,
                 timeout_env, default_timeout_s=120, error_prefix):
        self.model = model
        self.base_url = os.environ.get(base_url_env, default_base_url).rstrip("/")
        self.api_key_env = api_key_env
        self.timeout_s = int(os.environ.get(timeout_env, str(default_timeout_s)))
        self.error_prefix = error_prefix

    def _api_key(self):
        # Read at call time, not __init__ -- mirrors claude.py's
        # ANTHROPIC_API_KEY handling so --dry-run/--stats still work with
        # no key configured.
        api_key = os.environ.get(self.api_key_env)
        if not api_key:
            raise ProviderError(f"{self.api_key_env} is not set")
        return api_key

    def run_agentic_turn(self, messages, tools, execute_tool, max_iterations):
        """Send `messages` (OpenAI chat-message shape), dispatching any
        tool_calls the model requests via execute_tool, until it stops
        requesting tools and gives a final text turn."""
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
        # Single-phase, like claude.py -- these catalogs are tool-capable,
        # instruction-following models that reliably follow "respond with
        # ONLY the JSON verdict" directly, unlike local.py's smaller models
        # which need the separate unconstrained-analysis-then-forced-JSON
        # split to reach the same reliability.
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
                # urllib's default User-Agent ("Python-urllib/x.y") is a
                # known bot signature -- at least one of these hosted-model
                # WAFs (GMI's Cloudflare) blocks it outright with a 403
                # before the request ever reaches the API, distinct from
                # and easy to confuse with an actual auth/API failure. Any
                # non-default UA clears it, so set one everywhere on
                # principle rather than waiting to hit it per-host.
                "user-agent": "soc-lab-agent/1.0",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"{self.error_prefix} {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ProviderError(f"{self.error_prefix} unreachable: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise ProviderError(f"{self.error_prefix} request failed: {e}") from e
