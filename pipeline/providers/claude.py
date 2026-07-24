"""
Anthropic Messages API backend. Raw HTTP, stdlib only -- no `anthropic` import
anywhere in this file or this repo. See AGENT_BRIEF.md #4.

Endpoint, header, and default model are pinned to the exact values the brief
specifies: https://api.anthropic.com/v1/messages, anthropic-version
2023-06-01, default claude-sonnet-4-6. The key comes from ANTHROPIC_API_KEY
and is read at call time, not at construction -- so `--dry-run` and
`--provider claude --stats` work on a box with no key configured at all.
"""

import json
import os
import urllib.error
import urllib.request

from .base import AgenticResult, Heartbeat, ProviderError, Verdict, parse_verdict_json

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
MAX_TOKENS = 4096
# Bounds the tool-use round trips for one candidate. A model that keeps
# calling tools forever is a cost leak, not a triage decision -- cut it off
# and record the failure rather than paying for an infinite loop.
MAX_TOOL_ITERATIONS = 8
TIMEOUT_S = 60


class ClaudeProvider:
    def __init__(self, model):
        self.model = model

    def run_agentic_turn(self, system, messages, tools, execute_tool, max_iterations, token_budget=None):
        """Send `messages` (Anthropic content-block shape), dispatching any
        tool_use blocks via execute_tool, until the model stops requesting
        tools and gives a final text turn. Loop mechanics shared between
        complete() (triage, ending in a JSON verdict) and a red-team
        campaign stage (ending in free-form analysis or a proposal) --
        factored out so there's one implementation of Anthropic's
        tool_use/tool_result content-block bookkeeping, not one per caller.

        `messages` is mutated in place and also returned via the result, so
        the caller can keep the conversation going after this turn ends.

        `token_budget` is accepted but ignored -- usage isn't wired up for
        this provider yet (see base.py's AgenticResult.usage docstring), so
        there's nothing to check it against. Accepted for the same uniform-
        call-signature reason as local.py's no-op."""
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ProviderError("ANTHROPIC_API_KEY is not set")

        tool_calls = 0

        for i in range(max_iterations):
            print(f"    [iter {i + 1}/{max_iterations}] calling model ({self.model})...")
            with Heartbeat(f"iter {i + 1}/{max_iterations} still waiting on {self.model}"):
                resp = self._call(api_key, system, messages, tools)
            stop_reason = resp.get("stop_reason")
            content = resp.get("content", [])

            if stop_reason == "tool_use":
                messages.append({"role": "assistant", "content": content})
                results = []
                for block in content:
                    if block.get("type") != "tool_use":
                        continue
                    tool_calls += 1
                    text, is_error = execute_tool(block["name"], block.get("input") or {})
                    result = {
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": text,
                    }
                    if is_error:
                        result["is_error"] = True
                    results.append(result)
                # All tool_result blocks for this turn go back in ONE user
                # message -- splitting them trains the model to stop batching
                # parallel calls.
                messages.append({"role": "user", "content": results})
                continue

            final_text = "".join(b.get("text", "") for b in content if b.get("type") == "text")
            messages.append({"role": "assistant", "content": content})
            return AgenticResult(
                final_text=final_text,
                tool_calls=tool_calls,
                thinking=None,  # Anthropic extended thinking isn't wired up here
                messages=messages,
                model=resp.get("model", self.model),
            )

        raise ProviderError(
            f"exceeded {max_iterations} tool-use iterations without a final turn"
        )

    def complete(self, system, user, tools, execute_tool):
        # Anthropic tool_use turns require the full content array (including
        # tool_use blocks) echoed back verbatim as the assistant turn before
        # the matching tool_result -- see shared tool-use-concepts.
        messages = [{"role": "user", "content": [{"type": "text", "text": user}]}]

        result = self.run_agentic_turn(system, messages, tools, execute_tool, MAX_TOOL_ITERATIONS)
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

    def _call(self, api_key, system, messages, tools):
        body = json.dumps({
            "model": self.model,
            "max_tokens": MAX_TOKENS,
            "system": system,
            "messages": messages,
            "tools": tools,
        }).encode("utf-8")

        req = urllib.request.Request(
            API_URL,
            data=body,
            method="POST",
            headers={
                "content-type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": API_VERSION,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # Body carries the API's error message -- worth surfacing. The key
            # never appears in it; this reads the request headers, not the key.
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"Anthropic API {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ProviderError(f"Anthropic API unreachable: {e.reason}") from e
        except (TimeoutError, OSError) as e:
            raise ProviderError(f"Anthropic API request failed: {e}") from e
