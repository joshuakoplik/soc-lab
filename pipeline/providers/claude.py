"""
Anthropic Messages API backend. Raw HTTP, stdlib only -- no `anthropic` import
anywhere in this file or this repo. See AGENT_BRIEF.md #4.

Endpoint, header, and default model are pinned to the exact values the brief
specifies: https://api.anthropic.com/v1/messages, anthropic-version
2023-06-01, default claude-sonnet-4-6. The key comes from ANTHROPIC_API_KEY
and is read at call time, not at construction -- so `--dry-run` and
`--provider claude --stats` work on a box with no key configured at all.
"""

import http.client
import json
import os
import time
import urllib.error
import urllib.request

from .base import (
    MAX_CALL_ATTEMPTS,
    RETRYABLE_HTTP_CODES,
    AgenticResult,
    Heartbeat,
    IterationsExhausted,
    ProviderError,
    Verdict,
    parse_verdict_json,
    retry_backoff_s,
)

API_URL = "https://api.anthropic.com/v1/messages"
API_VERSION = "2023-06-01"
MAX_TOKENS = 4096
# Bounds the tool-use round trips for one candidate. A model that keeps
# calling tools forever is a cost leak, not a triage decision -- cut it off
# and record the failure rather than paying for an infinite loop.
MAX_TOOL_ITERATIONS = 8
# Overridable via ANTHROPIC_TIMEOUT_S, same pattern as OLLAMA_TIMEOUT_S /
# GMI_TIMEOUT_S / FIREWORKS_TIMEOUT_S -- a long agentic turn (e.g. a
# recon/assess stage writing out a full exploit) can take a lot longer than
# a single triage verdict.
TIMEOUT_S = int(os.environ.get("ANTHROPIC_TIMEOUT_S", "1200"))


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

            if stop_reason == "refusal":
                # Anthropic's dedicated stop_reason for "the model declined
                # to respond at all" -- content is empty ([]), no text, no
                # tool_use. Left unhandled, this fell through to the
                # generic final-turn branch below and got recorded as a
                # normal, successful completion with an empty final_text:
                # observed live, a full recon+assess campaign against
                # claude-opus-5 "completed" in 8 seconds with zero tool
                # calls, zero findings, and no error anywhere, because a
                # silent refusal looks identical to "the model finished and
                # had nothing to add" once stop_reason is discarded.
                # Surface it as what it actually is -- a real failure this
                # model isn't going to retry its way out of, same posture
                # as any other ProviderError -- instead of a quiet no-op.
                raise ProviderError(
                    f"{self.model} refused to respond (stop_reason=refusal) -- "
                    "the model declined the request outright, not a tool-use "
                    "or iteration-budget issue"
                )

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

        raise IterationsExhausted(
            f"exceeded {max_iterations} tool-use iterations without a final turn"
        )

    def complete(self, system, user, tools, execute_tool,
                 token_budget=None, max_chunks=1, max_tokens_hard_cap=None):
        # token_budget/max_chunks/max_tokens_hard_cap accepted for a uniform
        # Provider.complete() interface (triage/agent.py calls every
        # provider the same way) but not acted on here -- Anthropic's
        # Messages API usage isn't wired into run_agentic_turn's
        # AgenticResult.usage yet (see base.py), so there are no real numbers
        # to chunk against. Same "accepted, no-op" pattern as
        # run_agentic_turn's own token_budget parameter already documents.
        #
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

        for attempt in range(MAX_CALL_ATTEMPTS):
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
                # Body carries the API's error message -- worth surfacing. The
                # key never appears in it; this reads the request headers, not
                # the key.
                detail = e.read().decode("utf-8", errors="replace")[:500]
                if e.code in RETRYABLE_HTTP_CODES and attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [Anthropic API {e.code} -- retrying in {delay:.1f}s "
                          f"(attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"Anthropic API {e.code}: {detail}") from e
            except urllib.error.URLError as e:
                if attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [Anthropic API unreachable ({e.reason}) -- retrying in "
                          f"{delay:.1f}s (attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"Anthropic API unreachable: {e.reason}") from e
            except (TimeoutError, OSError, http.client.HTTPException) as e:
                if attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [Anthropic API request failed ({e}) -- retrying in "
                          f"{delay:.1f}s (attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"Anthropic API request failed: {e}") from e
