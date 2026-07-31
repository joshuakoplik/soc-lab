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
    ContextBudgetExceeded,
    Heartbeat,
    IterationsExhausted,
    ProviderError,
    Verdict,
    parse_verdict_json,
    retry_backoff_s,
)

MAX_TOOL_ITERATIONS = 8


def _now_ts():
    return time.strftime("%H:%M:%S")


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

    def run_agentic_turn(self, messages, tools, execute_tool, max_iterations, token_budget=None):
        """Send `messages` (OpenAI chat-message shape), dispatching any
        tool_calls the model requests via execute_tool, until it stops
        requesting tools and gives a final text turn.

        `token_budget`, if given, is a second, tighter ceiling than
        max_iterations: once this call's accumulated prompt tokens reach it
        AND the model wants to keep calling tools, raise ContextBudgetExceeded
        instead of dispatching another round -- deliberately checked only
        when the model is about to continue, never on a turn that would
        otherwise return a real final answer, so a legitimately-concluding
        call is never discarded just for arriving a little over budget. See
        redteam/agent.py's chunked stage runner, the caller this exists for:
        it catches ContextBudgetExceeded specifically to mean "start a fresh
        chunk," distinct from every other ProviderError, which means "this
        campaign is genuinely broken, stop."""
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
                if token_budget and usage_totals["prompt_tokens"] >= token_budget:
                    raise ContextBudgetExceeded(
                        f"context budget exceeded: {usage_totals['prompt_tokens']} prompt "
                        f"tokens >= {token_budget} (model still requesting tool calls)",
                        usage=dict(usage_totals),
                    )
                messages.append(message)
                # By this point _call()'s `with urllib.request.urlopen(...)`
                # block has already exited -- the connection this response
                # arrived on is fully closed before any execute_tool() call
                # below runs. Logged explicitly (not just true by
                # construction) so a transcript can show it: request ->
                # response -> close -> dispatch tools -> new request, never
                # a tool executing while a connection to the provider is
                # still open.
                print(f"    [{_now_ts()}] provider connection closed; "
                      f"dispatching {len(requested)} tool call(s)")
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

        raise IterationsExhausted(
            f"exceeded {max_iterations} tool-use iterations without a final turn",
            usage=usage_totals,
        )

    def complete(self, system, user, tools, execute_tool,
                 token_budget=None, max_chunks=1, max_tokens_hard_cap=None):
        # Single-phase, like claude.py -- these catalogs are tool-capable,
        # instruction-following models that reliably follow "respond with
        # ONLY the JSON verdict" directly, unlike local.py's smaller models
        # which need the separate unconstrained-analysis-then-forced-JSON
        # split to reach the same reliability.
        #
        # Chunking (token_budget/max_chunks) mirrors redteam/agent.py's
        # _run_chained_stage -- added 2026-07-28 after a defender run against
        # a candidate with heavily-correlated evidence produced a single tool
        # result north of 130K tokens, ballooning one candidate's triage past
        # 450K tokens and suspending the account. Same reasoning as
        # redteam's: real usage numbers only exist for these
        # OpenAI-compatible catalogs (see AgenticResult.usage), so this is
        # where the actual enforcement lives -- claude.py/local.py accept
        # the same parameters for a uniform Provider interface but can't act
        # on token_budget without usage data, same as their
        # run_agentic_turn()s already document.
        #
        # Restarting a chunk resends the ORIGINAL system+user turn (not a
        # distinct continuation prompt the way redteam's recon/assess
        # stages need one) -- the candidate's evidence bundle in `user` is
        # cheap and exactly what the model should be looking at regardless
        # of which chunk this is; what actually got expensive was the
        # accumulated tool-call HISTORY within one long-running turn, and
        # that's exactly what a restart discards. A short note appended to
        # `user` on chunk 2+ tells the model why it's starting over and to
        # wrap up rather than re-explore from scratch.
        continuation_note = (
            "\n\n---\nYour investigation of this candidate grew large enough "
            "that we're restarting fresh rather than let it keep growing -- "
            "any raise_alert/recommend_block/block_ip/page_oncall call you "
            "already made is already recorded regardless of this restart. "
            "Re-review the evidence above; if you already have enough to "
            "decide, respond with your verdict JSON now. If you still need a "
            "tool call, make only the essential one(s), then decide."
        )
        cumulative = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
        for chunk in range(1, max(1, max_chunks) + 1):
            this_user = user if chunk == 1 else user + continuation_note
            messages = [
                {"role": "system", "content": system},
                {"role": "user", "content": this_user},
            ]
            try:
                result = self.run_agentic_turn(messages, tools, execute_tool,
                                                 MAX_TOOL_ITERATIONS, token_budget=token_budget)
            except ContextBudgetExceeded as e:
                if e.usage:
                    for k in cumulative:
                        cumulative[k] += e.usage.get(k, 0)
                print(f"    [triage chunk {chunk}/{max_chunks} hit context budget -- {e}]")
                if max_tokens_hard_cap and cumulative["prompt_tokens"] >= max_tokens_hard_cap:
                    raise ProviderError(
                        f"hard token cap ({max_tokens_hard_cap}) reached across "
                        f"{chunk} chunks without a final verdict"
                    ) from e
                continue

            if result.usage:
                for k in cumulative:
                    cumulative[k] += result.usage.get(k, 0)
            if chunk > 1:
                print(f"    [triage concluded after {chunk} chunks, cumulative usage: "
                      f"{cumulative['prompt_tokens']} prompt / {cumulative['completion_tokens']} "
                      f"completion / {cumulative['total_tokens']} total]")
            parsed = parse_verdict_json(result.final_text)
            return Verdict(
                verdict=parsed["verdict"],
                confidence=parsed["confidence"],
                rationale=parsed["rationale"],
                recommended_action=parsed["recommended_action"],
                attack_technique=parsed.get("attack_technique"),
                model=result.model or self.model,
                tool_calls=result.tool_calls,
                usage=cumulative,
            )

        raise ProviderError(f"exceeded {max_chunks} chained chunks without a final verdict")

    def _call(self, api_key, messages, tools):
        # Streamed (SSE), not a single blocking POST -- a non-streaming
        # request against a reasoning model with a large prompt has nothing
        # come back over the wire until generation finishes, so total
        # generation time has to fit inside Cloudflare's ~600s origin
        # timeout on GMI's end. That was the steady state, not an outlier,
        # once prompts grew into the tens of thousands of tokens (see
        # DEFAULT_CONTEXT_BUDGET in redteam/agent.py) -- a 4h16m session
        # died to exactly this (GMI 524) after 21 of 22 chunks had already
        # been cut short by budget/iteration limits, on the one chunk that
        # finally would have run to completion. Streaming means bytes flow
        # continuously from the first token, so neither Cloudflare's origin
        # timer nor our own socket-read timeout (which resets on every
        # read, not the request as a whole) ever sees a silent gap long
        # enough to fire, even though total wall-clock for one call can
        # still run well past 600s.
        #
        # `_assemble_stream` reassembles the SSE chunks into the exact same
        # {"choices": [{"message": {...}}], "usage": {...}, "model": ...}
        # shape the old non-streaming response had, so run_agentic_turn()
        # below needs no changes at all.
        body = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "stream_options": {"include_usage": True},
        }
        if tools:
            body["tools"] = tools
        body = json.dumps(body).encode("utf-8")

        for attempt in range(MAX_CALL_ATTEMPTS):
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
                    "accept": "text/event-stream",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_s) as r:
                    return self._assemble_stream(r)
            except urllib.error.HTTPError as e:
                detail = e.read().decode("utf-8", errors="replace")[:500]
                if e.code in RETRYABLE_HTTP_CODES and attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [{self.error_prefix} {e.code} -- retrying in {delay:.1f}s "
                          f"(attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"{self.error_prefix} {e.code}: {detail}") from e
            except urllib.error.URLError as e:
                if attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [{self.error_prefix} unreachable ({e.reason}) -- retrying in "
                          f"{delay:.1f}s (attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"{self.error_prefix} unreachable: {e.reason}") from e
            except (TimeoutError, OSError, http.client.HTTPException) as e:
                # Covers a read timeout/connection reset mid-stream too, not
                # just at connect time -- iterating the response below can
                # raise any of these once bytes stop arriving. Nothing has
                # been returned to the caller yet at that point (this method
                # hasn't returned, so run_agentic_turn() hasn't dispatched
                # any tool calls from this attempt), so retrying here and
                # resending the identical `messages` is safe: there is
                # nothing from this attempt to duplicate.
                if attempt < MAX_CALL_ATTEMPTS - 1:
                    delay = retry_backoff_s(attempt)
                    print(f"    [{self.error_prefix} request failed ({e}) -- retrying in "
                          f"{delay:.1f}s (attempt {attempt + 2}/{MAX_CALL_ATTEMPTS})]")
                    time.sleep(delay)
                    continue
                raise ProviderError(f"{self.error_prefix} request failed: {e}") from e

    def _assemble_stream(self, response):
        """Reassemble an OpenAI-compatible SSE stream into the same response
        shape _call() used to hand back directly from json.loads() on a
        non-streaming body. Tool-call deltas arrive fragmented across many
        events, keyed by `index` (one stream can interleave deltas for
        several parallel tool calls) -- accumulate by index and only treat
        a tool call as complete once the stream itself ends, never dispatch
        from a partial fragment."""
        role = None
        content_parts = []
        reasoning_parts = []
        tool_calls_by_index = {}
        finish_reason = None
        usage = None
        model = self.model

        for raw_line in response:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line or not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            try:
                event = json.loads(data)
            except json.JSONDecodeError:
                continue

            if event.get("model"):
                model = event["model"]
            if event.get("usage"):
                # The final event on most OpenAI-compatible catalogs (with
                # stream_options.include_usage set above) carries usage with
                # an EMPTY choices list -- captured here, before the
                # `if not choices` check below, so it isn't skipped.
                usage = event["usage"]

            choices = event.get("choices") or []
            if not choices:
                continue
            choice = choices[0]
            if choice.get("finish_reason"):
                finish_reason = choice["finish_reason"]
            delta = choice.get("delta") or {}
            if delta.get("role"):
                role = delta["role"]
            if delta.get("content"):
                content_parts.append(delta["content"])
            if delta.get("reasoning_content"):
                reasoning_parts.append(delta["reasoning_content"])
            for tc_delta in delta.get("tool_calls") or []:
                idx = tc_delta.get("index", 0)
                entry = tool_calls_by_index.setdefault(idx, {
                    "id": None, "type": "function",
                    "function": {"name": "", "arguments": ""},
                })
                if tc_delta.get("id"):
                    entry["id"] = tc_delta["id"]
                if tc_delta.get("type"):
                    entry["type"] = tc_delta["type"]
                fn_delta = tc_delta.get("function") or {}
                if fn_delta.get("name"):
                    entry["function"]["name"] += fn_delta["name"]
                if fn_delta.get("arguments"):
                    entry["function"]["arguments"] += fn_delta["arguments"]

        message = {"role": role or "assistant", "content": "".join(content_parts) or None}
        if reasoning_parts:
            message["reasoning_content"] = "".join(reasoning_parts)
        if tool_calls_by_index:
            message["tool_calls"] = [tool_calls_by_index[i] for i in sorted(tool_calls_by_index)]

        return {
            "choices": [{"message": message, "finish_reason": finish_reason}],
            "usage": usage or {},
            "model": model,
        }
