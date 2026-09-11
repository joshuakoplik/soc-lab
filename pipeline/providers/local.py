"""
Local, OpenAI/Ollama-compatible backend. This is what lets the whole triage
tier run air-gapped -- no candidate data (which is, by construction,
attacker-controlled text) leaves the box. See AGENT_BRIEF.md #4.

Talks Ollama's native /api/chat, which is the lowest-common-denominator
surface most self-hosted runtimes speak. Base URL from OLLAMA_HOST, default
http://localhost:11434. No API key, no beta headers, no vendor SDK.
"""

import json
import os
import urllib.error
import urllib.request

from .base import (
    VALID_VERDICTS,
    AgenticResult,
    Heartbeat,
    IterationsExhausted,
    ProviderError,
    Verdict,
    parse_verdict_json,
)

DEFAULT_BASE_URL = "http://localhost:11434"
MAX_TOOL_ITERATIONS = 8

# Grammar-constrains the final-turn `content` generation to this exact
# shape -- Ollama enforces it at the token level, so the model literally
# cannot emit prose or a trailing `// comment` there. The <think> trace
# (when "think": true) is a separate, unconstrained generation phase before
# this kicks in, so reasoning is untouched. additionalProperties: false
# closes the one gap a comment-as-extra-key trick could still sneak through.
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(VALID_VERDICTS)},
        "confidence": {"type": "number"},
        "rationale": {"type": "string"},
        "recommended_action": {"type": "string"},
        "attack_technique": {"type": ["string", "null"]},
    },
    "required": [
        "verdict", "confidence", "rationale", "recommended_action",
        "attack_technique",
    ],
    "additionalProperties": False,
}
# Local models on modest hardware are slow, and get slower with model size --
# a hardcoded cutoff that was fine for an 8b model can hard-fail a genuinely
# bigger one mid-call (ProviderError, not just a slow response). Overridable
# via OLLAMA_TIMEOUT_S rather than requiring a code edit per model swap.
TIMEOUT_S = int(os.environ.get("OLLAMA_TIMEOUT_S", "1200"))
# Reasoning models (qwen3 etc.) emit a <think>...</think> trace by default --
# parse_verdict_json would choke on that prose instead of the JSON verdict.
# num_ctx defaults to 4096 in Ollama, which silently truncates a
# candidate-plus-evidence prompt (no error, just a verdict reasoned over a
# clipped prompt) -- so we force it up rather than trust the server default.
# Overridable via OLLAMA_NUM_CTX: this is the model's REAL context window
# (unlike triage/agent.py's context_budget/max_chunks, which are an
# accounting threshold that this provider ignores entirely -- see
# run_agentic_turn's docstring), so it needs to match whatever model is
# actually configured, not just the smallest one this lab has used.
MIN_NUM_CTX = int(os.environ.get("OLLAMA_NUM_CTX", "32768"))
# Ollama's default num_predict is also small (server-dependent, often ~128-
# 2048) and is a single shared budget across the <think> trace AND the final
# JSON -- with thinking on, the trace alone can eat the whole budget and cut
# the verdict off mid-object. Give it real headroom. Overridable via
# OLLAMA_NUM_PREDICT for the same reason as OLLAMA_NUM_CTX above.
NUM_PREDICT = int(os.environ.get("OLLAMA_NUM_PREDICT", "8192"))


class LocalProvider:
    def __init__(self, model):
        self.model = model
        self.base_url = os.environ.get("OLLAMA_HOST", DEFAULT_BASE_URL).rstrip("/")
        self._supports_thinking = None  # lazily queried and cached, see _thinking_supported()

    def _thinking_supported(self):
        """Ollama 400s outright on `"think": true` for a model whose template
        doesn't support it (observed live: llama3.3:70b) -- not a slow
        response, a hard failure before anything else runs. Checked once per
        provider instance and cached rather than assumed true for every
        model the way the unconditional `think: True` used to."""
        if self._supports_thinking is None:
            req = urllib.request.Request(
                f"{self.base_url}/api/show",
                data=json.dumps({"model": self.model}).encode("utf-8"),
                method="POST",
                headers={"content-type": "application/json"},
            )
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                    info = json.loads(r.read().decode("utf-8"))
                self._supports_thinking = "thinking" in (info.get("capabilities") or [])
            except (urllib.error.URLError, urllib.error.HTTPError, OSError, ValueError):
                # Can't even ask -- fail toward not requesting it, since a
                # wrong `false` just means no <think> trace, while a wrong
                # `true` is the 400 this whole check exists to avoid.
                self._supports_thinking = False
        return self._supports_thinking

    def run_agentic_turn(self, messages, tools, execute_tool, max_iterations, token_budget=None):
        """Send `messages`, dispatching any tool calls the model requests via
        execute_tool, until it stops requesting tools and gives a free-text
        turn. This is the shared loop mechanics both complete() (triage,
        ending in a locked verdict schema) and a red-team campaign stage
        (ending in free-form analysis or a proposal) build on -- factored out
        so there's one implementation of Ollama's `role:"tool"` echo
        convention, not one per caller.

        `messages` is mutated in place and also returned via the result, so
        the caller can keep the conversation going after this turn ends.

        `token_budget` is accepted but ignored -- Ollama's /api/chat reports
        usage as prompt_eval_count/eval_count, not the
        {prompt_tokens,completion_tokens,total_tokens} shape openai_compat.py
        tracks, and AgenticResult.usage stays None for this provider (see
        base.py). Accepted anyway so redteam/agent.py's chunked stage runner
        can pass the same call uniformly across all four providers without
        needing to know which ones actually enforce it -- here it's just a
        no-op, chunking degrades to iteration-count-only for local models."""
        # Ollama's tool format is OpenAI-shaped: {type, function:{name,
        # description, parameters}}. Our ToolSpec is already
        # {name, description, input_schema} -- just the field names differ.
        ollama_tools = [
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
        thinking_parts = []
        usage_totals = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

        for i in range(max_iterations):
            print(f"    [iter {i + 1}/{max_iterations}] calling model ({self.model})...")
            with Heartbeat(f"iter {i + 1}/{max_iterations} still waiting on {self.model}"):
                resp = self._call(messages, ollama_tools)
            # Ollama's own field names -- prompt_eval_count/eval_count, not
            # OpenAI's usage.prompt_tokens/completion_tokens shape. Mapped
            # here so callers (agent.py, redteam_agent.py) get the same
            # {prompt_tokens, completion_tokens, total_tokens} shape
            # regardless of provider.
            p_tok = resp.get("prompt_eval_count", 0)
            c_tok = resp.get("eval_count", 0)
            usage_totals["prompt_tokens"] += p_tok
            usage_totals["completion_tokens"] += c_tok
            usage_totals["total_tokens"] += p_tok + c_tok
            print(f"       usage: +{p_tok} prompt / +{c_tok} completion "
                  f"(running total: {usage_totals['total_tokens']})")
            message = resp.get("message", {})
            requested = message.get("tool_calls") or []

            if requested:
                messages.append(message)
                for call in requested:
                    tool_calls += 1
                    fn = call.get("function", {})
                    name = fn.get("name")
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    text, _is_error = execute_tool(name, args)
                    # Ollama's chat API has no tool_call_id round-trip like
                    # Anthropic's -- a role:"tool" message in call order is
                    # the whole contract.
                    messages.append({"role": "tool", "content": text})
                continue

            thinking_parts.append(message.get("thinking") or "")
            final_text = message.get("content", "")
            messages.append(message)
            return AgenticResult(
                final_text=final_text,
                tool_calls=tool_calls,
                thinking="\n\n---\n\n".join(p for p in thinking_parts if p) or None,
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
        # token_budget/max_chunks/max_tokens_hard_cap accepted for a uniform
        # Provider.complete() interface but not acted on -- this provider's
        # run_agentic_turn() already documents why: Ollama's /api/chat
        # reports usage as prompt_eval_count/eval_count, not the shape
        # AgenticResult.usage tracks, so there's nothing to chunk against.
        #
        # Phase 1: unconstrained analysis. Tools are on the table and the
        # model is explicitly told NOT to give the final JSON yet -- just
        # investigate and build its case in prose. This is every candidate's
        # path now, not a fallback: analysis quality shouldn't depend on
        # whether the first parse happened to fail.
        #
        # This prompt calls out that action tools (raise_alert/
        # recommend_block/block_ip/page_oncall) are ONLY reachable here, in
        # phase 1 -- confirmed empirically (2026-07-29) that without this,
        # qwen3:30b-a3b reliably calls zero tools and goes straight to
        # prose, even with an obvious block_ip-warranting candidate: the
        # original wording ("investigate...you'll be asked for the verdict
        # in a follow-up turn") reads as "the decision, and anything that
        # follows from it, happens later" -- and later never comes, because
        # phase 2 is JSON-schema-constrained with an empty tools list (see
        # below for why that can't change: format+tools together makes this
        # model silently skip tool_calls entirely).
        #
        # That alone wasn't enough, though: with the fix above but nothing
        # more, the model would reason its way to "recommend_block is
        # warranted" and then just WRITE that sentence into its analysis
        # prose or recommended_action field instead of emitting a real tool
        # call -- correctly deciding, then never acting. The blunt
        # "get called out for pretending" framing below (confirmed 2/2 in
        # testing, vs. 0/2 without it) is what actually closed that gap --
        # softer phrasing ("please call the tool") didn't move it. Revisit
        # if a future model doesn't need this or reacts badly to it.
        analysis_prompt = (
            user
            + "\n\nThis is a reasoning turn, not the final answer -- ignore "
            "the JSON-only output contract above for now. Investigate using "
            "your tools as needed. If your investigation concludes that an "
            "action is warranted -- raise_alert, recommend_block, block_ip, "
            "or page_oncall -- call it now, in THIS turn: the follow-up turn "
            "that produces your JSON verdict is JSON-only and cannot call "
            "any tool, so this is your only chance to act, not just "
            "investigate.\n\n"
            "IMPORTANT -- a tool call means an actual function call, not a "
            "sentence. Deciding in your prose that 'recommend_block is "
            "warranted' and then only describing that decision in your "
            "analysis or in recommended_action is NOT the same as calling "
            "recommend_block, and does not do anything -- no record is "
            "created, nothing happens, and the decision is lost the moment "
            "this turn ends. If you have decided an action is warranted, "
            "you MUST emit it as a real tool call in this turn before you "
            "write a single word of prose. Writing about the tool instead "
            "of calling it is a failure to do your job, not a softer "
            "version of doing it. A triage run that decides an action is "
            "needed and then fails to actually call the tool is worse than "
            "useless: it creates the appearance of a handled incident while "
            "nothing was actually done. Models that narrate actions instead "
            "of taking them are pulled from production.\n\n"
            "Then write out your full analysis in prose: walk through the "
            "evidence, say what it means, and build the case for the "
            "verdict you're leaning toward. You'll be asked for the "
            "structured JSON verdict in a follow-up turn."
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": analysis_prompt},
        ]

        result = self.run_agentic_turn(messages, tools, execute_tool, MAX_TOOL_ITERATIONS)
        thinking_parts = [result.thinking] if result.thinking else []
        if result.final_text.strip():
            thinking_parts.append(result.final_text)
        messages = result.messages

        # Phase 2: force that analysis into the strict verdict schema. No
        # tools here -- format grammar-constrains `content` generation, which
        # empirically makes the model skip tool_calls entirely even when
        # told to use one first, and there's nothing left to investigate
        # once analysis is done anyway.
        messages.append({
            "role": "user",
            "content": (
                "Based on your analysis above, respond with ONLY the JSON "
                "verdict object for this candidate -- no prose, no markdown "
                "fences, nothing before or after it."
            ),
        })
        print(f"    calling model ({self.model}) for final verdict...")
        with Heartbeat(f"still waiting on {self.model} for final verdict"):
            resp = self._call(messages, [], force_format=True)
        message = resp.get("message", {})
        if message.get("thinking"):
            thinking_parts.append(message["thinking"])
        content = message.get("content", "")
        try:
            verdict = parse_verdict_json(content)
        except ProviderError as e:
            e.thinking = "\n\n---\n\n".join(p for p in thinking_parts if p)
            raise

        p_tok = resp.get("prompt_eval_count", 0)
        c_tok = resp.get("eval_count", 0)
        usage_totals = dict(result.usage) if result.usage else {
            "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
        }
        usage_totals["prompt_tokens"] += p_tok
        usage_totals["completion_tokens"] += c_tok
        usage_totals["total_tokens"] += p_tok + c_tok
        print(f"       usage: +{p_tok} prompt / +{c_tok} completion "
              f"(running total: {usage_totals['total_tokens']})")

        return Verdict(
            verdict=verdict["verdict"],
            confidence=verdict["confidence"],
            rationale=verdict["rationale"],
            recommended_action=verdict["recommended_action"],
            attack_technique=verdict.get("attack_technique"),
            model=resp.get("model", self.model),
            tool_calls=result.tool_calls,
            thinking="\n\n---\n\n".join(p for p in thinking_parts if p) or None,
            usage=usage_totals,
        )

    def _call(self, messages, tools, force_format=False):
        body = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "stream": False,
            "options": {"num_ctx": MIN_NUM_CTX, "num_predict": NUM_PREDICT},
        }
        if self._thinking_supported():
            body["think"] = True
        if force_format:
            body["format"] = VERDICT_SCHEMA
        body = json.dumps(body).encode("utf-8")

        # Fresh connection per call by design (no pooled session): requests can
        # be minutes apart while a tool runs, long enough that a pooled idle
        # socket gets closed by an intermediary and the next POST fails on a
        # dead socket. One handshake per call is negligible.
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=body,
            method="POST",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:500]
            raise ProviderError(f"local model API {e.code}: {detail}") from e
        except urllib.error.URLError as e:
            raise ProviderError(
                f"local model unreachable at {self.base_url}: {e.reason} "
                f"(is Ollama running? set OLLAMA_HOST to override)"
            ) from e
        except (TimeoutError, OSError) as e:
            raise ProviderError(f"local model request failed: {e}") from e
