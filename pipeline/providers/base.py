"""
Provider interface the triage loop codes against, and nothing else.

AGENT_BRIEF.md #4 is the reason this file exists: "the triage loop MUST NOT
import any vendor SDK directly." pipeline/agent.py imports Provider, Verdict,
and ProviderError from here -- never anthropic.*, never an Ollama client.
Adding a third backend is a new file in this package implementing Provider;
agent.py does not change. claude.py and local.py are the proof -- writing the
second one is what verifies the first one's abstraction was honest.
"""

import json
import random
import re
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

VALID_VERDICTS = ("benign", "suspicious", "malicious", "needs_human")

# Shared retry policy for every HTTP-backed provider (claude.py, openai_compat.py).
# 524 is Cloudflare's own "origin took too long to respond" -- the exact
# failure a 4h16m red-team session died to, unhandled, right after
# identifying the real vuln chain. 5xx is the backend having a bad moment,
# 429 is a rate limit usually gone by the next attempt. 4xx other than 429
# (bad request, auth) is deliberately NOT here: retrying a malformed request
# just fails the same way five times slower.
RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}
# 1 initial attempt + this many retries. "3-5 attempts" -- 5 total (4
# retries) errs toward not losing a multi-hour campaign to one transient
# blip, same reasoning as this codebase's long per-call timeouts.
MAX_CALL_ATTEMPTS = 5


def retry_backoff_s(attempt):
    """Exponential with jitter, capped at 20s. `attempt` is 0-indexed (the
    attempt that just failed): attempt=0 -> ~1-2s, attempt=3 -> ~8-9s.
    Capped rather than left to grow unbounded -- past a few attempts the
    question isn't "did we wait long enough" so much as "is this actually
    transient at all," and MAX_CALL_ATTEMPTS is what answers that."""
    return min(2 ** attempt, 20) + random.uniform(0, 1)

# The vendor-neutral tool shape: name, description, JSON schema for input.
# Anthropic's tool format IS this shape, so ClaudeProvider passes it through
# unchanged. LocalProvider reshapes it into whatever its wire format wants.
ToolSpec = dict

# Called by a provider mid-loop when the model requests a tool. Returns
# (result_text, is_error) -- is_error lets the provider tell the model the
# call failed (bad input, unknown event id, ...) without that surfacing as a
# ProviderError and killing the candidate.
ToolExecutor = Callable[[str, dict], "tuple[str, bool]"]


@dataclass
class Verdict:
    verdict: str
    confidence: float
    rationale: str
    recommended_action: str
    attack_technique: Optional[str]
    model: str
    tool_calls: int = 0
    # Whatever reasoning led to this verdict -- the model's <think> trace
    # where the provider exposes one, plus (see local.py) any non-JSON reply
    # that had to be retried. Kept for audit/comparison, never parsed.
    thinking: Optional[str] = None
    # Same shape and same caveats as AgenticResult.usage -- real API-reported
    # token counts where the provider has them (GMI/Fireworks), None otherwise.
    usage: Optional[dict] = None


@dataclass
class AgenticResult:
    """Result of one unconstrained tool-use turn -- ends when the model stops
    requesting tools, not when it produces any particular shape of output.
    Shared between LocalProvider/ClaudeProvider's own run_agentic_turn()
    methods (the loop mechanics stay vendor-specific, only this return shape
    is common) and redteam_agent.py's per-stage campaign turns.

    `messages` is the full conversation so far, mutated in place and also
    returned, so a caller can keep going: complete()'s phase 2 appends a
    format-locked follow-up to it; a red-team campaign stage starts a fresh
    one per stage instead."""
    final_text: str
    tool_calls: int
    thinking: Optional[str]
    messages: list
    model: Optional[str] = None
    # Cumulative {prompt_tokens, completion_tokens, total_tokens} across every
    # call in this turn, when the provider's API reports real usage (GMI/
    # Fireworks' OpenAI-compatible responses do). None for providers that
    # don't -- Ollama's /api/chat has its own prompt_eval_count/eval_count
    # fields, not this shape, and Anthropic's Messages API usage isn't wired
    # up here yet. Never estimated; only ever a real number from the API.
    usage: Optional[dict] = None


class Heartbeat:
    """Background thread that prints an elapsed-time tick every `interval_s`
    while a blocking provider call is in flight. Neither provider's HTTP call
    streams, so without this a slow local model just goes silent for however
    long inference takes -- indistinguishable from a hang. Not a progress bar
    (there's no total to measure against, see redteam_agent.py's stage
    runners): just proof of life."""

    def __init__(self, label, interval_s=10):
        self._label = label
        self._interval = interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        start = time.monotonic()
        while not self._stop.wait(self._interval):
            print(f"       ...{self._label}, {time.monotonic() - start:.0f}s elapsed")

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self._stop.set()
        self._thread.join(timeout=1)


class ProviderError(Exception):
    """A provider call failed outright: network, auth, rate limit, or a model
    response so malformed there's nothing left to defensively parse. The loop
    in agent.py MUST catch this per candidate and record a failure verdict --
    see AGENT_BRIEF.md #4: "the loop MUST survive one candidate's failure and
    move on." One candidate's bad day does not get to kill the batch."""


class ContextBudgetExceeded(ProviderError):
    """Raised by run_agentic_turn() instead of the plain "exceeded N
    iterations" ProviderError when a `token_budget` was given and this
    call's accumulated prompt tokens crossed it -- deliberately BEFORE
    max_iterations, so a caller doing chunked/chained turns (see
    redteam/agent.py's run_recon_stage/run_assess_stage, triage/agent.py's
    chunked complete()) can tell "this chunk got too big, start a fresh
    one" apart from a real failure or genuine iteration exhaustion. Still a
    ProviderError, so code that only catches the base class keeps working
    unchanged.

    `usage`, when the raising call had real numbers to report (GMI/
    Fireworks), carries the discarded chunk's own token spend -- a caller
    tracking cumulative cost across restarts (a hard cap on top of chunking)
    needs this: the chunk that hit the budget still cost real tokens even
    though its own result is thrown away, so cumulative cost isn't just the
    sum of successful chunks' usage."""

    def __init__(self, message, usage=None):
        super().__init__(message)
        self.usage = usage


class IterationsExhausted(ProviderError):
    """Raised by run_agentic_turn() instead of the plain "exceeded N
    iterations" ProviderError when max_iterations is hit without the model
    producing a final (non-tool-call) turn -- distinct from
    ContextBudgetExceeded (which fires on token growth, not call count) so
    a caller doing chunked/chained turns can restart on EITHER exhaustion
    signal the same way, without conflating "this chunk got too big" with
    "this chunk ran out of narrowly-scoped steps." See redteam/agent.py's
    _run_chained_stage, which now treats both identically: write a handoff
    note, continue with a fresh chunk, rather than let either kill the
    whole stage -- deliberately capping max_iterations low (see
    RECON_MAX_ITERATIONS/ASSESS_MAX_ITERATIONS there) makes this the
    NORMAL way a chunk ends, not a rare safety-valve.

    `usage`, when available, follows the same convention as
    ContextBudgetExceeded.usage -- the exhausted chunk's own token spend,
    thrown away along with its result but still real cost."""

    def __init__(self, message, usage=None):
        super().__init__(message)
        self.usage = usage


class Provider(Protocol):
    model: str

    def complete(
        self,
        system: str,
        user: str,
        tools: "list[ToolSpec]",
        execute_tool: ToolExecutor,
        token_budget: Optional[int] = None,
        max_chunks: int = 1,
        max_tokens_hard_cap: Optional[int] = None,
    ) -> Verdict: ...


def _extract_json_object(text: str):
    """Scan for every '{' in the text and try a balanced decode from each,
    keeping the LAST one that parses. The model's true final answer is
    whatever it committed to last -- a narrated preamble ("investigating
    candidate {5}...") can itself contain stray '{' characters, so we can't
    just take the first match; we take the last thing that actually parses
    as a JSON value."""
    decoder = json.JSONDecoder()
    best = None
    idx = 0
    while True:
        start = text.find("{", idx)
        if start == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, start)
            best = obj
            idx = end
        except json.JSONDecodeError:
            idx = start + 1
    return best


# Matches a `// comment` only when preceded by whitespace, so it strips a
# trailing JS-style annotation the model tacks onto a JSON value (a common
# local-model quirk -- JSON has no comment syntax, so it breaks parsing
# outright) without mangling a `://` inside a URL string, which never has
# whitespace immediately before the slashes.
_TRAILING_COMMENT_RE = re.compile(r"[ \t]+//[^\n]*")


def _strip_trailing_comments(text: str) -> str:
    return _TRAILING_COMMENT_RE.sub("", text)


def parse_verdict_json(text: str) -> dict:
    """Defensive parse of the model's final turn, shared by every provider so
    the "strip fences, catch the parse" rule in AGENT_BRIEF.md #5 has exactly
    one implementation. Raises ProviderError -- not a silent None -- because a
    verdict we can't parse is a failure worth recording, not a candidate to
    quietly drop (the recurring failure mode the brief calls out).

    Observed live against claude-sonnet-4-6: after a few tool calls the model
    sometimes narrates before committing to JSON ("Here is the final
    verdict:\n\n```json\n{...}") even though the system prompt says JSON
    only. A bare fence-strip only handles a LEADING fence, so that case falls
    straight to a decode error at char 0. Fall back to scanning the text for
    the JSON object rather than giving up on the first non-JSON character."""
    stripped = text.strip()
    if stripped.startswith("```"):
        # Model added fences despite instructions not to. First line is the
        # fence, optionally with a language tag ("```json"); last is the fence.
        lines = stripped.split("\n")
        lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        data = _extract_json_object(text)
        if data is None:
            # Observed live against qwen3:8b: an otherwise-valid object with
            # a `// explanation` tacked onto one field (JSON has no comment
            # syntax, so this breaks the decode outright even though every
            # other character is well-formed). Try once more with those
            # stripped before giving up -- free, no extra model call.
            repaired = _strip_trailing_comments(text)
            if repaired != text:
                data = _extract_json_object(repaired)
        if data is None:
            # Full text, not a snippet -- a truncated preview here looks
            # exactly like the model's output was cut off even when it
            # wasn't, and destroys the one piece of evidence needed to tell
            # "model ran out of budget" from "model wrote malformed JSON"
            # apart after the fact.
            raise ProviderError(
                f"model returned non-JSON output: no parseable object found; "
                f"raw={text!r}"
            ) from None

    if not isinstance(data, dict):
        raise ProviderError(f"verdict JSON was not an object: {data!r}")

    required = ("verdict", "confidence", "rationale", "recommended_action")
    missing = [k for k in required if k not in data]
    if missing:
        raise ProviderError(f"verdict JSON missing fields {missing}: {data!r}")

    if data["verdict"] not in VALID_VERDICTS:
        raise ProviderError(f"model returned invalid verdict {data['verdict']!r}")

    try:
        data["confidence"] = float(data["confidence"])
    except (TypeError, ValueError) as e:
        raise ProviderError(f"confidence not a number: {data['confidence']!r}") from e

    data.setdefault("attack_technique", None)
    return data
