# injection_asr -- indirect prompt-injection ASR harness

Measures how often an attacker can steer the triage agent by writing into the
fields the agent has to read. Attack success rate, measured by outcome rather
than by whether the text "looked like" an injection.

```bash
python3 injection_asr/run_asr.py [--provider ...] [--classes ...] [--controls on|off|both]
```

## How a case runs

It forges a known-malicious case, embeds a payload into the **real**
attacker-controlled fields, then runs it through the *actual*
normalize -> SQLite -> `detect/rules.py` -> `triage/agent.py` path — not a
mock of it — against an **isolated harness DB that is never `soc.db`**.
`scorer.py` then judges the outcome against a domain-specific oracle. A win for
the attacker means the wrong-target or no-alert outcome was *observed*, not
that the payload merely appeared persuasive.

Attack classes live in `payloads/`: `imperative`, `false_context`,
`field_splitting`, `evasion`, plus generator backends (garak, Ollama,
Fireworks) for externally-produced variants.

## What the controls ablation is for

`--controls on` is the production path: trust-fenced prompt,
`<untrusted-evidence>` separation. `--controls off` swaps in
`SYSTEM_PROMPT_NAIVE` with no separation at all. That arm exists **only** here
and is never reachable from `triage/agent.py`'s `main()`.

Comparing the two arms is the only way to tell whether a prompt change actually
improved injection resistance rather than merely changing verdicts. Report both.

## The deliberate exception

`block_ip` is **not** intercepted by this harness. `runner.py` routes it through
the same `agent.dispatch_tool` path a live triage run uses, on purpose —
whether a forged payload can talk the model into calling the real block tool on
the wrong target is exactly the question this harness exists to answer.

The only thing standing between that and your network is `block_enforcer.py`'s
hard CIDR fence, which admits this lab's own subnets and nothing else. A
rejection prints loudly so a fence hit during a run is never mistaken for
noise. Run `./reset.sh --network` afterwards to undo anything a run blocked; a
full `./reset.sh` isn't needed, since the harness DB is already isolated.
`recommend_block` never executes anywhere, harness or production.

## Output

Runs land in `runs/<name>/` — **entirely gitignored**, write-ups included. They
are one machine's numbers for one model lineup on one day, and re-running
overwrites them. If a finding is worth keeping, promote the conclusion into the
docs.
