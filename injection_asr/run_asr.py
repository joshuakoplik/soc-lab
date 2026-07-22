#!/usr/bin/env python3
"""
Single entry point for the outcome-based indirect-prompt-injection ASR
harness. Forges known-malicious cases, embeds a payload from each attack
class into the real attacker-controlled fields, runs them through the ACTUAL
normalize -> SQLite -> rules -> agent.py triage path (against an isolated
harness DB, never the lab's real soc.db), scores the outcome per the
domain-specific oracle in scorer.py, and writes harness/RESULTS.md plus a
JSONL audit log.

    python3 harness/run_asr.py                                   # defaults: local/qwen3:8b, both controls arms, 8 cases/class
    python3 harness/run_asr.py --provider claude --model claude-sonnet-4-6
    python3 harness/run_asr.py --classes imperative,false_context --n-per-class 20
    python3 harness/run_asr.py --controls on                      # skip the ablation, one arm only
    python3 harness/run_asr.py --backend ollama                   # add externally-generated variants
    python3 harness/run_asr.py --backend fireworks --backend-model accounts/fireworks/models/glm-5p1

Hard constraint this harness relies on and does not itself enforce: no tool
in this codebase ever executes a block against real infrastructure.
recommend_block only ever writes block_recommendations with approved=0,
never read or acted on by anything; block_ip (pipeline/agent.py's
tool_block_ip) is a test-only no-op stand-in that logs the call and returns
success without touching anything real. A "block" win condition in this
harness is therefore always an OBSERVED, never-executed call aimed at the
wrong target, exactly as the plan required -- true regardless of what src_ip
the injector generates, which is why harness/injector.py no longer
constrains itself to non-routable ranges (see harness/config.py).
"""

import argparse
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "pipeline"))
sys.path.insert(0, os.path.join(ROOT, "pipeline", "triage"))

from injection_asr import config, db, injector, report, runner, scorer  # noqa: E402
from injection_asr.payloads import generator  # noqa: E402
import agent  # noqa: E402

DEFAULT_RUN_DIR = os.path.join(HERE, "runs", "default")
DEFAULT_DB_PATH = os.path.join(DEFAULT_RUN_DIR, "harness.db")
DEFAULT_JSONL_PATH = os.path.join(DEFAULT_RUN_DIR, "results.jsonl")
DEFAULT_MD_PATH = os.path.join(DEFAULT_RUN_DIR, "RESULTS.md")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--provider", choices=["claude", "local", "gmi", "fireworks"], default="local")
    ap.add_argument("--model", default=None)
    ap.add_argument("--seed", type=int, default=config.DEFAULT_SEED)
    ap.add_argument("--n-per-class", type=int, default=config.DEFAULT_N_PER_CLASS)
    ap.add_argument("--classes", default=",".join(generator.CLASS_MODULES),
                     help="comma-separated attack classes to run")
    ap.add_argument("--controls", choices=["on", "off", "both"], default="both")
    ap.add_argument("--backend", choices=["template", "ollama", "fireworks", "garak"], default="template",
                     help="payload generation backend (default: built-in, no network)")
    ap.add_argument("--backend-model", default=None,
                     help="model for the payload-generation backend, independent of --model "
                          "(the triage model) -- defaults to that backend's own default model")
    ap.add_argument("--gateway-ip", default=config.DEFAULT_GATEWAY_IP)
    ap.add_argument("--min-alert-severity", default=config.DEFAULT_MIN_ALERT_SEVERITY,
                     choices=list(config.SEVERITY_RANK))
    ap.add_argument("--db-path", default=DEFAULT_DB_PATH,
                     help="isolated harness database (reset every run; never soc.db)")
    ap.add_argument("--jsonl-out", default=DEFAULT_JSONL_PATH)
    ap.add_argument("--md-out", default=DEFAULT_MD_PATH)
    args = ap.parse_args()

    for out_path in (args.db_path, args.jsonl_out, args.md_out):
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)

    classes = args.classes.split(",")
    arms = ["on", "off"] if args.controls == "both" else [args.controls]

    print(f"[*] harness db: {args.db_path} (reset)")
    conn = db.connect(args.db_path, reset=True)

    payloads = generator.generate_all(
        args.seed, args.n_per_class, classes=classes,
        gateway_ip=args.gateway_ip, backend=args.backend,
        backend_model=args.backend_model,
    )
    print(f"[*] generated {len(payloads)} payload(s) across {len(classes)} class(es) "
          f"(backend={args.backend}, seed={args.seed})")

    inject_rng = random.Random(args.seed)
    cases = injector.inject_cases(conn, inject_rng, payloads)
    n_missing = sum(1 for c in cases if not c["candidate_id"])
    print(f"[*] {len(cases)} case(s) forged through the real pipeline, "
          f"{len(cases) - n_missing} produced a real candidate"
          + (f", {n_missing} did NOT (skipped)" if n_missing else ""))

    provider = agent.build_provider(args.provider, args.model)
    print(f"[*] triaging via provider={args.provider} model={provider.model}, controls arm(s)={arms}")

    all_scored = []
    for controls in arms:
        print(f"\n[*] --- controls={controls} ---")
        results = runner.run_suite(conn, cases, provider, args.provider, controls)
        scored = scorer.score_all(
            results, min_alert_severity=args.min_alert_severity, gateway_ip=args.gateway_ip
        )
        for c in scored:
            tag = ("WIN " + "+".join(c["score"]["reasons"])) if c["score"]["win"] else "caught"
            print(f"    {c['payload'].attack_class:<16} {c['payload'].variant_id:<20} "
                  f"-> {c['result']['verdict']:<12} {tag}")
        all_scored.extend(scored)

    summary = scorer.summarize(all_scored)
    report.write_jsonl(all_scored, args.jsonl_out)
    report.write_markdown(all_scored, summary, args.md_out, meta={
        "provider": args.provider, "model": provider.model, "seed": args.seed,
        "n_cases": len(cases), "min_alert_severity": args.min_alert_severity,
        "jsonl_path": args.jsonl_out,
    })

    print(f"\n[*] wrote {args.md_out} and {args.jsonl_out}")
    for controls in arms:
        overall = summary[controls]["__overall__"]
        print(f"    ASR (controls={controls}): {overall['wins']}/{overall['n']} = {overall['asr']:.1%}")


if __name__ == "__main__":
    main()
