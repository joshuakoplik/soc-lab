# target-designer

An agentic designer that turns **recent, published CVEs** into chainable,
dockerized, intentionally-vulnerable lab targets — the same kind of box as
Vulhub or the lab's own `wordpress/` mode, but composed automatically and kept
recent enough to postdate model training data (the difficulty point).

## Pipeline

```
discover  →  pull recent foothold (RCE/injection) + privesc (LPE) CVEs from NVD
design    →  an LLM composes ONE foothold + ONE privesc into a single-host
             chain scenario + a docker build recipe (a TargetSpec)
generate  →  assemble the Dockerfile from the spec
build      →  build → verify → repair loop: docker build, run the non-exploit
             checks, and on any failure feed the build/verify output back to the
             model for a corrected Dockerfile, up to --max-repair attempts
verify     →  confirm it stood up (liveness + vulnerable-version presence)
deploy     →  wire it into the lab via the dealer range (--deploy)
save       →  persist spec.json + Dockerfile + build log under targets/<id>/
```

## Wiring into the lab (Wazuh / Suricata / network)

Deploy reuses the **dealer** range's plumbing rather than inventing a parallel
one: a built image is a plain docker image ref, which `dealer-range/up.py`
already stands up on the internal, no-egress `soclab-dealer` bridge under an
opaque random hostname, and `dealer-range/wire.py` makes it observable —
restarts Suricata to pick up `soclab-dealer0` (network leg) and tails the
container's **stdout** into the permanent Wazuh `/lab-logs/dealer/` buckets (log
leg). So a designed target lands in the defender's telemetry exactly like any
dealer target, with no new wiring. This is why the designer biases every target
toward **foreground services that log to stdout** and a **self-contained
runtime** (the bridge has no egress).

```bash
# design + build-repair + wire into the lab in one go (switches active mode to dealer):
python3 target-designer/designer.py --stage all --deploy --env-file /home/josh/soc-lab/.env

# rebuild / iterate a saved target without a new design call:
python3 target-designer/designer.py --from-spec <target-id> --max-repair 4 \
  --env-file /home/josh/soc-lab/.env

# or deploy an already-built image the normal way:
./lab-mode.sh switch dealer soclab-td/<target-id>:latest
```

```bash
# discover only (stdlib, no key needed):
python3 target-designer/cve_feed.py --days 30 --min-cvss 9 --role foothold

# design a chain (needs GMI_API_KEY; --env-file points at the repo-root .env):
python3 target-designer/designer.py --stage design --no-build \
  --env-file /home/josh/soc-lab/.env --model moonshotai/kimi-k3

# full run incl. docker build:
python3 target-designer/designer.py --stage all --env-file /home/josh/soc-lab/.env
```

Stdlib only (urllib), like `ingest.py` / `labctl` — the LLM call hits the same
GMI OpenAI-compatible endpoint `pipeline/providers/gmi.py` uses.

## Scope & safety

This builds the vulnerable **environment** from **published** advisory
information and writes an operator-side **answer key** (`chain_narrative`, prose
referencing CVE IDs). It deliberately does **not**:

- discover unpublished / 0-day vulnerabilities, or
- author or run weaponized exploit code / payloads / attack scripts.

Exploitation is the lab **attacker agent's** job. `verify` runs **non-exploit**
checks only — service liveness, an open port, or a version/banner string that
proves the vulnerable build is present. This mirrors the lab's existing
hand-built CVE targets and the rule that vulnerable services are built from
docs, not live-PoC testing. Targets are for the isolated, egress-locked range
only. If you hand it a **CVE ID or advisory of your own** (including private
research), it can instantiate that too — the designer does the plumbing, not the
vuln discovery.

`targets/` is generated output and gitignored.
