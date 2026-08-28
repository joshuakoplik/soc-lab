# northwind-range -- the vulnerable AI application

The fourth lab mode, and the odd one out: where `easy`/`hard`/`wordpress` are
vulnerable *services*, Northwind is a vulnerable **AI product** — an air-gapped
RAG chat application with real authentication, real per-tenant authorization,
and real tool use, wrapped in a harness that swaps backend models and toggles
individual security controls to measure each one's effect independently.

The thesis it exists to test: *an attacker writes into a trusted store, and the
platform voluntarily ingests it.*

## Structurally separate, on purpose

This is its own docker-compose project (`name: northwind-range`) with its own
networks, its own `.env`, and its own `Makefile` — not a profile in the repo's
top-level `compose.yaml`, and not a `pipeline/net_topology.py` subnet. The
red-team agent therefore reaches it through `pipeline/redteam/northwind_adapter.py`
rather than nmap/hydra.

```bash
cd northwind-range
cp .env.example .env     # NW_OLLAMA_UPSTREAM_HOST is required, and must be a raw IP
make up                  # build + start
make reset               # wipe and re-seed corpus, entitlements, records
make verify              # the full assertion suite against live state
```

`../lab-mode.sh up northwind` does the same thing by delegating to this
Makefile, and is the better entry point since it also sets `lab_mode.json`.

> Because this project is nested inside another compose project, always `cd`
> here or pass `-f` explicitly. A stale working directory will point
> `docker compose down` at the wrong stack.

## Specs

- `SPEC.md` — the range itself: services, networks, egress policy, data model
- `SPEC_phase2.md` — the control-ablation harness
- `REDTEAM_MODE_SPEC.md` — how the red-team agent engages this mode
