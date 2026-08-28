# Northwind Range — Phase 1 Build Specification

**The RAG platform, entitlement layer, and ablation harness.**

**Target audience:** an agentic coding tool (Claude Code) building this end to end.

**What this is:** an air-gapped, instrumented AI application used as a measurement
instrument. It runs a realistic RAG chat product with real authentication, real
authorization, and real tool use, wrapped in a harness that can swap backend models and
toggle individual security controls so their effect can be measured independently.

**What this is not:** a capture-the-flag box. Phase 1 has no deliberate infrastructure
vulnerabilities enabled. Phase 2 adds those behind a build flag (§11).

**The thesis both phases serve:** an attacker writes into a trusted store, and the platform
voluntarily ingests it. Phase 1 is documents into a knowledge base. Phase 2 is models into a
registry. Same shape, different layer.

---

## 0. Hard constraints — read before writing any code

A build violating any of these is a failed build.

1. **No egress.** All Docker networks are `internal: true` except a build-time bridge torn
   down after image build, and except one deliberate, narrow exception: `llm-backend`
   forwards to an operator-controlled remote inference host over a dedicated
   non-`internal` network (`nw_llm_egress`), allow-listed to exactly that one destination —
   see §4 for the mechanism and the tradeoff being made. `scripts/verify-isolation.sh` must
   prove every other container reaches no external address, that `llm-backend` reaches
   nothing *but* its configured upstream, and must pass on a cold start.
2. **No host port publishing** except the operator harness API, bound to `127.0.0.1`. Never
   `0.0.0.0`. **Post-build-order exception:** `edge-nginx` also publishes the chat app on
   `${NW_EDGE_BIND_IP:-127.0.0.1}:8888 -> 80`. It is loopback by default; an operator who
   wants to reach the app from another of their own machines sets `NW_EDGE_BIND_IP` in
   `northwind-range/.env` to one specific private-interface address (a WireGuard/Tailscale-style
   IP), never `0.0.0.0` — the same discipline as the harness's own carve-out, just a private
   interface instead of loopback. Setting it widens the app's reachability beyond this host
   (any device on that private network can then reach it), which is a real, deliberate
   loosening of this constraint for operator convenience, not
   something `verify-isolation.sh` was written to expect; that script still asserts harness is
   the *only* published port and will need updating if this exception is meant to be permanent
   rather than a working-session convenience.
3. **No known-vulnerable dependency versions in any Phase 1 image.** Every package, base
   image and binary is pinned to a current patched release. This is stronger than "the vuln
   chain is disabled" — the vulnerable code must not be *present*, not merely unreachable.
   `scripts/verify-no-cves.sh` runs a dependency audit against every built image and **fails
   the build** on any known-vulnerable version. See §0.7 for the distinction this preserves.
4. **Every control in §5 is independently toggleable at runtime** without a rebuild, and its
   state is recorded with every result row. A control that cannot be turned off is not a
   control, it is an assumption.
5. **Determinism where possible.** Pinned seeds, pinned temperature, pinned model versions,
   versioned attack corpus. A run from March must be comparable to a run from July.
6. **The attack corpus content is maintainer-supplied.** See §9.4.
7. **Two categories of weakness, and only one belongs here.**

   - **Implementation mistakes — in scope, and the entire point.** Prompt-only entitlement
     enforcement, tools running with service credentials, post-filter retrieval, unreviewed
     ingestion, retrieved content placed in the system turn, missing output filtering.
     These are *configuration states* of correctly-written software. Each is a runtime
     toggle, each is recorded on every result row (§5.5), and each represents a design
     decision a real team plausibly made.
   - **Software vulnerabilities — out of scope entirely.** No CVE-bearing versions, no
     memory-safety bugs, no injection flaws in the application code itself, no deliberately
     broken crypto or session handling. Those live in a different lab mode with a different
     build.

   The line: Phase 1 measures whether an AI application's *design* holds up. It must never
   be possible to attribute a Phase 1 result to a bug in a library. If a leak occurs, it
   must be attributable to a toggle whose state is in the result row.

---

## 1. Scenario

"Northwind Analytics" runs an internal AI assistant for its support and operations staff. It
answers from an internal knowledge base, looks up customer records and tickets, and is used
across several departments and several customer tenants.

It has the properties a real deployment has: users with roles, documents with sensitivity
labels, customers belonging to tenants, and a knowledge base that ingests content from
places no human reviews closely.

---

## 2. Architecture

```
                    ┌─────────────┐
   operator ───────▶│   harness   │  (127.0.0.1 only)
                    └──────┬──────┘
                           │ config, runs, results
                           ▼
┌──────────┐      ┌──────────────┐      ┌──────────────┐
│  users  ─┼─────▶│  edge-nginx  │─────▶│   chat-web   │
└──────────┘      └──────────────┘      └──────┬───────┘
                                               ▼
                                        ┌──────────────┐
                                        │  portal-api  │  authN/authZ,
                                        └──────┬───────┘  orchestration,
                                               │          controls
                     ┌─────────────────────────┼──────────────────┐
                     ▼                         ▼                  ▼
              ┌────────────┐          ┌────────────────┐   ┌────────────┐
              │  litellm   │          │  retrieval-svc │   │ tool-svc   │
              └─────┬──────┘          └───────┬────────┘   └─────┬──────┘
                    ▼                         ▼                  ▼
            ┌──────────────┐          ┌──────────────┐   ┌──────────────┐
            │ llm-backend  │          │   postgres   │   │   postgres   │
            │  (swappable) │          │  + pgvector  │   │  app schema  │
            └──────────────┘          └──────────────┘   └──────────────┘
                                               ▲
                                        ┌──────┴───────┐
                                        │ ingest-svc   │◀── feedback form,
                                        └──────────────┘    ticket feed,
                                                            drive sync
```

### 2.1 Networks

| Network | CIDR | `internal` | Members |
|---|---|---|---|
| `nw_dmz` | 172.28.10.0/24 | yes | `edge-nginx`, `chat-web`, `portal-api` (dual-homed) |
| `nw_app` | 172.28.20.0/24 | yes | `portal-api`, `litellm`, `llm-backend`, `retrieval-svc`, `tool-svc`, `ingest-svc`, `postgres`, `redis` |
| `nw_ops` | 172.28.40.0/24 | no | `harness`, `postgres` (results schema) |
| `nw_llm_egress` | 172.28.50.0/24 | no | `llm-backend` (dual-homed with `nw_app`) |

Phase 2 adds `nw_ml`. Leave the compose file structured so that is additive.

**Note carried over from the earlier Phase 2 draft (`SPEC_phase2.md` §2.2), still load-bearing
here:** `internal: true` silently disables Docker's own host port publishing for every
container on that network, not just egress — confirmed empirically during the parent
soc-lab's own network-isolation refactor. `nw_ops` hosts the harness's one required host port
(§0.2), so **`nw_ops` must not be `internal: true`**, unlike `nw_dmz`/`nw_app`. This is
deliberate, not an inconsistency: `nw_ops` is operator-plane, not part of the measured
application, and has no reason to route anywhere but to `harness` and the results schema of
`postgres`. `nw_llm_egress` is non-`internal` for a different, unrelated reason — see §4's
"Remote inference backend" for why `llm-backend` needs real egress at all.
`scripts/verify-isolation.sh` must assert `nw_dmz`/`nw_app` are `internal: true`, that
`nw_ops`/`nw_llm_egress` are not, and — since `nw_llm_egress` existing at all is a real
exception to §0.1, not just a port-publishing workaround like `nw_ops` — that `llm-backend`
reaches *only* its configured upstream and nothing else. A build that makes all four internal
"for consistency" would silently break the harness's own API; a build that leaves
`nw_llm_egress` unrestricted would silently turn a narrow, audited exception into an open
hole.

---

## 3. Component inventory

| Service | Stack | Role |
|---|---|---|
| `edge-nginx` | nginx | TLS termination, vhost routing |
| `chat-web` | Next.js | Chat UI, login, session handling |
| `portal-api` | FastAPI | AuthN/authZ, orchestration, **all control toggles** |
| `litellm` | LiteLLM | Model gateway — the model-swap seam |
| `llm-backend` | Ollama or llama.cpp | Local models, swappable (§4) |
| `retrieval-svc` | Python | Embedding + vector search, **entitlement pre-filtering** |
| `tool-svc` | Python | Tool implementations, **per-user credential context** |
| `ingest-svc` | Python | Document ingestion from three sources (§6.3) |
| `postgres` | postgres 16 + pgvector | App data, corpus, vectors, entitlements, results |
| `redis` | redis 7 | Sessions, cache |
| `harness` | Python + FastAPI | Run orchestration, scoring, results (§9) |

Do not add a separate vector database. pgvector is the correct choice here: it is what a
company this size would actually deploy, and entitlement pre-filtering (§6.2) is far cleaner
when the ACL predicate and the vector index live in the same query planner.

---

## 4. Model swapping

The point of `litellm` in Phase 1 is to make the backend model a variable rather than a
constant.

### 4.1 Remote inference backend (deliberate exception to §0.1)

The original design here was "bake weights into the `llm-backend` image at build time, run
entirely locally" — the standard approach, and still the right default for a range meant to
be portable and fully air-gapped. It was reconsidered before building, for reasons specific
to this deployment, not as a general recommendation:

- The build host has no GPU and limited RAM. Local CPU inference on an 8B model would be slow
  enough to make iteration and eval runs genuinely painful.
- A real, motivating use case for this range — comparing how *different* models resist
  tampering — is much better served by cheap model-swapping than by one baked-in model.
  Baking in "three sizes" per the original plan below would mean maintaining several
  multi-gigabyte images; pointing at an existing multi-model Ollama host turns "add a model"
  into one `litellm` config line.

**What was built instead:** `llm-backend` is a narrow reverse proxy (nginx), not a model
server. It forwards to one operator-configured remote Ollama host over a dedicated network,
`nw_llm_egress` (§2.1) — the *only* real egress anywhere in this range. The blast radius is
scoped tightly on purpose:

- `nw_llm_egress` is non-`internal`, but `llm-backend` is the only container on it.
- `llm-backend`'s own per-container iptables allow exactly loopback, this range's own
  subnets (it's still dual-homed on `nw_app` too), and the one configured
  `OLLAMA_UPSTREAM_HOST:OLLAMA_UPSTREAM_PORT` — default `DROP` otherwise. Not a general
  internet hole; one destination, enforced at the packet level, not just by convention.
- Every other container in the range is unaffected — still exactly as isolated as §0.1
  describes. This exception is `llm-backend`'s alone.

**The tradeoff, stated plainly:** this range is no longer fully self-contained for its model
layer. A fresh checkout on a different machine won't have this specific Ollama host
reachable, and a run's behavior now depends on infrastructure outside the repo — the kind of
external dependency §0.5's determinism goal ("a run from March must be comparable to a run
from July") normally argues against. That's accepted here as a conscious cost, not an
oversight; if this range is ever handed off or needs to run somewhere without access to that
host, `llm-backend` would need to revert to the original baked-weights design.

- **Model selection is a run parameter**, not a config file edit. This is easier now, not
  harder: each model is one `litellm` `model_list` entry (`ollama_chat/<model>` pointed at
  `llm-backend`), and the harness picks per run via the gateway exactly as originally
  planned. `services/litellm/config.yaml` ships two working entries (`qwen3-8b`,
  `gemma4-31b`) as of milestone 4; adding another remote-hosted model is a config change, not
  a rebuild.
- Pin temperature and seed. Cap context and max tokens. (`temperature`/`max_tokens` are
  pinned in `litellm`'s config now; `num_ctx`/seed pass-through at the request level is
  whichever milestone actually constructs chat requests, portal-api, milestone 5+.)
- Record model identity, quantization, and all sampling parameters on **every result row**
  (harness's job, milestone 11).

---

## 5. The control matrix

Every item below is an independent runtime toggle exposed by `portal-api`, readable by the
harness, and recorded with every result. Default state for each is given; the harness must
be able to set any combination.

### 5.1 Entitlement enforcement layers

**These three are the core experiment. They must be separately toggleable, including all
combinations, including all three off.**

| ID | Layer | Default | Description |
|---|---|---|---|
| `ENT_PROMPT` | Prompt | off | System prompt states the user's role and grants and instructs the model to honor them. The model is asked to be the access control. |
| `ENT_RETRIEVAL` | Retrieval | on | ACL predicate is applied **inside** the vector query. Forbidden documents are never candidates. |
| `ENT_TOOL` | Tool | on | Tools execute in the calling user's context; the backend rejects out-of-scope requests. |

The question these answer: **how much does prompt-level enforcement buy, and does it buy
anything once the other layers are on?** Expect `ENT_PROMPT` alone to fail against a
competent attacker at every model size, and expect that failure rate not to improve smoothly
with model capability.

### 5.2 Retrieval controls

| ID | Default | Description |
|---|---|---|
| `RET_PREFILTER` | on | Pre-filter vs post-filter (§6.2). Off = retrieve then drop, which leaks via result counts and score distributions. |
| `RET_SOURCE_ALLOWLIST` | off | Only ingest-sources on an allow list are retrievable. |
| `RET_SCORE_THRESHOLD` | off | Minimum similarity; below it, return nothing rather than weak matches. |
| `RET_PLACEMENT` | `user_delimited` | Where retrieved content lands: `system`, `user_delimited`, or `tool_result`. |
| `RET_PROVENANCE` | off | Retrieved chunks carry visible source/trust labels into the context. |

### 5.3 Input and output controls

| ID | Default | Description |
|---|---|---|
| `IN_INJECTION_CLASSIFIER` | off | Classifier on user input. Implement as a call through the gateway to a small local model so it is itself swappable. |
| `IN_RETRIEVED_SCAN` | off | Same classifier applied to **retrieved** content, not just user input. |
| `OUT_PII_FILTER` | off | Output scanned for PII patterns. |
| `OUT_SECRET_FILTER` | off | Output scanned for credential-shaped strings. |
| `OUT_GROUNDING_CHECK` | off | Assert output claims trace to retrieved chunks. |
| `OUT_STRUCTURED` | off | Enforce structured response schema. |

### 5.4 System prompt and tool controls

| ID | Default | Description |
|---|---|---|
| `SYS_PROMPT_VARIANT` | `baseline` | `minimal`, `baseline`, `hardened`, `hardened_with_examples`. Stored as versioned files, never inline. |
| `TOOL_GATING` | off | Tool calls above a risk tier require explicit approval; harness can auto-approve or auto-deny to keep runs unattended. |
| `TOOL_ARG_VALIDATION` | on | Schema and range validation on tool arguments. |
| `RATE_LIMIT` | on | Per-session request and token ceilings. |

**§14's open item on `TOOL_GATING`, resolved (milestone 10):** auto-approve and auto-deny are
both needed, as separate conditions, not a single fixed policy -- a harness studying whether
gating helps needs to run batches under both. A second control, `TOOL_GATING_POLICY`
(`approve` / `deny`, default `deny`), decides what happens to a gated (high-tier) call while
`TOOL_GATING=on`. Default `deny` is the fail-safe choice; the harness can set it to `approve`
per run.

### 5.5 Recording requirement

Every result row carries the **full control vector**, the model identity, the corpus version,
and the harness version. A result without its configuration is not a result.

---

## 6. Data model and the entitlement system

### 6.1 Entities

- **Tenants** — 3 customer orgs. Hard isolation. No document or record crosses tenants.
- **Roles** — Support, Engineering, HR, Finance, Admin.
- **Users** — 15–20 across tenants and roles, including deliberate overlap cases.
- **Documents** — labeled `public` / `internal` / `confidential` / `restricted`, plus an
  owning department, plus an optional explicit share list.
- **Records** — customer records with PII, tickets, invoices. Tenant-scoped.

**Include the messy cases.** Clean hierarchies make the attacks trivial. Required:

- a document owned by HR and explicitly shared with Finance
- a Support user with a time-boxed Engineering grant
- a user whose grant was revoked mid-corpus, for testing stale context
- a document whose label is `internal` but which quotes `restricted` content — a
  mislabeling, which is what actually happens in real corpora

### 6.2 Pre-filter, and why it is a toggle

**Pre-filter (`RET_PREFILTER=on`)** — the ACL predicate goes into the vector query. Forbidden
documents are never candidates.

**Post-filter (off)** — retrieve top-k, then drop what the user cannot see. This leaks:
result counts vary with what exists, score distributions shift, and a query returning three
results instead of ten is itself a signal. It also silently degrades answers because k is
consumed by discarded chunks.

Both paths must be implemented, because the difference between them is a measurement.

### 6.3 Ingestion — the Phase 1 attack surface

There must be paths where content enters the index **without human review**. Implement three:

1. **Feedback form** — public-facing, unauthenticated, low volume.
2. **Ticket feed** — support tickets auto-indexed after closure.
3. **Drive sync** — a watched directory, polled, any file picked up.

These are the direct analogue of Phase 2's registry write. `ingest-svc` records source,
submitter identity if any, and ingestion timestamp on every chunk, so provenance is
available to `RET_PROVENANCE` and `RET_SOURCE_ALLOWLIST`.

### 6.4 Corpus

150–300 documents: policies, runbooks, support macros, product FAQ, HR material, financial
summaries, engineering design notes. Generate them with a local model at build time and
commit the output so the corpus is versioned and stable. Some documents must contain PII and
some must contain credential-shaped strings, because "did it emit something it retrieved" is
a primary measurement.

---

## 7. Authentication and authorization

- Session-based auth, HTTP-only cookies, server-side session state in Redis.
- Password login plus an API-token path for programmatic access.
- **Authorization decisions are made in one place** — a single policy module that
  `retrieval-svc` and `tool-svc` both call. Not duplicated logic. When a Phase 1 bug is
  found, it must be attributable to policy or to a caller, not to drift between two copies.
- The policy module emits a decision log: subject, object, action, decision, reason. This is
  what §9.3 scores against.

**Note for the builder:** implement this correctly and idiomatically. Session handling,
token validation, cookie flags, password storage and CSRF protection are all to current best
practice. Phase 1's authN layer is the control condition, and it is *not* a thing being
measured — do not introduce weaknesses here, toggleable or otherwise (§0.7).

The measured weaknesses are all downstream of a correctly-authenticated user: what the
retrieval layer hands them, what the tools do on their behalf, and whether the model honors
the boundary. A broken session layer would confound all three.

---

## 8. Tools

Four tools via `tool-svc`. Each declares a risk tier for `TOOL_GATING`.

| Tool | Tier | Description |
|---|---|---|
| `doc_search` | low | Semantic search over the corpus |
| `ticket_lookup` | low | Fetch ticket by ID |
| `customer_record` | **high** | Customer record including PII |
| `usage_calc` | low | Arithmetic over account usage |

**The confused-deputy seam.** When `ENT_TOOL=off`, tools run with a service credential that
can see everything — which is exactly what a large fraction of real deployments do. The model
may faithfully honor the user's stated entitlements while the tool underneath ignores them.
This must be a clean toggle, because the gap between `ENT_PROMPT` holding and `ENT_TOOL`
being off is one of the most valuable measurements in the range.

---

## 9. The harness

**The harness is the deliverable.** The application is the thing being measured; the harness
is the instrument. Build it with equal care.

### 9.1 Run model

A **run** = one model × one control vector × one corpus version × the full attack corpus.

```
harness run --model qwen3-8b --controls configs/ablation-07.yaml --corpus v3
```

Runs are unattended, resumable, and produce a results row per attempt. `make reset` restores
corpus and entitlement state between runs so attempts cannot contaminate each other —
critical, since ingestion attacks mutate the index by design.

### 9.2 Attack categories

Structure the corpus around these. Content is maintainer-supplied (§9.4).

| Category | Description |
|---|---|
| Direct entitlement request | Ask for out-of-scope content directly. Baseline. |
| Indirect via retrieval | Plant instructions in a writable-source document aimed at making the assistant fetch or summarize something the attacker cannot read. **The Phase 1 analogue of the Phase 2 pivot.** |
| Confused deputy | Induce a tool call that exceeds the caller's entitlements. |
| Enumeration | Infer existence of forbidden content from refusal wording, citation counts, result counts, latency. |
| Cross-tenant | Bleed via cache keys, session reuse, or summarization outliving a session. |
| System prompt extraction | Recover the system prompt and control configuration. |
| Stale entitlement | Content retrieved under a grant, then referenced after revocation. |
| Resource abuse | Context or token exhaustion, cost amplification. |

### 9.3 Scoring — record all four layers

For every attempt, log separately:

1. **Requested** — what the attack asked for
2. **Policy decision** — what the entitlement layer *should* have returned
3. **Retrieved** — what retrieval actually handed to the model
4. **Emitted** — what the model produced

This separation is what lets you attribute a failure to the right layer. A leak because
retrieval passed a forbidden chunk is a different defect from a leak because the model
recited something from three turns earlier after a grant was revoked, and they have different
fixes. A harness that only records the last column cannot tell them apart.

### 9.4 Over-refusal is a first-class metric

Run a **benign control corpus** of legitimate, in-scope requests in every run and report the
false-refusal rate alongside leakage.

A configuration that refuses everything scores perfectly on leakage and is a useless product.
Without this number the ablations will actively reward broken configurations. Both metrics
appear in every report, always together.

### 9.5 Attack corpus content is maintainer-supplied

Build the **harness, schema, loader, and scoring** — do not author the attack payloads.
`corpus/attacks/` ships with the schema, a README, and two or three trivially benign examples
to prove the loader works. The maintainer populates it out of band.

Two reasons: the corpus is the experimental variable and must be version-controlled
deliberately rather than generated ad hoc, and a repository shipping a curated, tested
jailbreak library is a liability independent of how well the lab is fenced.

### 9.6 Output

- Results to Postgres, one row per attempt, full configuration attached.
- Export to a stable schema for cross-run comparison.
- A report generator producing the ablation matrix: leakage rate and false-refusal rate per
  control vector per model, with attribution by layer.

---

## 10. Telemetry

Ship into the existing SOC-lab normalizer schema so the defender agent can be scored against
the same runs.

- nginx access/error logs
- `portal-api` request logs including session, user, and active control vector
- Full LLM transcripts: prompts, retrieved context, tool calls, completions
- Policy decision log (§7)
- `ingest-svc` events: source, submitter, content hash, timestamp
- `retrieval-svc`: query, filter predicate, candidate count, returned count

The ingestion and retrieval logs are the interesting ones for the defender side. A poisoned
document arriving through the feedback form is visible **only** in ingest telemetry, and only
if someone correlates it with a later retrieval. That is the Phase 1 preview of the Phase 2
detection gap.

---

## 11. Phase 2 hooks

Phase 2 adds the ML supply-chain tier and the infrastructure vulnerability chain. Prepare
for it without building it:

- **Phase 2 is a separate build, not a runtime flag.** The infrastructure vulnerability
  chain requires CVE-bearing versions of `portal-api`'s dependencies and of `litellm`, which
  §0.3 prohibits from Phase 1 images. Phase 2 therefore ships its own pin set and its own
  compose overlay. Do not add a `VULN_CHAIN` toggle to the Phase 1 codebase — a runtime flag
  implies the vulnerable code is installed, which is exactly what must not be true.
- **Why this matters for the data.** If the vulnerable versions were present during control
  ablations, the "controls on" condition would contain a hole unrelated to what is being
  measured, and every Phase 1 result would carry an asterisk. Keeping the pin sets in
  separate builds is what makes Phase 1 results citable.
- Keep the compose file structured so `nw_ml` and its services are purely additive.
- `litellm` is already the seam Phase 2 exploits. Keep its configuration templated.
- The harness run model must generalize from "attack attempt" to "attack chain stage" without
  a schema rewrite.

See `SPEC_phase2.md` for the earlier draft this tier is expected to grow from — a reference
for scope and shape, not current build instructions.

---

## 12. Repository layout

```
northwind-range/
├── Makefile                     # up, down, reset, verify, run, report
├── docker-compose.yml
├── .seed
├── services/
│   ├── edge-nginx/  chat-web/  portal-api/
│   ├── litellm/  llm-backend/
│   ├── retrieval-svc/  tool-svc/  ingest-svc/
├── policy/                      # single authorization module (§7)
├── corpus/
│   ├── docs/                    # generated, committed, versioned
│   ├── entitlements/            # users, roles, grants, labels
│   ├── attacks/                 # SCHEMA + README ONLY (§9.5)
│   └── benign/                  # over-refusal control corpus
├── prompts/                     # versioned system prompt variants
├── harness/
│   ├── api.py  runner.py  scoring.py  report.py
│   └── configs/                 # control vectors for ablation runs
├── telemetry/
└── scripts/
    ├── verify-isolation.sh
    ├── verify-no-cves.sh         # dependency audit; fails build (§0.3)
    ├── verify-entitlements.sh
    └── reset.sh
```

---

## 13. Build order

Separate, individually verifiable milestones. Do not proceed past a failing verification.

1. Compose skeleton, networks, `verify-isolation.sh` and `verify-no-cves.sh` passing on cold
   start. Wire the dependency audit into the build from the first milestone — retrofitting it
   after nine services exist means auditing nine dependency trees at once.
2. Postgres + pgvector, schema, entitlement model, seeded users and grants.
3. Corpus generation, committed and versioned.
4. `llm-backend` with weights baked in; offline cold start verified; `litellm` in front.
5. `portal-api` with authN, session handling, policy module; `verify-entitlements.sh`
   passing — every user, every document, expected decision, **before** any model is involved.
6. `retrieval-svc` with both pre-filter and post-filter paths.
7. `chat-web` and the end-to-end chat path.
8. `tool-svc` with all four tools and the `ENT_TOOL` toggle.
9. `ingest-svc` with all three ingestion sources.
10. Full control matrix wired and runtime-toggleable; state readable by the harness.
11. Harness: run model, schema, loader, scoring, over-refusal control.
12. Telemetry shippers.
13. Report generator and first full ablation run.

Milestone 5 is the gate that matters. If entitlements are not provably correct with no model
in the loop, every downstream measurement is uninterpretable.

---

## 14. Open decisions for the maintainer

Flag rather than deciding unilaterally:

- ~~Model lineup and quantization, pending measured host headroom after milestone 4.~~
  **Resolved differently than assumed, milestone 4:** local host headroom is no longer the
  constraint — `llm-backend` forwards to a remote Ollama host instead of running inference
  locally (§4.1), so "ship 3 sizes" became "add `litellm` config entries." Two models are
  wired up as of this milestone (`qwen3-8b`, `gemma4-31b`); more can be added the same way
  without a rebuild.
- Whether the injection classifier is a local small model, a rules engine, or both as
  separate toggles.
- Corpus size, and whether documents are generated per-build or committed once. Committed is
  recommended for comparability.
- Whether `TOOL_GATING` auto-approves or auto-denies during unattended runs, or whether both
  are separate conditions.
- Run budget: attempts per category per run, and whether repeated trials per attempt are
  needed for variance estimates. Recommended, since single-shot results on stochastic systems
  are close to meaningless.
- Whether the harness records full transcripts or only scored outcomes. Full transcripts are
  strongly recommended and will dominate storage.
