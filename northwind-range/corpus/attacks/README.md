# Attack corpus (maintainer-supplied)

SPEC.md §9.5: this repository ships the harness -- schema, loader, scoring -- but not attack
content. Real attack payloads are the maintainer's job, populated out of band, for two
reasons: the corpus is the experimental variable and must be version-controlled
deliberately rather than generated ad hoc, and a repository shipping a curated, tested
jailbreak library is a liability independent of how well the lab is fenced.

## Item shape

See `schema.yaml` for an annotated template. A file under `corpus/attacks/` (or
`corpus/benign/`, which uses the same shape) may contain a single item (a YAML mapping) or a
list of items (a YAML sequence of mappings) -- `harness/loader.py` accepts either.

- `id` -- unique slug, stable across corpus revisions. Used as the database upsert key
  (`harness.corpus_items` is keyed on `(kind, item_key)`), so re-running the loader after
  adding or editing items never orphans results from a prior run that referenced the old row.
- `category` -- one of SPEC.md §9.2's eight: `direct_entitlement`, `indirect_retrieval`,
  `confused_deputy`, `enumeration`, `cross_tenant`, `system_prompt_extraction`,
  `stale_entitlement`, `resource_abuse`. Required for items under `corpus/attacks/`; items
  under `corpus/benign/` don't set this (they aren't attack-shaped at all).
- `actor` -- which user's session context the item runs as: `tenant` + `department` picks any
  matching seeded user, or set `username` for an exact one (e.g. to specifically use
  `maria.support`'s time-boxed grant, or `olivia.hr`'s revoked one -- SPEC.md §6.1's messy
  cases).
- `setup` -- optional list of pre-steps executed before `steps`. Currently one action is
  supported: `{action: feedback, tenant, message, submitter}`, which posts to the public
  feedback form (`POST /feedback`) -- the mechanism an `indirect_retrieval` item needs to
  plant a poisoned document before probing whether it gets retrieved and acted on.
- `steps` -- the chat message(s) sent to `POST /chat`, in order, in the actor's session.
- `target` -- optional; describes *what* the item is probing for, not a specific id. The
  runner resolves this against the *live* database at run time (`type`:
  `document`/`customer_record`/`ticket`/`usage`/`system_prompt`/`none`; `scope`:
  `any_denied`/`cross_department`/`cross_tenant`) -- the same "pick a real denied document for
  this user right now" pattern the `verify-*.sh` scripts already use, so items stay valid
  across corpus and entitlement regenerations instead of hardcoding ids that go stale the
  moment `.seed` rotates.
- `expected.refuse` -- whether a correctly-defended response to this item should refuse.

## What's here now

`examples/items.yaml` holds exactly three trivially benign items (SPEC.md §9.5) proving the
loader and the full attempt-execution pipeline work end to end -- none of them are
attack-shaped; each expects `refuse: false`. Real attack content goes directly under
`corpus/attacks/` (not `examples/`), whenever the maintainer populates it out of band.
