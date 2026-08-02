# Entitlement fixtures

Tenants, departments, users, and grants for SPEC.md's entitlement model
(§6.1/§7). Committed and versioned like the real corpus, not `.seed`-random
-- passwords are the only thing derived from `.seed` (see
`scripts/seed_entitlements.py`).

## Carried forward to milestone 3 (corpus generation)

SPEC.md §6.1 requires two more messy cases that can't be seeded here since
`app.documents` is intentionally empty until milestone 3:

- **A document owned by HR and explicitly shared with Finance** -- give it
  `label='internal'` (or stricter) and an `app.document_shares` row for the
  Finance department alongside its HR `owning_department_id`.
- **A document labeled `internal` that quotes `restricted` content** -- a
  deliberate mislabeling, per SPEC.md §6.1's own framing of what actually
  happens in real corpora.

Both should belong to whichever tenant milestone 3 finds most natural (no
requirement that it be a specific one of the three).
