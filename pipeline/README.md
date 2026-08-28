# pipeline -- the deterministic tier, and both agents

Everything host-side and Python. Two tiers live here, and the split between
them is the point: a reproducible layer that never involves a model, and an
LLM layer built on top of it that is studied precisely because it isn't
reproducible.

```
ingest.py          tail cowrie/nginx/suricata/wazuh -> normalize -> soc.db
normalize.py       each source's native JSON -> one shared, trust-labeled column set
schema.sql         the events table, grouped by trust rather than by type
llm_view.py        the redacted event view the agents actually see
net_topology.py    per-mode subnets; the single source of truth for lab CIDRs
detect/rules.py    pure deterministic functions: events -> candidates
triage/            blue team: agent, its tools, and the iptables block enforcer
redteam/           offense: agent, executor, gating, per-mode configs
providers/         vendor-neutral Provider interface (claude/local/gmi/fireworks)
```

## The one convention everything rests on

`schema.sql` groups columns **by trust, not by type**:

- **infrastructure-asserted** (`ts`, `source`, `event_type`, `src_ip`) —
  observed by a sensor, not forgeable by the attacker
- **attacker-controlled** (`username`, `password`, `command`, `url_path`,
  `user_agent`, `request_body`) — free text a hostile party wrote and the
  pipeline merely transported
- **IDS/SIEM-asserted** (`ids_*`, `siem_*`) — the rule *firing* is trustworthy;
  the payload that tripped it is still hostile text

`normalize.ATTACKER_CONTROLLED` names exactly that middle group and is imported
anywhere the boundary has to be re-asserted — most importantly in
`triage/agent.py`, which fences everything derived from those columns inside
`<untrusted-evidence>` tags, structurally separated from instruction text.

**When you touch code that moves data from an attacker-controlled column into a
prompt, a tool result, or a log line a human will read, that is the first
question to ask, not an afterthought.**

`ingest.py` reads new bytes since a per-file `(inode, offset)` tail state and
handles rotation. It never silently drops a line: anything unparseable goes to
`parse_failures` rather than vanishing, because a gap in a SOC feed is
indistinguishable from an attacker cleaning up after themselves.

## Tool gating

Every tool touching real infrastructure gets one of exactly three postures —
ungated-but-logged, human-gated via a `pending_actions`-style table, or
whitelist-scoped auto-execute. Adding a fourth ad-hoc pattern is the thing to
avoid. The module docstrings at the top of `triage/agent.py` and
`redteam/agent.py` are the canonical spec; read them before changing gating.

Note that some older docstrings in this tree still reference pre-restructure
paths (`pipeline/rules.py`, `pipeline/agent.py`, `harness/*`). Trust the actual
file layout over those comments.
