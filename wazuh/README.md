# wazuh -- SIEM

Emits alerts that `pipeline/ingest.py` tails as the `wazuh` source. It also
reads the `wordpress` target's Apache access/error logs directly (see
`ossec.conf`), because that target has no reverse proxy in front of it the way
Juice Shop has nginx — without this, wordpress-mode traffic would generate no
telemetry at all.

## local_rules.xml

Wazuh ships roughly 3000 rules and **none** of them are for Cowrie: it isn't
sshd, and it emits its own JSON taxonomy. What rescues us is that it emits
JSON at all — Wazuh's built-in JSON decoder turns every key into a queryable
field, so this file contains rules only, no decoder XML. Field names come
straight from `cowrie.json`: `eventid`, `username`, `password`, `src_ip`,
`input`, `session`.

## The trap that will cost you an afternoon

`<field>` defaults to **OS_Regex**, a deliberately minimal engine with no
grouping parens, no `?` quantifier, and no character classes. PCRE habits do
not error — they fail to *parse*, `analysisd` then refuses to load the entire
file, and every rule in it dies together, not just the offending one. So every
field here declares `type="pcre2"` explicitly. Slower per event, irrelevant at
lab volume, and it means the regex means what it looks like.

Custom rule IDs live in the reserved `100000+` range. Never reuse a shipped SID.
