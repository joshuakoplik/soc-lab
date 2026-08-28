# suricata -- network IDS

Watches the lab bridges and writes EVE JSON. `pipeline/ingest.py` reads
**only `alert` records** from that stream — the flow/http/dns records are far
higher volume and are not what the detection tier is asking about.

## Why there is an entrypoint script

Suricata takes exactly **one** config file; it does not merge fragments. To
avoid vendoring a full copy of the shipped `suricata.yaml` (which then silently
rots against the image), `entrypoint.sh` merges `overrides.yaml` on top of the
image's own config at start-up with a small PyYAML deep-merge, and fails loudly
if PyYAML is missing rather than starting with a half-applied config.

## overrides.yaml

Mostly `HOME_NET`, which has to cover the lab's per-mode subnets
(`10.211.0.0/16`, plus `10.210.0.0/24` and `172.16.0.0/12`) or every rule
written in terms of "inbound to the network we protect" fails to match and the
IDS goes quiet without erroring. `HTTP_PORTS`/`SSH_PORTS` are widened to the
lab's non-standard ports (3000, 8080, 2222) for the same reason. A handful of
ICS protocol parsers are enabled to give the ruleset more to say.
