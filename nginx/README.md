# nginx -- reverse proxy, and the thing that turns traffic into telemetry

Juice Shop is never published directly. All web traffic goes through nginx,
because nginx is what writes the access log that `pipeline/ingest.py` tails.
Bypass it and the request happened, but the SOC never saw it.

## The log format is a contract

`nginx.conf` defines a `json_ecs` log format writing to
`/var/log/nginx/access.json`. Its field names are not cosmetic — they line up
with the column set `pipeline/normalize.py` maps every source into, and they
are split along the same trust boundary the rest of the pipeline depends on:

- infrastructure-asserted, observed by nginx itself: `source_ip`,
  `source_port`, `status`, `bytes_sent`, `request_time`
- attacker-controlled, merely transported: `url_path`, `url_query`,
  `user_agent`, `referer`, `request_body`

Changing a field name here means changing `normalize.py` too. A plain
`combined` access log is written alongside it for humans.

## Decoys

`decoys-easy/credentials.txt` is served in `easy` mode and leaks exactly the
credentials `cowrie/userdb.txt` accepts — the intended recon-before-brute-force
path. `decoys-hard/` is empty (just a `.gitkeep`): in `hard` mode there is no
leaked credential to find, which is most of what makes it hard.
