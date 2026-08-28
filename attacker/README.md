# Attacker container

Kali, multi-homed onto every mode's own network at once (soclab-easy,
soclab-hard, soclab-wordpress -- see pipeline/net_topology.py), not one
shared `soclab` bridge anymore. Every packet it sends carries a real
container IP on whichever mode's segment it's talking on (e.g.
10.211.10.x for easy, 10.211.20.x for hard), so sensors attribute the
attack to one true source per mode -- which is what makes `same_field`
and cross-source correlation actually work. Attacking from the host
instead masquerades everything to a bridge gateway and the correlation
is meaningless.

## First run

```bash
docker compose up -d attacker
```

The full attack toolkit (nmap, hydra, sqlmap, metasploit-framework,
curl, python3, ...) is baked into the image at build time now (see
attacker/Dockerfile) -- no separate provisioning step needed for that.
`provision.sh` still runs (idempotent, also at the top of each attack
script) but only starts msfdb/postgres, which isn't persisted across a
recreate and does need restarting every time.

## Run attacks

```bash
docker exec -it soc-attacker /scripts/attack-web.sh      # sqlmap + discovery vs Juice Shop
docker exec -it soc-attacker /scripts/attack-cowrie.sh   # hydra brute -> shell vs Cowrie
docker exec -it soc-attacker /scripts/attack-all.sh      # both, one IP, correlatable
```

Then on the host, turn telemetry into candidates:

```bash
python3 pipeline/ingest.py && python3 pipeline/rules.py --all
```

## Interactive

```bash
docker exec -it soc-attacker bash
# msfconsole, nmap, sqlmap, hydra all on PATH; targets are cowrie:2222 and nginx:80
```

## What each attack should light up

| Attack | Suricata | Wazuh | pipeline |
|---|---|---|---|
| hydra SSH brute | flow/scan sigs | 100110/111/113 | ssh candidate |
| post-login cmds  | (encrypted)    | 100121/122/123/124 | — |
| sqlmap / SQLi    | ET WebServer sigs | 31100-series | ids + wazuh candidates |
| content discovery| scan sigs      | web 404 rules | http_rate |
| full run (all)   | all of the above | all | **cross_source_activity, 4 sources** |

## Loot

`attacker/loot/` is bind-mounted, so nmap/hydra/sqlmap output lands on the host.

## Egress lockdown

soc-attacker's outbound traffic is locked to loopback + every lab subnet
(one ACCEPT rule per pipeline/net_topology.py entry -- 10.211.10.0/24,
10.211.20.0/24, 10.211.30.0/24 as of this writing) via `iptables` rules
applied *inside this container's own network namespace* -- not the
host's, and not persisted anywhere (not a compose volume, not baked into
the image). shell_exec (pipeline/redteam/agent.py) has no target
allowlist at all; this lockdown is its only containment. See CLAUDE.md:
**don't treat shell_exec as safe against an attacker container that
hasn't had this reapplied.**

(A structural alternative -- making the lab networks themselves
`internal: true`, so no per-container lockdown is needed at all -- was
tried during the 2026-08 network refactor and reverted: it also silently
disables Docker's own host port publishing for every container on the
network, breaking nginx's published ports elsewhere in this lab. So this
stays a per-container iptables rule, same approach as before that
refactor, just covering three subnets now instead of one.)

That means it does NOT survive `docker compose up --force-recreate attacker`
(or any rebuild) -- confirmed live 2026-07-28, recreating the container came
back with a wide-open OUTPUT chain. **`./reset.sh --attacker` does all of
this for you** (rebuild, provision, reapply the lockdown across every
subnet, verify) -- this is the manual equivalent if you need to do it by
hand:

```bash
docker exec soc-attacker iptables -F OUTPUT
docker exec soc-attacker iptables -A OUTPUT -o lo -j ACCEPT
while read -r subnet; do
  docker exec soc-attacker iptables -A OUTPUT -d "$subnet" -j ACCEPT
done < <(python3 pipeline/net_topology.py --subnets)
docker exec soc-attacker iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
docker exec soc-attacker iptables -A OUTPUT -j DROP
```

Verify before trusting it:

```bash
docker exec soc-attacker iptables -S OUTPUT                                        # rules present, one ACCEPT per subnet
docker exec soc-attacker curl -m5 -s -o /dev/null -w '%{http_code}\n' http://1.1.1.1/     # should be 000 (blocked)
docker exec soc-attacker curl -s -o /dev/null -w '%{http_code}\n' http://nginx.soclab-easy/  # should 200, if easy mode is up
```

### Deliberately opening real egress (bounded experiments only)

`pipeline/redteam/agent.py` has a `REDTEAM_UNRESTRICTED_EGRESS=1` flag
that changes the model's *prompt* to say it has real internet access --
it does not touch the network itself. To actually grant that access for
a bounded, deliberate experiment, punch a temporary hole outside this
codebase rather than editing the lockdown loop above:

```bash
docker exec soc-attacker iptables -I OUTPUT 1 -j ACCEPT   # before the default DROP
# ... run the experiment, REDTEAM_UNRESTRICTED_EGRESS=1 ...
./reset.sh --attacker                                     # rebuilds + relocks cleanly afterward
```
