#!/usr/bin/env bash
# Bring lab modes up and down. Since each mode now lives on its own network
# (see pipeline/net_topology.py) instead of one shared bridge, modes can
# coexist -- this is no longer just a "switch to X" toggle.
#
#   ./lab-mode.sh bootstrap        -- idempotent: create the 3 per-mode networks if missing.
#                                      Every verb below runs this first on its own; call it
#                                      directly only if you want the networks up with nothing
#                                      else changed.
#   ./lab-mode.sh up <mode>        -- bring that mode's target containers up. Other modes'
#                                      containers, if any are running, are left alone. Also
#                                      sets lab_mode.json's PRIMARY mode -- the one
#                                      pipeline/redteam/lab_modes.py gates tool access against.
#   ./lab-mode.sh down <mode>      -- tear that mode's target containers down. Other modes
#                                      untouched. Warns loudly (doesn't refuse) if you tear
#                                      down the current primary mode -- lab_mode.json still
#                                      points at it, so the red-team agent's target allowlist
#                                      would be pointing at nothing running until you `up`
#                                      something else.
#   ./lab-mode.sh switch <mode>    -- down every OTHER mode, then up <mode> -- today's old
#                                      mutually-exclusive behavior, kept as a convenience.
#   ./lab-mode.sh easy|hard|wordpress|northwind
#                                   -- bare aliases for `switch <mode>`, for backward
#                                      compatibility with existing muscle memory/docs.
#   ./lab-mode.sh status           -- lab_mode.json's primary mode, plus live docker state
#                                      for ALL four modes (not just the primary one).
#
# modes: easy (cowrie + metasploitable + juiceshop-easy + nginx-easy, planted creds),
#        hard (juiceshop-hard + nginx-hard, hardened + network-locked, no leaked creds),
#        wordpress (real WordPress core pinned to CVE-2026-63030/CVE-2026-60137 -- see
#                   wordpress/README.md, a single-target scenario, not a difficulty rung),
#        northwind (a vulnerable AI application rather than a vulnerable service -- see
#                   northwind-range/SPEC.md and REDTEAM_MODE_SPEC.md).
#
# northwind is the odd one out mechanically, and this script hides that rather than
# pretending it isn't true. The other three are profiles in this repo's own compose.yaml
# on net_topology.py subnets; northwind is a SEPARATE docker-compose project under
# northwind-range/ with its own Makefile, its own networks, and its own .env. So every
# verb below delegates northwind to that Makefile instead of reimplementing it -- one
# definition of how the range comes up, not two that can drift. `bootstrap` still means
# only the three net_topology networks, because northwind's compose creates its own.
#
# Writes lab_mode.json (gitignored), which pipeline/redteam/lab_modes.py reads so the
# red-team agent's target/tool config always matches whichever mode is PRIMARY -- there's
# no separate flag to remember to pass, and no way for the agent to drift out of sync with
# that. lab_mode.json only ever names ONE primary mode even when multiple are physically
# running -- the agent still targets exactly one mode's targets per campaign; coexistence is
# about the underlying INFRASTRUCTURE not being mutually exclusive anymore, not about a
# single campaign attacking multiple modes at once (a separate, bigger feature this doesn't
# attempt).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PY="${PYTHON:-python3}"
if [ -x .venv/bin/python3 ]; then
  PY=".venv/bin/python3"
fi

STATE_FILE="lab_mode.json"
VERB="${1:-status}"
MODE="${2:-}"
# Third positional, used only by `dealer` mode: the Vulhub target to stand up
# (e.g. "struts2/CVE-2017-5638", or a plain docker image ref). Every other mode
# ignores it.
TARGET="${3:-}"

# Merge ONE key into lab_mode.json, preserving every other key -- so setting the
# mode never clobbers the posture (a second, orthogonal axis) and vice versa.
# Always refreshes switched_at. Replaces the old whole-file printf, which wiped
# any key it didn't itself write.
_state_set() {
  "$PY" - "$STATE_FILE" "$1" "$2" <<'PY'
import json, sys, datetime
path, key, val = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    d = json.load(open(path))
    if not isinstance(d, dict):
        d = {}
except Exception:
    d = {}
d[key] = val
d["switched_at"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
with open(path, "w") as f:
    json.dump(d, f)
    f.write("\n")
PY
}

write_state() { _state_set mode "$1"; }

current_mode() {
  if [ -f "$STATE_FILE" ]; then
    "$PY" -c "import json; print(json.load(open('$STATE_FILE')).get('mode','unknown'))" 2>/dev/null || echo unknown
  else
    echo "(none set -- lab_mode.json has never been written)"
  fi
}

# Attacker posture -- a second axis, orthogonal to the vuln mode (see
# PERIMETER_PLAN.md). Default "insider" preserves today's behavior until the
# perimeter build lands and someone explicitly switches to "remote".
current_posture() {
  if [ -f "$STATE_FILE" ]; then
    "$PY" -c "import json; print(json.load(open('$STATE_FILE')).get('posture','insider'))" 2>/dev/null || echo insider
  else
    echo insider
  fi
}

# The docker networks soc-attacker is currently attached to (space-padded so
# `case` membership tests are unambiguous).
_attacker_nets() {
  echo " $(docker inspect -f '{{range $n,$c := .NetworkSettings.Networks}}{{$n}} {{end}}' soc-attacker 2>/dev/null) "
}

# Place soc-attacker according to the posture (PERIMETER_PLAN.md, validated in the
# PR-2 spike). insider: multi-homed on every inside bridge (the compose default),
# off soclab-inet. remote: on soclab-inet ONLY, so it reaches inside hosts solely
# through the perimeter firewall. Idempotent (connect/disconnect only when the
# state actually needs to change); a no-op with a clear note if soc-attacker isn't
# running yet -- the placement is (re)asserted on the next `up`/`switch`. Requires
# soclab-inet to exist, so callers bootstrap first.
rehome_attacker() {
  local posture="$1"
  if ! docker inspect soc-attacker >/dev/null 2>&1; then
    echo "[posture] soc-attacker not running -- placement will apply on next 'up'/'switch'"
    return 0
  fi
  local cur inside_names
  cur="$(_attacker_nets)"
  inside_names="$("$PY" pipeline/net_topology.py --names | grep -vx soclab-inet)"
  if [ "$posture" = "remote" ]; then
    # Self-sufficient about the segment existing, so this is safe even from the
    # northwind path (which skips the normal bootstrap).
    docker network inspect soclab-inet >/dev/null 2>&1 || "$PY" pipeline/net_topology.py --bootstrap >/dev/null
    case "$cur" in *" soclab-inet "*) : ;; *) docker network connect soclab-inet soc-attacker && echo "[posture] soc-attacker -> soclab-inet" ;; esac
    for n in $inside_names; do
      case "$cur" in *" $n "*) docker network disconnect "$n" soc-attacker && echo "[posture] soc-attacker off $n" ;; esac
    done
  else  # insider (default)
    case "$cur" in *" soclab-inet "*) docker network disconnect soclab-inet soc-attacker && echo "[posture] soc-attacker off soclab-inet" ;; esac
    for n in $inside_names; do
      case "$cur" in *" $n "*) : ;; *) docker network connect "$n" soc-attacker && echo "[posture] soc-attacker -> $n" ;; esac
    done
  fi
}

# Install (remote) or tear down (insider) the perimeter firewall rules for a mode
# via pipeline/firewall/perimeter.py. Rules only exist under posture=remote; under
# insider the perimeter is cleared so the attacker's LAN-adjacency is unfenced.
perimeter_sync() {
  local mode="$1" posture="$2"
  if [ "$posture" = "remote" ]; then
    "$PY" pipeline/firewall/perimeter.py apply "$mode" >/dev/null && echo "[perimeter] rules applied for $mode (posture=remote)"
  else
    "$PY" pipeline/firewall/perimeter.py clear >/dev/null && echo "[perimeter] rules cleared (posture=insider)"
  fi
}

bootstrap() {
  "$PY" pipeline/net_topology.py --bootstrap
}

# Always reached via `make -C` or an explicit `-f`/--project-directory, never a bare
# `docker compose` from this script's cwd: with a compose project nested inside another
# one, a stale working directory aims the command at the wrong stack, and `down` is not
# a mistake you want to make twice.
NORTHWIND_DIR="northwind-range"

# The "dealer's choice" range -- like northwind, a separate concern with its own
# Makefile that this script only ever shells out to via `make -C`. UNLIKE
# northwind, it DOES live on a net_topology subnet (soclab-dealer), so it IS
# bootstrapped normally. Its Makefile takes the chosen target from $DEALER_TARGET.
DEALER_DIR="dealer-range"

# northwind's containers can start without this and then fail confusingly deep in a
# chat request, so fail here instead, where the cause is still obvious.
northwind_precheck() {
  if [ ! -f "$NORTHWIND_DIR/.env" ]; then
    echo "[!] $NORTHWIND_DIR/.env does not exist. Copy $NORTHWIND_DIR/.env.example to it" >&2
    echo "    and set NW_OLLAMA_UPSTREAM_HOST -- the range is air-gapped apart from that" >&2
    echo "    one allow-listed inference host, and it must be a raw IP (no DNS resolver)." >&2
    exit 1
  fi
  if ! grep -qE '^[[:space:]]*NW_OLLAMA_UPSTREAM_HOST=[^[:space:]]' "$NORTHWIND_DIR/.env"; then
    echo "[!] NW_OLLAMA_UPSTREAM_HOST is empty or unset in $NORTHWIND_DIR/.env. The range" >&2
    echo "    has no inference backend to forward to, so chat would fail. Set it to a raw IP." >&2
    exit 1
  fi
}

mode_up() {
  case "$1" in
    easy)
      docker compose --profile easy up -d cowrie metasploitable juiceshop-easy nginx-easy
      ;;
    hard)
      docker compose --profile hard up -d juiceshop-hard nginx-hard juiceshop-netlock
      ;;
    wordpress)
      docker compose --profile wordpress up -d wordpress-db wordpress wordpress-init wordpress-netlock
      ;;
    northwind)
      northwind_precheck
      make -C "$NORTHWIND_DIR" up
      ;;
    dealer)
      # $2 is the Vulhub target (required); the range's Makefile reads it from
      # DEALER_TARGET, resolves it to a compose, rewrites it onto soclab-dealer,
      # and brings it up contained.
      [ -n "${2:-}" ] || { echo "usage: $0 up dealer <vulhub-target>   (e.g. struts2/CVE-2017-5638)" >&2; exit 1; }
      DEALER_TARGET="$2" make -C "$DEALER_DIR" up
      ;;
    *)
      echo "usage: $0 up {easy|hard|wordpress|northwind|dealer}" >&2
      exit 1
      ;;
  esac
}

mode_down() {
  case "$1" in
    easy)
      docker compose --profile easy rm -sf cowrie metasploitable juiceshop-easy nginx-easy
      ;;
    hard)
      docker compose --profile hard rm -sf juiceshop-hard nginx-hard juiceshop-netlock
      ;;
    wordpress)
      docker compose --profile wordpress rm -sf wordpress wordpress-init wordpress-netlock wordpress-db
      ;;
    northwind)
      # `make down` is `docker compose down` -- containers and networks go, the postgres
      # volume stays. Same semantics as the rm -sf above: `down` is not a data reset.
      # Use `make -C northwind-range reset` for that.
      make -C "$NORTHWIND_DIR" down
      ;;
    dealer)
      # down -v inside the Makefile -- the ephemeral target and its volumes go,
      # so switching away leaves nothing behind. No-op if the range isn't up.
      make -C "$DEALER_DIR" down 2>/dev/null || true
      ;;
    *)
      echo "usage: $0 down {easy|hard|wordpress|northwind|dealer}" >&2
      exit 1
      ;;
  esac
}

case "$VERB" in
  bootstrap)
    bootstrap
    echo "[*] all per-mode networks exist (soclab-easy/hard/wordpress + soclab-dealer[internal])"
    echo "[*] northwind is not included -- its own compose project creates its own networks"
    ;;
  up)
    [ -n "$MODE" ] || { echo "usage: $0 up {easy|hard|wordpress|northwind|dealer} [dealer-target]" >&2; exit 1; }
    # northwind sits on none of the net_topology subnets, so bootstrapping them for it
    # would create networks it will never touch. Every other mode (dealer included)
    # uses a net_topology bridge, so bootstrap runs.
    [ "$MODE" = "northwind" ] || bootstrap
    echo "[*] bringing $MODE mode up (other modes, if running, are left alone)"
    # Record the selected mode BEFORE the (possibly slow) bring-up, not after.
    # mode_up for northwind is `docker compose up -d --build --wait`, which can
    # block on healthchecks for minutes; a caller that kills mode_up on a
    # timeout (e.g. labctl's subprocess timeout from the dashboard) would
    # otherwise leave lab_mode.json stale while the detached (`-d`) containers
    # keep coming up on their own -- and an attacker launched afterward reads
    # the OLD mode. Mode selection is operator intent and is recorded
    # immediately; readiness is a separate axis that `status`/docker report.
    write_state "$MODE"
    mode_up "$MODE" "$TARGET"
    rehome_attacker "$(current_posture)"
    perimeter_sync "$MODE" "$(current_posture)"
    echo "[*] $MODE mode up; lab_mode.json primary mode set to $MODE"
    if [ "$MODE" = "northwind" ]; then
      echo "[*] if this range has never been seeded, its corpus/entitlements/records are"
      echo "    empty until you run: make -C $NORTHWIND_DIR reset"
    fi
    ;;
  down)
    [ -n "$MODE" ] || { echo "usage: $0 down {easy|hard|wordpress|northwind}" >&2; exit 1; }
    echo "[*] tearing $MODE mode down (other modes, if running, are left alone)"
    mode_down "$MODE"
    # The mode's targets are gone; drop any perimeter rules that published them.
    if [ "$(current_mode)" = "$MODE" ]; then
      perimeter_sync "" insider
    fi
    if [ "$(current_mode)" = "$MODE" ]; then
      echo "[!] $MODE was the PRIMARY mode -- lab_mode.json still points at it, so the" >&2
      echo "    red-team agent's target allowlist now points at nothing running. Run" >&2
      echo "    '$0 up <mode>' to set a new primary before starting a campaign." >&2
    fi
    echo "[*] $MODE mode down"
    ;;
  switch)
    [ -n "$MODE" ] || { echo "usage: $0 switch {easy|hard|wordpress|northwind|dealer} [dealer-target]" >&2; exit 1; }
    [ "$MODE" = "northwind" ] || bootstrap
    echo "[*] switching to $MODE mode (tearing down every other mode first)"
    for other in easy hard wordpress northwind dealer; do
      [ "$other" = "$MODE" ] && continue
      mode_down "$other" 2>/dev/null || true
    done
    # Record the selected mode BEFORE the bring-up (same reasoning as the `up`
    # branch above): mode_up can be slow enough to be killed on a timeout,
    # which would leave lab_mode.json pointing at the mode we just tore down.
    write_state "$MODE"
    mode_up "$MODE" "$TARGET"
    rehome_attacker "$(current_posture)"
    perimeter_sync "$MODE" "$(current_posture)"
    echo "[*] $MODE mode active (exclusively)"
    ;;
  easy|hard|wordpress|northwind|dealer)
    # Bare mode name: back-compat alias for `switch <mode>`. Passes $MODE through
    # as the switch target arg so bare `dealer <vulhub-target>` still works
    # (VERB=dealer, MODE=<target> -> `switch dealer <target>`).
    exec "$0" switch "$VERB" "$MODE"
    ;;
  posture)
    # Set (or, with no arg, report) the attacker posture. Orthogonal to the vuln
    # mode: does NOT bring anything up or down, only records the axis in
    # lab_mode.json. The perimeter topology reacts to it once that build lands;
    # until then it is recorded and read (lab_modes.active_config()) but inert.
    case "$MODE" in
      remote|insider)
        _state_set posture "$MODE"
        echo "[*] attacker posture set to '$MODE' (orthogonal to the vuln mode)"
        rehome_attacker "$MODE"
        perimeter_sync "$(current_mode)" "$MODE"
        ;;
      "")
        echo "current attacker posture: $(current_posture)"
        ;;
      *)
        echo "usage: $0 posture {remote|insider}" >&2
        exit 1
        ;;
    esac
    ;;
  status)
    echo "primary mode: $(current_mode)"
    echo "attacker posture: $(current_posture)"
    echo
    docker compose --profile easy --profile hard --profile wordpress ps --format "table {{.Name}}\t{{.Status}}"
    echo
    echo "-- northwind (separate compose project: $NORTHWIND_DIR/) --"
    # -f plus --project-directory rather than a cd, so this reads the nested project
    # explicitly and can never be aimed at the outer stack by an inherited cwd.
    docker compose -f "$NORTHWIND_DIR/docker-compose.yml" --project-directory "$NORTHWIND_DIR" \
      ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null \
      || echo "(northwind range not up, or $NORTHWIND_DIR/.env missing)"
    echo
    echo "-- dealer (separate compose project: $DEALER_DIR/) --"
    if [ -f "$DEALER_DIR/.run/compose.yml" ]; then
      docker compose -f "$DEALER_DIR/.run/compose.yml" --project-directory "$DEALER_DIR" \
        ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || true
      echo "current dealer target(s): $("$PY" -c "import json,sys; d=json.load(open('$DEALER_DIR/.run/state.json')); items=d if isinstance(d,list) else [d]; print(', '.join(t.get('target','?') for t in items))" 2>/dev/null || echo '?')"
    else
      echo "(dealer range not up)"
    fi
    echo
    # NPC flocks are an independent range (npc-range/), never started/stopped by
    # lab-mode -- only reported here. Managed with `make -C npc-range ...` /
    # npc-range/npcctl.py.
    echo "-- npc flocks (separate range: npc-range/) --"
    make -C npc-range status 2>/dev/null || echo "(no flocks up)"
    ;;
  *)
    echo "usage: $0 {bootstrap|up|down|switch|status|posture|easy|hard|wordpress|northwind|dealer} [mode|remote|insider] [dealer-target]" >&2
    exit 1
    ;;
esac
