#!/bin/sh
set -e

BASE=/etc/suricata/suricata.yaml
OVER=/overrides.yaml
MERGED=/tmp/suricata-merged.yaml
RULES_DIR=/var/lib/suricata/rules

# --- 1. Build the real config -----------------------------------------------
# Suricata takes ONE config file; it does not merge. So we merge ourselves:
# shipped config as the base, overrides.yaml on top. python3 + PyYAML are
# already in the image because suricata-update depends on them.
if ! python3 -c "import yaml" 2>/dev/null; then
  echo "[suricata] FATAL: python3+PyYAML missing from image; cannot merge config."
  exit 1
fi

echo "[suricata] merging /overrides.yaml onto shipped $BASE"
python3 - "$BASE" "$OVER" "$MERGED" <<'PYEOF'
import sys, yaml

def merge(base, over):
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = merge(base[k], v) if k in base else v
        return out
    # Suricata expresses outputs and eve types as lists of single-key dicts.
    # Merge those by key so tweaking eve-log doesn't delete fast.log or stats.
    if isinstance(base, list) and isinstance(over, list):
        if base and over and all(isinstance(x, dict) and len(x) == 1 for x in base + over):
            over_by_key = {list(x)[0]: x for x in over}
            out = []
            for item in base:
                k = list(item)[0]
                if k in over_by_key:
                    out.append({k: merge(item[k], over_by_key.pop(k)[k])})
                else:
                    out.append(item)
            out.extend(over_by_key.values())
            return out
        return over          # mixed-shape list: overrides win wholesale
    return over

base_p, over_p, out_p = sys.argv[1], sys.argv[2], sys.argv[3]
with open(base_p) as f:
    base = yaml.safe_load(f)
with open(over_p) as f:
    over = yaml.safe_load(f) or {}
merged = merge(base, over)
with open(out_p, "w") as f:
    f.write("%YAML 1.1\n---\n")
    yaml.safe_dump(merged, f, default_flow_style=False, sort_keys=False)
print("[suricata] merged config -> " + out_p)
PYEOF

# --- 2. Rules ---------------------------------------------------------------
if [ ! -f "$RULES_DIR/suricata.rules" ]; then
  echo "[suricata] no ruleset yet - fetching ET Open (first run only)..."
  suricata-update --no-test --reload-command '' || {
    echo "[suricata] ruleset fetch FAILED - check container internet access."
    echo "[suricata] continuing so the sensor still starts."
  }
else
  echo "[suricata] ruleset present ($(wc -l < "$RULES_DIR/suricata.rules") lines)"
fi

# --- 3. Validate before running ---------------------------------------------
# -T is test mode: parse the config, load every rule, exit. Turns "thousands of
# errors scrolling past at runtime" into one clear pass/fail up front.
echo "[suricata] validating config + ruleset (-T)..."
suricata -T -c "$MERGED" -v 2>&1 | grep -E "error|Error|ERROR|successfully|Configuration provided" | tail -8 || true

# --- 4. Discover every lab bridge, then run ---------------------------------
# One interface per mode network now (soclab-easy0, soclab-hard0,
# soclab-wp0, ... -- see pipeline/net_topology.py), not the single fixed
# "soclab0" this used to wait for. Self-discovery off the naming
# convention means a future mode needs zero changes here: multiple -i
# flags in one Suricata invocation is its own documented mechanism for
# multi-interface af-packet capture, not something this script has to
# implement itself. SURICATA_IFACES (plural, space-separated) is kept as
# an explicit operator override for debugging -- SURICATA_IFACE
# (singular) is gone along with the single-bridge assumption it implied.
discover_ifaces() {
  ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^soclab-[a-z]+0$' | sort
}

for i in $(seq 1 30); do
  [ -n "$(discover_ifaces)" ] && break
  echo "[suricata] waiting for a soclab-*0 bridge to exist ($i)..."
  sleep 1
done

IFACES="${SURICATA_IFACES:-$(discover_ifaces)}"
if [ -z "$IFACES" ]; then
  echo "[suricata] FATAL: no soclab-*0 bridge interfaces found -- has"
  echo "[suricata] pipeline/net_topology.py --bootstrap run yet? (setup.sh / lab-mode.sh do this)"
  exit 1
fi

IFACE_ARGS=""
IFACE_LIST=""
for i in $IFACES; do
  IFACE_ARGS="$IFACE_ARGS -i $i"
  IFACE_LIST="$IFACE_LIST $i"
done

echo "[suricata] starting on:$IFACE_LIST"
# shellcheck disable=SC2086
exec suricata -c "$MERGED" $IFACE_ARGS
