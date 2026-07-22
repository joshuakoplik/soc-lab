#!/bin/sh
set -e

IFACE="${SURICATA_IFACE:-soclab0}"
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

# --- 4. Wait for the bridge, then run ---------------------------------------
for i in $(seq 1 30); do
  if ip link show "$IFACE" >/dev/null 2>&1; then break; fi
  echo "[suricata] waiting for interface $IFACE ($i)..."
  sleep 1
done

echo "[suricata] starting on $IFACE"
exec suricata -c "$MERGED" -i "$IFACE"
