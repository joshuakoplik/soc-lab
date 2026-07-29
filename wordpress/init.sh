#!/bin/sh
# One-shot installer for the wordpress target. Runs `wp core install` and seeds
# a second author + a few posts so WP_Query has more than a single row to
# enumerate against, then exits. wordpress:cli-* is wp-cli talking to the
# shared /var/www/html volume and the DB directly (no HTTP round trip to the
# wordpress container), so this doesn't need the apache container reachable
# over the network -- only the shared volume and the DB.
set -eu

until [ -f /var/www/html/wp-load.php ]; do
  echo "[wordpress-init] waiting for WordPress core files..."
  sleep 2
done

if wp core is-installed --path=/var/www/html --allow-root; then
  echo "[wordpress-init] already installed"
else
  # No separate DB-readiness probe: wp-cli's own `wp db check` shells out to
  # mariadb-check, whose default client behavior demands TLS this DB doesn't
  # offer -- an unrelated client-default mismatch, not a signal about
  # whether the DB is actually reachable. `wp core install` talks to the DB
  # through wp-config.php's normal (non-TLS-enforcing) mysqli connection, so
  # just retry the install itself until it succeeds.
  until wp core install \
    --path=/var/www/html \
    --allow-root \
    --url="$WP_SITE_URL" \
    --title="$WP_SITE_TITLE" \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL" \
    --skip-email; do
    echo "[wordpress-init] install failed (DB probably not ready yet), retrying..."
    sleep 3
  done
  echo "[wordpress-init] core installed"
fi

wp user create editor editor@wordpress.lab --role=editor \
  --user_pass="$WP_ADMIN_PASSWORD" --path=/var/www/html --allow-root || true
wp post generate --count=5 --path=/var/www/html --allow-root || true

echo "[wordpress-init] target ready"
