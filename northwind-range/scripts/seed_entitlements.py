#!/usr/bin/env python3
"""Load corpus/entitlements/*.yaml into Postgres (SPEC.md §13 milestone 2).

Passwords are derived from .seed rather than stored in the committed
fixtures (SPEC.md §0.4/§0.5: fresh randomized secrets, reproducible for a
given seed). Password hashing happens in Postgres itself via pgcrypto's
crypt()/gen_salt('bf') -- real bcrypt -- since neither bcrypt nor passlib
is available on the host and nw_app has no host-published port for a
host-side DB connection anyway (internal: true; only `docker compose exec`
reaches it).
"""
import base64
import hashlib
import hmac
import json
import secrets
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEED_FILE = ROOT / ".seed"
CREDS_FILE = ROOT / ".seed-credentials.json"
ENTITLEMENTS_DIR = ROOT / "corpus" / "entitlements"


def get_or_create_seed() -> str:
    if SEED_FILE.exists():
        return SEED_FILE.read_text().strip()
    value = secrets.token_hex(32)
    SEED_FILE.write_text(value + "\n")
    return value


def derive_password(seed: str, username: str) -> str:
    digest = hmac.new(seed.encode(), username.encode(), hashlib.sha256).digest()
    return base64.b32encode(digest).decode().rstrip("=").lower()[:20]


def sql_str(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def sql_ts_or_null(value: str | None) -> str:
    return f"{sql_str(value)}::timestamptz" if value else "NULL"


def load_fixtures() -> dict:
    fixtures = {}
    for name in ("tenants", "departments", "users", "grants"):
        with open(ENTITLEMENTS_DIR / f"{name}.yaml") as f:
            fixtures[name] = yaml.safe_load(f)[name]
    usernames = [u["username"] for u in fixtures["users"]]
    if len(usernames) != len(set(usernames)):
        sys.exit("seed_entitlements: duplicate username in users.yaml -- must be globally unique")
    return fixtures


def build_sql(fixtures: dict, seed: str) -> tuple[str, dict]:
    lines = [
        "BEGIN;",
        "TRUNCATE app.grants, app.users, app.document_shares, app.documents, "
        "app.departments, app.tenants RESTART IDENTITY CASCADE;",
    ]

    for t in fixtures["tenants"]:
        lines.append(
            f"INSERT INTO app.tenants (slug, name) VALUES ({sql_str(t['slug'])}, {sql_str(t['name'])});"
        )

    for d in fixtures["departments"]:
        lines.append(f"INSERT INTO app.departments (name) VALUES ({sql_str(d)});")

    credentials = {}
    for u in fixtures["users"]:
        password = derive_password(seed, u["username"])
        credentials[u["username"]] = password
        lines.append(
            "INSERT INTO app.users (tenant_id, department_id, username, password_hash, display_name) "
            f"SELECT t.id, d.id, {sql_str(u['username'])}, crypt({sql_str(password)}, gen_salt('bf')), "
            f"{sql_str(u['display_name'])} "
            f"FROM app.tenants t, app.departments d "
            f"WHERE t.slug = {sql_str(u['tenant'])} AND d.name = {sql_str(u['department'])};"
        )

    for g in fixtures["grants"]:
        lines.append(
            "INSERT INTO app.grants (user_id, department_id, granted_at, expires_at, revoked_at) "
            f"SELECT u.id, d.id, {sql_ts_or_null(g.get('granted_at'))}, "
            f"{sql_ts_or_null(g.get('expires_at'))}, {sql_ts_or_null(g.get('revoked_at'))} "
            f"FROM app.users u, app.departments d "
            f"WHERE u.username = {sql_str(g['username'])} AND d.name = {sql_str(g['department'])};"
        )

    lines.append("COMMIT;")
    return "\n".join(lines), credentials


def main() -> None:
    seed = get_or_create_seed()
    fixtures = load_fixtures()
    sql, credentials = build_sql(fixtures, seed)

    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-v", "ON_ERROR_STOP=1",
         "-U", "northwind", "-d", "northwind"],
        input=sql, capture_output=True, text=True, cwd=str(ROOT),
    )
    if result.returncode != 0:
        sys.exit(f"seed_entitlements: psql failed:\n{result.stdout}\n{result.stderr}")

    CREDS_FILE.write_text(json.dumps(credentials, indent=2, sort_keys=True) + "\n")
    CREDS_FILE.chmod(0o600)
    print(f"Seeded {len(fixtures['tenants'])} tenants, {len(fixtures['departments'])} departments, "
          f"{len(fixtures['users'])} users, {len(fixtures['grants'])} grants.")
    print(f"Plaintext credentials written to {CREDS_FILE}")


if __name__ == "__main__":
    main()
