"""Benign DNS lookups against a dns-bind NPC (dig)."""
import subprocess

NAMES = ["corp.internal", "mail.corp.internal", "www.example.com",
         "intranet.corp.internal", "github.com"]
TYPES = ["A", "A", "A", "MX", "TXT"]


def run(hostname, rng):
    subprocess.run(
        ["dig", f"@{hostname}", "+time=5", "+tries=1", rng.choice(NAMES), rng.choice(TYPES)],
        capture_output=True, timeout=12)
