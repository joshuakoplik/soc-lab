"""Benign object-store traffic against an objstore-minio NPC.

The traffic image doesn't ship the minio client, so this just exercises the S3
HTTP endpoint with curl -- a list/HEAD against the API returns an auth error but
still produces the recurring connection pattern a real app/backup job would.
"""
import subprocess


def run(hostname, rng):
    path = rng.choice(["/", "/backups/", "/artifacts/", "/minio/health/live"])
    subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "--max-time", "8", f"http://{hostname}:9000{path}"],
        capture_output=True, timeout=15)
