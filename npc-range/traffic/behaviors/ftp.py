"""Benign FTP traffic against an ftp-vsftpd NPC (curl ftp://, directory list)."""
import subprocess

USER, PASS = "svc-transfer", "changeit"   # matches a typical seeded account


def run(hostname, rng):
    # A plain directory listing; occasionally an anonymous attempt (benign
    # failure). vsftpd logs both, which the fleet tailer ships to Wazuh.
    if rng.random() < 0.3:
        url, cred = f"ftp://{hostname}/", []
    else:
        url, cred = f"ftp://{hostname}/", ["-u", f"{USER}:{PASS}"]
    subprocess.run(["curl", "-s", "-o", "/dev/null", "--max-time", "8"] + cred + [url],
                   capture_output=True, timeout=15)
