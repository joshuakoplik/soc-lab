"""Benign IMAP logins against an imap-dovecot NPC (curl imap://)."""
import subprocess

USERS = [("alice", "changeit1"), ("bob", "changeit2"), ("carol", "changeit3")]


def run(hostname, rng):
    user, pw = rng.choice(USERS)
    if rng.random() < 0.05:
        pw = "wrongpass"     # occasional benign auth failure
    subprocess.run(
        ["curl", "-s", "--max-time", "10", "--url", f"imap://{hostname}/INBOX",
         "-u", f"{user}:{pw}", "--request", "EXAMINE INBOX"],
        capture_output=True, timeout=15)
