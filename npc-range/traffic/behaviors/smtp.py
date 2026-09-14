"""Benign SMTP traffic against a mail-postfix NPC (swaks, stop after RCPT)."""
import subprocess

SENDERS = ["reports@corp.internal", "noreply@corp.internal", "hr@corp.internal"]
RCPTS = ["dana.ellsworth@corp.internal", "marcus.vint@corp.internal", "team@corp.internal"]


def run(hostname, rng):
    # --quit-after RCPT keeps it a lightweight, well-formed conversation (no
    # actual message body relayed); realistic connection + envelope traffic.
    subprocess.run(
        ["swaks", "--server", hostname, "--from", rng.choice(SENDERS),
         "--to", rng.choice(RCPTS), "--quit-after", "RCPT", "--timeout", "10"],
        capture_output=True, timeout=20)
