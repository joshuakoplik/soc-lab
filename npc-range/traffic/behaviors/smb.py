"""Benign SMB traffic against a fileshare-samba NPC (smbclient list)."""
import subprocess

USER, PASS = "svc-finance", "Sh4reMe!"


def run(hostname, rng):
    if rng.random() < 0.3:
        # anonymous share enumeration
        argv = ["smbclient", "-N", "-L", f"//{hostname}", "-t", "8"]
    else:
        argv = ["smbclient", f"//{hostname}/finance", "-U", f"{USER}%{PASS}",
                "-t", "8", "-c", "ls"]
    subprocess.run(argv, capture_output=True, timeout=15)
