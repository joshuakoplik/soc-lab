"""Benign LDAP searches/binds against an ldap-openldap NPC (ldapsearch)."""
import subprocess

BASE = "dc=corp,dc=internal"
FILTERS = ["(objectClass=person)", "(uid=alice)", "(cn=*)"]


def run(hostname, rng):
    if rng.random() < 0.4:
        # anonymous search
        argv = ["ldapsearch", "-x", "-H", f"ldap://{hostname}", "-b", BASE,
                "-o", "nettimeout=8", rng.choice(FILTERS), "dn"]
    else:
        # authenticated bind
        argv = ["ldapsearch", "-x", "-H", f"ldap://{hostname}",
                "-D", "cn=admin," + BASE, "-w", "changeit1", "-b", BASE,
                "-o", "nettimeout=8", rng.choice(FILTERS), "dn"]
    subprocess.run(argv, capture_output=True, timeout=15)
