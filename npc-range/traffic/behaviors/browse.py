"""Benign web browsing against an HTTP NPC.

Mostly 200s on real paths, with occasional benign misses (a stale bookmark, a
favicon request) that produce the 404s a real intranet sees all day. Never
aggressive -- one request per call.
"""
import subprocess

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:129.0) Gecko/20100101 Firefox/129.0",
]

GOOD_PATHS = ["/", "/", "/", "/docs/", "/directory/", "/support/", "/health"]
MISS_PATHS = ["/favicon.ico", "/old-wiki/", "/index.php", "/.well-known/security.txt"]


def run(hostname, rng):
    if rng.random() < 0.10:
        path = rng.choice(MISS_PATHS)     # benign 404 noise
    else:
        path = rng.choice(GOOD_PATHS)
    ua = rng.choice(USER_AGENTS)
    subprocess.run(
        ["curl", "-s", "-o", "/dev/null", "-A", ua, "--max-time", "8",
         f"http://{hostname}{path}"],
        capture_output=True, timeout=15)
