"""Benign Redis cache operations against a cache-redis NPC.

Simulates an app using the cache: a GET (cache read), a SET with a short TTL
(cache fill), an INCR (a counter). One op per call.
"""
import subprocess

KEYS = ["session:active", "app:page_views", "cache:dashboard", "rate:login"]


def run(hostname, rng):
    op = rng.choice(["get", "set", "incr"])
    key = rng.choice(KEYS)
    if op == "get":
        argv = ["redis-cli", "-h", hostname, "GET", key]
    elif op == "set":
        argv = ["redis-cli", "-h", hostname, "SET", key, str(rng.randint(1, 9999)), "EX", "300"]
    else:
        argv = ["redis-cli", "-h", hostname, "INCR", key]
    subprocess.run(argv, capture_output=True, timeout=15)
