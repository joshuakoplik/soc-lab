#!/usr/bin/env python3
"""Workstation traffic driver.

Reads the flock manifest (bind-mounted at /manifest.json), finds this client's
entry by CLIENT_HOSTNAME, and generates a continuous, low-rate stream of normal
traffic against the flock's NPCs. Each client is its own container (its own IP),
so the defender sees source-IP diversity, not one chatty host.

Pacing is deliberately gentle -- a few actions/min, exponential inter-arrival,
weighted toward "working hours" -- so benign traffic does NOT flood the
deterministic detectors (pipeline/detect/rules.py). Web traffic here reaches the
pipeline as source=wazuh (via the tailer), so it structurally cannot trip the
nginx-source http_rate_anomaly rule; we still keep the rate realistic.

Behaviors live in behaviors/<name>.py, each exposing run(target_hostname, rng).
Unknown behaviors are skipped, so the driver tolerates a richer library than it
has modules for.
"""
import datetime
import importlib
import json
import os
import random
import sys
import time

MANIFEST = os.environ.get("NPC_MANIFEST", "/manifest.json")
CLIENT = os.environ.get("CLIENT_HOSTNAME", "")
# A few actions per minute on average.
BASE_INTERVAL_S = float(os.environ.get("NPC_BASE_INTERVAL", "12"))


def load_entry():
    with open(MANIFEST) as f:
        manifest = json.load(f)
    hosts = {h["hostname"]: h for h in manifest.get("hosts", [])}
    for c in manifest.get("clients", []):
        if c["hostname"] == CLIENT:
            return c, hosts
    # Fall back to the first client entry if the env didn't match (compose scale
    # can rename); still produces plausible traffic.
    clients = manifest.get("clients", [])
    if clients:
        return clients[0], hosts
    return None, hosts


def working_hours_weight(rng):
    """0.15..1.0 multiplier on cadence by UTC hour -- busier in the day."""
    hour = datetime.datetime.utcnow().hour
    if 8 <= hour < 18:
        return 1.0
    if 6 <= hour < 8 or 18 <= hour < 22:
        return 0.5
    return 0.2


def pick_behavior(behaviors, rng):
    return rng.choice(behaviors) if behaviors else None


def main():
    entry, hosts = load_entry()
    if not entry:
        print("[driver] no client entry in manifest; idling", file=sys.stderr, flush=True)
        while True:
            time.sleep(3600)

    rng = random.Random(hash(CLIENT) & 0xffffffff)
    # Map each target hostname to the behaviors its type supports.
    targets = []
    for hostname in entry.get("targets", []):
        h = hosts.get(hostname)
        if not h:
            continue
        for b in _behaviors_for(h):
            targets.append((hostname, b))
    if not targets:
        print("[driver] no actionable targets; idling", file=sys.stderr, flush=True)
        while True:
            time.sleep(3600)

    print(f"[driver] {CLIENT}: {len(targets)} target/behavior pairs", file=sys.stderr, flush=True)
    loaded = {}
    while True:
        hostname, behavior = rng.choice(targets)
        mod = loaded.get(behavior)
        if mod is None:
            try:
                mod = importlib.import_module(f"behaviors.{behavior}")
            except Exception as e:
                print(f"[driver] no behavior {behavior!r}: {e}", file=sys.stderr, flush=True)
                mod = False
            loaded[behavior] = mod
        if mod:
            try:
                mod.run(hostname, rng)
            except Exception as e:
                print(f"[driver] {behavior} on {hostname} failed: {e}", file=sys.stderr, flush=True)
        # Exponential inter-arrival, scaled by hour-of-day.
        wait = rng.expovariate(1.0 / BASE_INTERVAL_S) / working_hours_weight(rng)
        time.sleep(min(max(wait, 1.0), 120.0))


def _behaviors_for(host):
    # host record carries per-target behaviors when the manifest was written by
    # a newer npcctl; else fall back to the type's client behaviors embedded in
    # the target list. Keep it defensive.
    return host.get("client_behaviors") or _DEFAULT_BEHAVIORS.get(host.get("type"), [])


_DEFAULT_BEHAVIORS = {
    "webserver-nginx": ["browse"],
    "webserver-apache": ["browse"],
    "intranet-app": ["browse"],
    "api-svc": ["browse"],
    "db-postgres": ["psql"],
    "db-mysql": ["mysql"],
    "cache-redis": ["redis"],
}


if __name__ == "__main__":
    main()
