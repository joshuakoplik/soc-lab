# dealer-range: ephemeral, docker-based vulnerable targets sourced from Vulhub.
#
# Driven by ../lab-mode.sh (`up|down|switch dealer <target>`), which sets
# DEALER_TARGET and bootstraps the soclab-dealer network first. Mirrors
# northwind-range/Makefile's "self-contained lifecycle, lab-mode.sh only ever
# shells out via make -C" pattern -- the repo root never references these
# containers directly. Everything the range stands up lives in the
# `dealer-range` compose project and is torn down by `make down`.
SHELL := /bin/bash
VULHUB_REPO ?= https://github.com/vulhub/vulhub.git
CACHE   := .cache/vulhub
PROJECT := dealer-range
COMPOSE := .run/compose.yml

-include .env

.PHONY: up down reset refresh cache net wait wire purge

# Shallow clone of the Vulhub repo -- the only "connect to the source" step, so
# a given <software>/<CVE> path resolves to files. Picking WHICH target is the
# operator's/assistant's job at invocation, not this code's.
cache:
	@if [ ! -d "$(CACHE)/.git" ]; then \
	  echo "[dealer] cloning Vulhub (shallow) into $(CACHE) ..."; \
	  git clone --depth 1 "$(VULHUB_REPO)" "$(CACHE)"; \
	else echo "[dealer] Vulhub cache present ($(CACHE))"; fi

# Make sure soclab-dealer (internal bridge) exists. lab-mode.sh already runs
# this, but `make up` should be self-sufficient too.
net:
	@python3 ../pipeline/net_topology.py --bootstrap >/dev/null

up: cache net
	@[ -n "$(DEALER_TARGET)" ] || { echo "[dealer] set DEALER_TARGET (e.g. struts2/CVE-2017-5638)"; exit 1; }
	python3 up.py "$(DEALER_TARGET)"
	@PROJECT_DIR=$$(cat .run/project_dir); \
	  echo "[dealer] bringing target up on $(PROJECT) ..."; \
	  docker compose -f "$(COMPOSE)" --project-directory "$$PROJECT_DIR" -p "$(PROJECT)" up -d --build --remove-orphans
	@$(MAKE) --no-print-directory wait
	@$(MAKE) --no-print-directory wire

wait:
	@echo "[dealer] waiting for the target to come up ..."; \
	  PROJECT_DIR=$$(cat .run/project_dir); \
	  for i in $$(seq 1 30); do \
	    n=$$(docker compose -f "$(COMPOSE)" --project-directory "$$PROJECT_DIR" -p "$(PROJECT)" ps --status running -q | wc -l); \
	    [ "$$n" -gt 0 ] && { echo "[dealer] target running ($$n service(s))."; exit 0; }; \
	    sleep 2; \
	  done; \
	  echo "[dealer] WARNING: nothing came up running -- the image may be broken; pick another target." >&2

# Wire the (now-running) target into the defender: restart Suricata if it isn't
# already sniffing soclab-dealer0, then gather facts + one LLM turn to tail the
# target's logs into logs/dealer/ (picked up by wazuh's permanent dealer
# buckets). Best-effort by design -- never fail `up` over a wiring hiccup; the
# deterministic baseline inside wire.py keeps the defender from going blind.
# Uses the venv python if present (provider stack), else python3.
wire:
	@PY=python3; [ -x ../.venv/bin/python3 ] && PY=../.venv/bin/python3; \
	  "$$PY" wire.py || echo "[dealer] WARNING: wiring step reported a problem (see above)." >&2

# down -v: containers AND volumes go, then wipe .run -- "like it was never
# there". The soclab-dealer bridge persists (it's a net_topology network, torn
# down by nobody, same as the other three). First kill the host-side log tailers
# wire.py spawned and clear the dealer log buckets, so no orphaned `docker
# logs -f` survives and the next target starts from empty files.
down:
	@python3 wire.py --teardown 2>/dev/null || true
	@if [ -f "$(COMPOSE)" ]; then \
	  PROJECT_DIR=$$(cat .run/project_dir 2>/dev/null || echo .); \
	  docker compose -f "$(COMPOSE)" --project-directory "$$PROJECT_DIR" -p "$(PROJECT)" down -v 2>/dev/null || true; \
	fi
	@rm -rf .run
	@echo "[dealer] target torn down; tailers killed, logs/dealer cleared, .run removed"

# Re-provision the CURRENT target (from state.json) or a new DEALER_TARGET.
reset:
	@t="$${DEALER_TARGET:-$$(python3 -c "import json;print(json.load(open('.run/state.json'))['target'])" 2>/dev/null)}"; \
	  [ -n "$$t" ] || { echo "[dealer] nothing to reset -- set DEALER_TARGET"; exit 1; }; \
	  $(MAKE) --no-print-directory down; \
	  DEALER_TARGET="$$t" $(MAKE) --no-print-directory up

refresh: cache
	git -C "$(CACHE)" pull --ff-only

# Full cleanup: tear down + drop the Vulhub cache. (Pulled base images are left;
# `docker image prune` manually if you want the disk back.)
purge: down
	rm -rf "$(CACHE)"
	@echo "[dealer] cache removed."
