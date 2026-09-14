# npc-range: libraries of benign "NPC" services spun up as flocks for noise and
# distraction. Self-contained lifecycle -- the repo root only ever drives this
# via `make -C npc-range` (lab-mode.sh status). Mirrors dealer-range/ and
# northwind-range/. All real logic is in npcctl.py; these are thin wrappers so
# the `make -C` convention works and so a venv python (for PyYAML) is selected.
SHELL := /bin/bash

# Prefer the repo venv (PyYAML lives there, like northwind-range); fall back to
# system python3.
PY := $(shell if [ -x ../.venv/bin/python3 ]; then echo ../.venv/bin/python3; else echo python3; fi)

# Operator-supplied on the command line, e.g.
#   make -C npc-range up TEMPLATE=corp-intranet NETWORK=easy
#   make -C npc-range down FLOCK=corp-intranet-1a2b
#   make -C npc-range traffic-start FLOCK=corp-intranet-1a2b
TEMPLATE ?=
NETWORK  ?=
FLOCK    ?=
CLIENTS  ?=
FLAGS    ?=

.PHONY: types templates up down status traffic-start traffic-stop pull flags reconcile build

types:
	@$(PY) npcctl.py types

templates:
	@$(PY) npcctl.py templates

up:
	@[ -n "$(TEMPLATE)" ] || { echo "set TEMPLATE=<name> (see: make -C npc-range templates)"; exit 1; }
	@$(PY) npcctl.py up "$(TEMPLATE)" \
	  $(if $(NETWORK),--network "$(NETWORK)") \
	  $(if $(CLIENTS),--clients "$(CLIENTS)") \
	  $(if $(FLAGS),--flags "$(FLAGS)")

down:
	@[ -n "$(FLOCK)" ] || { echo "set FLOCK=<name> (or: make -C npc-range down-all)"; exit 1; }
	@$(PY) npcctl.py down "$(FLOCK)"

down-all:
	@$(PY) npcctl.py down --all

status:
	@$(PY) npcctl.py status

reconcile:
	@$(PY) npcctl.py reconcile

flags:
	@[ -n "$(FLOCK)" ] || { echo "set FLOCK=<name>"; exit 1; }
	@$(PY) npcctl.py flags "$(FLOCK)"

traffic-start:
	@[ -n "$(FLOCK)" ] || { echo "set FLOCK=<name>"; exit 1; }
	@$(PY) npcctl.py traffic start "$(FLOCK)"

traffic-stop:
	@[ -n "$(FLOCK)" ] || { echo "set FLOCK=<name>"; exit 1; }
	@$(PY) npcctl.py traffic stop "$(FLOCK)"

# Refresh every library image to its current stable tag ("fully patched").
pull:
	@$(PY) npcctl.py pull

# Build the custom images (intranet-app, api-svc, the traffic client).
build:
	@$(PY) npcctl.py build
