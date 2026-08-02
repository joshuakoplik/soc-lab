.PHONY: up down reset verify

up:
	docker compose up -d --build

down:
	docker compose down

# Milestone 1: no seed/corpus/entitlement state exists yet, so "known-good
# state" is just a clean rebuild. Milestone 2+ extends this to also
# regenerate .seed and reload corpus/entitlements per SPEC.md §0.4.
reset:
	docker compose down -v
	docker compose up -d --build

verify:
	./scripts/verify-isolation.sh
	./scripts/verify-no-cves.sh
