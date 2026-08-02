PY := $(shell [ -x .venv/bin/python3 ] && echo .venv/bin/python3 || echo python3)

.PHONY: up down reset seed verify

up:
	docker compose up -d --build --wait

down:
	docker compose down

# SPEC.md §0.4: fresh randomized secrets, no manual steps -- down -v wipes
# the postgres volume so services/postgres/init/*.sql re-runs on next up,
# then seed reloads entitlement data (deriving fresh passwords if .seed
# was also deleted; stable passwords otherwise, see seed_entitlements.py).
reset:
	docker compose down -v
	docker compose up -d --build --wait
	$(MAKE) seed

seed:
	$(PY) scripts/seed_entitlements.py

verify:
	./scripts/verify-isolation.sh
	./scripts/verify-no-cves.sh
	./scripts/verify-schema.sh
