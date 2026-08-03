PY := $(shell [ -x .venv/bin/python3 ] && echo .venv/bin/python3 || echo python3)

.PHONY: up down reset seed load-corpus embed-corpus verify

up:
	docker compose up -d --build --wait

down:
	docker compose down

# SPEC.md §0.4: fresh randomized secrets, no manual steps -- down -v wipes
# the postgres volume so services/postgres/init/*.sql re-runs on next up,
# then seed/load-corpus/embed-corpus reload entitlement + document data
# (deriving fresh passwords if .seed was also deleted; stable passwords
# otherwise, see seed_entitlements.py). load-corpus reads the committed
# corpus/docs/**/*.md files -- it does not regenerate them (see
# scripts/generate_corpus.py). embed-corpus must run after load-corpus,
# since that truncates app.documents and wipes any prior embeddings.
reset:
	docker compose down -v
	docker compose up -d --build --wait
	$(MAKE) seed
	$(MAKE) load-corpus
	$(MAKE) embed-corpus

seed:
	$(PY) scripts/seed_entitlements.py

load-corpus:
	$(PY) scripts/load_corpus.py

embed-corpus:
	docker compose exec -T retrieval-svc python3 backfill_embeddings.py

verify:
	./scripts/verify-isolation.sh
	./scripts/verify-no-cves.sh
	./scripts/verify-schema.sh
	./scripts/verify-corpus.sh
	./scripts/verify-llm-backend.sh
	./scripts/verify-entitlements.sh
	./scripts/verify-retrieval.sh
