-- SPEC.md §13 build order step 6. Deferred from milestone 2 (no embedding
-- model chosen yet at that point) -- embeddinggemma:latest is 768-dim, see
-- services/retrieval-svc/embeddings.py.
ALTER TABLE app.documents ADD COLUMN embedding vector(768);

-- HNSW is pgvector's current recommended default for cosine distance.
-- Not load-bearing at 180 rows, but correct practice and free to add now.
CREATE INDEX documents_embedding_idx ON app.documents USING hnsw (embedding vector_cosine_ops);
