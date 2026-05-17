-- Adds the byte-budget fields signed in v2 of the permission canonical bytes.
-- The CHECK constraints guarantee non-negative values, which lets the gateway
-- safely cast Postgres BIGINT (i64) to Rust u64 at the rate-limit boundary.
ALTER TABLE permission_registry
    ADD COLUMN capacity_bytes BIGINT NOT NULL CHECK (capacity_bytes >= 0),
    ADD COLUMN refill_bytes_per_sec BIGINT NOT NULL CHECK (refill_bytes_per_sec >= 0);

INSERT INTO agent_gateway_schema_version (version) VALUES (2);
