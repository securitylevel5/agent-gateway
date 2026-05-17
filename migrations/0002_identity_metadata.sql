CREATE TABLE identity_metadata (
    subject_identity TEXT PRIMARY KEY,
    rate_limit_bytes_per_second BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (subject_identity <> ''),
    CHECK (
        rate_limit_bytes_per_second IS NULL
        OR rate_limit_bytes_per_second > 0
    )
);

INSERT INTO agent_gateway_schema_version (version) VALUES (2);
