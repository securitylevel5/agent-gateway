# Agent Instructions

## Project Overview

This repository contains `agent_gateway`, a Rust 2024 mTLS HTTP/2 CONNECT proxy. It authorizes tunnel requests from custom X.509 client certificate extensions against a PostgreSQL-backed signed permission registry, then proxies raw TCP bytes to approved destinations.

Key paths:

- `src/main.rs` starts the gateway binary and wires configuration, policy, TLS, proxying, and observability together.
- `src/lib.rs` exposes the library modules used by tests and the binary.
- `src/config.rs`, `src/tls.rs`, `src/policy.rs`, `src/registry.rs`, `src/proxy.rs`, and `src/observability.rs` hold the main implementation.
- `migrations/0001_signed_authorization_registry.sql` defines the authorization registry schema.
- `tests/integration.rs`, `tests/e2e.rs`, and `tests/common/mod.rs` cover policy behavior, TLS material, database registry setup, and proxy flows.

## Planning Larger Changes

When writing complex features or significant refactors, use an ExecPlan (as described in `.agent/PLANS.md`) from design to implementation.

Keep ExecPlans current while working. Record decisions, discoveries, progress, validation evidence, and any change in direction in the plan before relying on that context later.

## Build and Test Commands

Use the repository root as the working directory for all commands below.

- Format Rust code with `cargo fmt`.
- Run static checks with `cargo clippy --locked --all-targets`. The project denies `clippy::pedantic`, so address warnings instead of suppressing them unless there is a narrow, documented reason.
- Run the full test suite with `cargo test --locked`.
- For a release build, use `cargo build --release`.

The CI test job also checks SQLx query metadata:

```bash
SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx database setup
SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx prepare --check -- --all-targets --locked
```

Run the SQLx check when changing migrations, SQL query text, or registry/policy code that relies on checked SQLx macros.

## Test Suite Notes

Most tests are ordinary Rust tests run by `cargo test --locked`, but database-backed policy and end-to-end tests require `TEST_DATABASE_URL` to point at a writable PostgreSQL database. The test process applies migrations and writes test data, so use a disposable test database.

The GitHub Actions workflow uses Postgres 16 with:

```text
TEST_DATABASE_URL=postgres://agent_gateway_admin:agent_gateway_dev@localhost:5432/agent_gateway_test
```

The tests cover destination normalization, config validation, TLS PKI generation, request parsing, signed permission verification, signer delegation scope enforcement, and database-backed authorization behavior. When changing authorization semantics, add or update tests close to the affected behavior rather than relying only on broad e2e coverage.

## SQLx and Migrations

Checked SQLx query macros compile against committed metadata in normal builds. If you change migration SQL or SQL query text, regenerate or check the metadata using `sqlx-cli` version `0.8.6`, matching the README and CI workflow.

Do not treat SQLx metadata as a replacement for migrations. Schema changes belong in `migrations/`, with tests updated to prove the migrated database supports the intended behavior.

## Commit Discipline

Make regular git commits while working, especially before and after risky changes. Each commit should represent one logical change: for example, keep a behavior change separate from formatting, dependency updates, SQLx metadata refreshes, or test-only follow-ups.

For all Codex-initiated commits, include a co-author trailer:

```text
Co-authored-by: Codex <codex@openai.com>
```

Before committing, review `git diff --stat` and `git diff` to ensure the commit only contains the intended files. Do not revert unrelated user changes in a dirty working tree.

## Implementation Guidelines

Prefer the existing module boundaries and patterns. Keep authorization and registry logic explicit and well tested, because small changes can affect security-sensitive decisions about which client identities may connect to which destinations.

Preserve locked dependency behavior by using `--locked` for checks where practical. Avoid introducing new dependencies unless they clearly reduce complexity or match an established project need.

Update `README.md`, `config.example.toml`, migrations, or tests whenever a code change alters user-visible behavior, configuration, database requirements, or operational expectations.
