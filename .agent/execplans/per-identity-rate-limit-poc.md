# Add Per-Identity Proxied-Data Rate Limits

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

This plan follows `.agent/PLANS.md` from the repository root. The implementation must not begin until the user has reviewed and approved this plan.


## Purpose / Big Picture

The gateway currently authorizes whether an identity may open a CONNECT tunnel to a destination, but once a tunnel is established there is no per-identity data-volume throttling. After this proof of concept, an operator can store an optional bytes-per-second limit for a source identity in the authorization registry. When that identity opens one or more tunnels through a single gateway process, bytes flowing in both directions across all of that identity's active tunnels share one in-memory token bucket and are slowed to that configured rate.

The visible behavior is that an identity with no rate-limit row behaves exactly as it does today, while an identity with a rate limit can still connect to approved destinations but large transfers take measurably longer. This is intentionally process-local: it assumes only one running gateway process and does not coordinate buckets across multiple gateway instances.


## Progress

- [x] (2026-05-17T04:42Z) Read `.agent/PLANS.md`, `src/proxy.rs`, `src/policy.rs`, `src/registry.rs`, `src/main.rs`, `src/config.rs`, `migrations/0001_signed_authorization_registry.sql`, and the integration/e2e test helpers to ground the design in the current repository.
- [x] (2026-05-17T04:42Z) Created this ExecPlan for user review.
- [x] (2026-05-17T04:47Z) Updated the plan to reflect the user decision to introduce a `SubjectIdentity` struct carrying identity metadata instead of threading a raw identity string and separate settings.
- [x] (2026-05-17T04:51Z) Updated the plan so `RegistryStore` returns a complete `SubjectIdentity`, with absent identity metadata represented as an unlimited identity rather than as `None`.
- [x] (2026-05-17T04:54Z) Updated the limiter design to use per-bucket `std::sync::Mutex` locking, while keeping a short-lived map lock only for bucket lookup and creation.
- [ ] Implement the registry schema and SQLx metadata changes.
- [ ] Add `SubjectIdentity` and thread it through policy evaluation.
- [ ] Add a process-local shared token bucket limiter.
- [ ] Replace the tunnel copy path with a rate-aware bidirectional copy loop.
- [ ] Add focused unit, integration, and e2e tests.
- [ ] Run formatting, SQLx metadata checks, clippy, and the full test suite.
- [ ] Update README/configuration documentation and record final outcomes.


## Surprises & Discoveries

- Observation: `src/proxy.rs` currently uses `tokio::io::copy_bidirectional`, which reports final byte counts but does not expose a hook before each chunk is forwarded.
  Evidence: `spawn_tunnel` calls `copy_bidirectional(&mut downstream, &mut upstream).await` and logs the returned `(up, down)` byte counts.

- Observation: the policy engine returns only `PolicyDecision::Allow { source_identity }`, so policy evaluation needs a new structured allow result that carries both the identity string and the identity metadata loaded from the registry.
  Evidence: `src/policy.rs` defines `PolicyDecision::Allow { source_identity: String }` and the proxy stores that identity before opening the upstream TCP connection.

- Observation: schema version checking is strict, so adding a migration requires bumping the expected registry schema version.
  Evidence: `src/registry.rs` has `const EXPECTED_SCHEMA_VERSION: i32 = 1` and `verify_schema_version` rejects any other latest version.


## Decision Log

- Decision: Store limits in a new `identity_metadata` registry table keyed by `subject_identity`, with an optional positive `rate_limit_bytes_per_second` column.
  Rationale: The task asks for a per-identity limit, not a per-permission or per-destination limit. A separate table keeps metadata independent from permission grants and allows an identity to have no row, or a row with no limit, without affecting authorization semantics.
  Date/Author: 2026-05-17 / Codex

- Decision: Create a `SubjectIdentity` struct to represent an identity and its associated settings in the `identity_metadata` table, rather than just representing identities as a `String`.
  Rationale: Designing for future extensibility, and indicating a clear separation of concerns when we embed identity metadata in other structs/enums.
  Date/Author: 2026-05-17 / ajd

- Decision: Interpret the rate limit as one aggregate limit per identity across all active tunnels in one gateway process, with both client-to-destination and destination-to-client bytes charged to the same bucket.
  Rationale: This matches the user's high-level design and is the simplest useful behavior. It avoids destination-level buckets and avoids distributed coordination.
  Date/Author: 2026-05-17 / Codex

- Decision: Fetch the identity's current rate limit during policy evaluation and attach it to the `SubjectIdentity` returned inside `PolicyDecision::Allow`.
  Rationale: The policy engine already has the registry pool and already establishes the authenticated source identity. Returning structured identity metadata with the allow decision avoids adding a second database dependency to the proxy layer.
  Date/Author: 2026-05-17 / Codex

- Decision: `RegistryStore` should fetch identity metadata and return a complete `SubjectIdentity`, not just a standalone rate-limit value.
  Rationale: `SubjectIdentity` is the representation of an identity plus its registry-backed settings. A missing `identity_metadata` row means an authenticated identity with no configured rate limit, so the registry method should return `Ok(SubjectIdentity { rate_limit_bytes_per_second: None })` rather than `Ok(None)`.
  Date/Author: 2026-05-17 / ajd and Codex

- Decision: Enforce limits in the proxy layer with a shared in-memory token bucket map owned by `MakeProxyService`.
  Rationale: The proxy layer sees every proxied byte and already creates per-connection services from a shared factory. Keeping the limiter there avoids mixing byte-forwarding concerns into authorization code.
  Date/Author: 2026-05-17 / Codex

- Decision: Use `std::sync::Mutex` for both the bucket map and each individual bucket, but put token accounting behind per-bucket locks rather than one global lock.
  Rationale: The proof of concept does not need Tokio's `sync` feature as long as no lock is held across `.await`. A short map lock for lookup or insertion is simple, while per-bucket locks reduce unnecessary contention between different identities during high-throughput copying.
  Date/Author: 2026-05-17 / ajd and Codex

- Decision: The gateway refreshes the process-local bucket configuration for an identity when a new CONNECT request for that identity is authorized; it does not poll the database or read metadata per chunk.
  Rationale: A shared bucket must have one current configuration per identity. Refreshing on CONNECT keeps implementation simple and avoids database work in the forwarding loop. Existing tunnels for the same identity may observe the refreshed process-local limit after a later CONNECT for that identity, which is acceptable for this proof of concept and must be documented.
  Date/Author: 2026-05-17 / Codex


## Outcomes & Retrospective

This section is intentionally empty until implementation begins. At completion, record what was implemented, what validation passed, and which proof-of-concept limitations remain.


## Context and Orientation

This repository is a Rust 2024 project named `agent_gateway`. The entry point in `src/main.rs` starts an mTLS HTTP/2 CONNECT proxy. A CONNECT proxy accepts an HTTP CONNECT request, opens a TCP connection to the requested destination, and then forwards raw bytes between the client and that destination.

The current startup path is:

    src/main.rs loads config, builds TLS config, builds a policy engine with policy::build_engine, constructs MakeProxyService::new(policy_engine), accepts TLS connections, extracts peer certificates, and serves HTTP/2 requests using ProxyService.

The current authorization path is:

    src/proxy.rs parses the CONNECT authority into a canonical destination string.
    src/proxy.rs builds a RequestContext containing the mTLS peer certificates and destination.
    src/policy.rs extracts the source identity from a configured X.509 certificate extension.
    src/policy.rs normalizes the destination.
    src/registry.rs queries permission_registry and principal_signing_keys for active candidate permissions.
    src/policy.rs verifies the permission signature and checks signer destination scope.
    src/policy.rs returns PolicyDecision::Allow with a SubjectIdentity, or PolicyDecision::Deny with a reason.

The current tunnel path is:

    src/proxy.rs connects to the upstream TCP destination before returning HTTP 200.
    src/proxy.rs waits for the HTTP upgrade.
    src/proxy.rs wraps the upgraded stream in hyper_util::rt::TokioIo.
    src/proxy.rs calls tokio::io::copy_bidirectional to forward bytes both ways until EOF or error.
    src/proxy.rs logs bytes_client_to_dest and bytes_dest_to_client when the tunnel closes.

The current registry schema is in `migrations/0001_signed_authorization_registry.sql`. It has `agent_gateway_schema_version`, `principal_signing_keys`, `principal_key_permissions`, and `permission_registry`. The schema version check in `src/registry.rs` expects version 1. Tests use `tests/common/mod.rs`, which runs migrations against `TEST_DATABASE_URL` and provides helpers for seeding signed permissions.

The new term "token bucket" means a small in-memory state object that holds a number of available byte tokens for one identity. Tokens refill over time at the configured bytes-per-second rate. Before the proxy forwards a chunk of N bytes for that identity, it waits until the bucket has N tokens, then subtracts those tokens. This makes short bursts possible up to the bucket capacity while keeping the long-term average near the configured rate.

The new term `SubjectIdentity` means the Rust struct that represents an authenticated source identity after policy evaluation has extracted it from the client certificate and loaded any associated identity metadata from the registry. Its required fields for this proof of concept are the identity value itself and the optional `rate_limit_bytes_per_second` value. Code should use this struct when passing an allowed identity between policy and proxy layers instead of passing a bare `String` plus separate metadata fields.


## Plan of Work

First, add registry storage for identity metadata. Create a new migration `migrations/0002_identity_metadata.sql`. It should create a table named `identity_metadata` with `subject_identity TEXT PRIMARY KEY`, `rate_limit_bytes_per_second BIGINT`, `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`, `CHECK (subject_identity <> '')`, and `CHECK (rate_limit_bytes_per_second IS NULL OR rate_limit_bytes_per_second > 0)`. Insert schema version 2 into `agent_gateway_schema_version`. Then change `EXPECTED_SCHEMA_VERSION` in `src/registry.rs` to 2. For this proof of concept, a missing row and a row with `rate_limit_bytes_per_second = NULL` both mean unlimited.

Next, define the structured identity type in `src/policy.rs`. Add `pub struct SubjectIdentity` with private fields for `value: String` and `rate_limit_bytes_per_second: Option<NonZeroU64>`. Implement a constructor usable inside the policy module, plus public accessor methods `value(&self) -> &str` and `rate_limit_bytes_per_second(&self) -> Option<NonZeroU64>`. Keeping fields private lets future identity metadata be added without turning the struct into an unstructured bag of public fields.

Then add a registry method for loading identity metadata into the structured identity type. In `src/registry.rs`, add a method on `RegistryStore` named `subject_identity(&self, subject_identity: String) -> anyhow::Result<crate::policy::SubjectIdentity>`. The SQL should select `rate_limit_bytes_per_second` from `identity_metadata` for the identity value. If no row exists or the value is NULL, return a `SubjectIdentity` with `rate_limit_bytes_per_second: None`; absence of metadata does not mean absence of the authenticated identity. If a positive value exists, convert it to `u64`, then to `NonZeroU64`, and return a `SubjectIdentity` with that limit. Because the database check constraint prevents zero and negative values, conversion failure should be treated as a registry data error with context. Wrap the query in the same `self.query_timeout` pattern used by `candidate_permissions` and `signer_has_scope`.

Then thread the structured identity through policy evaluation. In `src/policy.rs`, change `PolicyDecision::Allow` to `Allow { subject_identity: SubjectIdentity }`. In `PostgresPolicyEngine::evaluate`, after a candidate permission is accepted, call `self.registry.subject_identity(source_identity).await` and return the resulting `SubjectIdentity` in the allow decision. If the metadata lookup fails, deny the request with the original source identity in `source_identity: Some(...)` and a reason such as `identity metadata lookup failed: ...`; this mirrors existing registry lookup failure behavior. Existing tests that match `Allow { .. }` can continue using wildcard fields, but any exact construction or match must be updated.

After that, add the limiter implementation. Prefer a new module `src/rate_limit.rs`, exported from `src/lib.rs` as `pub mod rate_limit;`, because the logic is independent enough to unit test without TLS or Postgres. Define a cloneable `RateLimiter` type that owns an `Arc<std::sync::Mutex<HashMap<String, Arc<std::sync::Mutex<Bucket>>>>>`. Use `std::sync::Mutex`, not `tokio::sync::Mutex`, so no new Tokio feature is required; do not hold any mutex guard across `.await`. The outer map mutex should be held only long enough to insert, remove, or clone an `Arc` to a per-identity bucket. Token refill and subtraction should happen while holding only that identity bucket's mutex, so unrelated identities do not block each other while copying data.

Define a synchronous method `configure_identity(&self, identity: &SubjectIdentity)` that creates or updates the per-identity bucket when `identity.rate_limit_bytes_per_second()` returns a positive limit, and removes the bucket from the map when it returns `None`. Define an async method `acquire(&self, identity_value: &str, bytes: usize)`. If there is no bucket for that identity value or `bytes == 0`, return immediately. If a bucket exists, clone its `Arc` while holding the map lock, release the map lock, then refill and inspect the bucket under the bucket lock. If enough tokens are present, subtract them and return. If not, compute a sleep duration, release the bucket lock, sleep with `tokio::time::sleep`, and retry. Bucket capacity should be one second of traffic: `limit.get()` tokens. If a read chunk is larger than capacity, acquire it in repeated chunks no larger than capacity so low configured rates can still make progress.

Use integer math for refill to keep clippy clean. One workable representation is `Bucket { limit_bytes_per_second: NonZeroU64, capacity: u64, tokens: u64, refill_remainder: u128, last_refill: Instant }`, with nanoseconds as the time unit. On refill, compute `total = elapsed_nanos * u128::from(limit) + refill_remainder`, add `total / 1_000_000_000` tokens up to capacity, and retain `total % 1_000_000_000` as the remainder. When the configured limit for an identity changes, update that identity's bucket under its bucket lock, clamp tokens to the new capacity, and keep the bucket otherwise intact. If the identity becomes unlimited, remove its bucket from the map under the map lock. For a couple-hour proof of concept, do not implement garbage collection of idle buckets beyond removing buckets for identities explicitly configured as unlimited.

Then wire the limiter into the proxy. In `src/proxy.rs`, add `rate_limiter: RateLimiter` to `MakeProxyService` and `ProxyService`. `MakeProxyService::new(policy_engine)` should create `RateLimiter::default()` internally so most callers do not need a new argument. `make_service` should clone the limiter into each `ProxyService`. In `handle`, bind `subject_identity` from the allow decision. After the policy decision allows the CONNECT and before spawning the tunnel, call `rate_limiter.configure_identity(&subject_identity)`. Clone or extract the identity value string from `subject_identity` for logging and as the limiter key in the spawned tunnel. Pass the limiter into `spawn_tunnel`.

Replace `copy_bidirectional` with an explicit rate-aware tunnel copy. One straightforward design is to split both streams with `tokio::io::split`, then run two `rate_limited_copy` futures concurrently with `tokio::try_join!`. The client-to-destination copy reads from the upgraded downstream stream, calls `rate_limiter.acquire(source_identity_value.as_str(), n).await`, writes the bytes to the upstream writer, and accumulates the byte count. The destination-to-client copy does the same in reverse and uses the same identity value, so both directions charge the same bucket. On EOF, call `shutdown()` on the writer for that direction. Preserve the existing final log fields `bytes_client_to_dest` and `bytes_dest_to_client` so existing observability expectations continue to hold.

Finally, update tests and docs. Add unit tests for the token bucket behavior in `src/rate_limit.rs`. Add registry or policy integration tests showing that an identity without metadata is allowed with no limit, an identity with metadata is allowed with the expected limit, and an invalid metadata lookup failure denies authorization if such a failure can be induced cleanly. Add an e2e test that configures a very low limit, transfers enough bytes through the echo tunnel, and asserts elapsed time is greater than a conservative lower bound. Keep timing thresholds loose to avoid flakes. Update `README.md` to describe the `identity_metadata` table and the proof-of-concept limitations.


## Concrete Steps

Work from the repository root: `/home/ajd/projects/sl5_work_test/agent-gateway`.

1. Create `migrations/0002_identity_metadata.sql` with the new table and schema version insert.

2. Edit `src/registry.rs`:

    - Change `EXPECTED_SCHEMA_VERSION` from 1 to 2.
    - Import `std::num::NonZeroU64`.
    - Add `RegistryStore::subject_identity` returning `anyhow::Result<crate::policy::SubjectIdentity>`.

3. Edit `src/policy.rs`:

    - Import `std::num::NonZeroU64`.
    - Add `pub struct SubjectIdentity` with private identity value and rate-limit fields.
    - Add accessor methods for the identity value and optional rate limit.
    - Change `PolicyDecision::Allow` to contain `subject_identity: SubjectIdentity`.
    - Query identity metadata through `RegistryStore::subject_identity` after a permission candidate is accepted.
    - Deny on metadata lookup errors with an explicit reason.

4. Add `src/rate_limit.rs`:

    - Define `RateLimiter`.
    - Define internal `Bucket`.
    - Store buckets as `HashMap<String, Arc<std::sync::Mutex<Bucket>>>` behind a short-lived map mutex.
    - Implement `Default`, `Clone`, `configure_identity`, and `acquire`.
    - Have `configure_identity` accept `&SubjectIdentity`.
    - Have `acquire` accept the identity value string key and byte count.
    - Hold the map mutex only for bucket lookup, insertion, removal, or cloning the bucket `Arc`; hold the bucket mutex only for token accounting; hold no lock across `.await`.
    - Add unit tests using short real-time sleeps with generous assertions. Avoid adding Tokio's `test-util` feature unless the timing tests become too slow or flaky.

5. Edit `src/lib.rs` to export `pub mod rate_limit;`.

6. Edit `src/proxy.rs`:

    - Remove the `copy_bidirectional` import.
    - Add `use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};` or equivalent imports.
    - Add the limiter to `MakeProxyService` and `ProxyService`.
    - Configure the limiter from the allow decision's `SubjectIdentity` before spawning the tunnel.
    - Use `SubjectIdentity::value()` for log fields and the limiter key.
    - Add `rate_limited_copy`.
    - Use `tokio::try_join!` to run both directions concurrently.

7. Edit `tests/common/mod.rs`:

    - Add a helper on `TestAuthzRegistry` to insert or clear an identity rate limit, for example `set_identity_rate_limit(&self, subject_identity: &str, bytes_per_second: Option<i64>)`.
    - Extend cleanup to delete rows from `identity_metadata` for test identities touched by the registry, or have the helper return enough information for test-local cleanup.

8. Edit `tests/integration.rs`:

    - Add tests for policy allow decisions with absent metadata and configured metadata.
    - Adjust existing matches for the new `PolicyDecision::Allow` shape if needed.

9. Edit `tests/e2e.rs`:

    - Add a conservative timing test using an echo server and a low rate limit.
    - Transfer enough data to observe throttling without making the suite slow. For example, 4096 bytes through an echo server at 2048 bytes per second accounts for 8192 total bytes across both directions; with a one-second initial bucket capacity, that should take roughly three seconds, but the assertion should use a conservative lower bound to allow scheduling variability.

10. Edit `README.md`:

    - Document the new identity metadata table.
    - State that rate limits are process-local, are refreshed when a new CONNECT is authorized for an identity, aggregate across active tunnels by identity, and count both directions.

11. Regenerate SQLx metadata if the repository contains `.sqlx` metadata or if CI expects it. Use the exact commands from README/CI:

        cargo install sqlx-cli --version 0.8.6 --locked --no-default-features --features postgres
        SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx database setup
        SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx prepare -- --all-targets --locked

12. Run validation:

        cargo fmt
        SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx prepare --check -- --all-targets --locked
        cargo clippy --locked --all-targets
        cargo test --locked


## Validation and Acceptance

The implementation is acceptable when all of the following are true.

An identity without a row in `identity_metadata` can still connect and tunnel data exactly as before. The existing `tunnel_echoes_data` e2e test should continue to pass, and the final `tunnel closed` event should still include positive `bytes_client_to_dest` and `bytes_dest_to_client` values.

An identity with `identity_metadata.rate_limit_bytes_per_second = N` receives `PolicyDecision::Allow { subject_identity }` when it otherwise has a valid signed permission, where `subject_identity.value()` is the certificate identity and `subject_identity.rate_limit_bytes_per_second()` is `Some(N)`. This should be proven with a database-backed integration test.

All active tunnels for the same identity share one limiter in the same process. This can be proven with either a focused unit test that calls `RateLimiter::acquire` concurrently for the same identity or an e2e test with two tunnels if there is enough time. For the proof of concept, the unit test is sufficient if the e2e timing test proves real tunnel throttling.

Both traffic directions count against the same configured limit. The e2e timing test should use the echo server so bytes written by the client are also returned by the destination; the observed elapsed time should reflect charging both the outbound and inbound chunks.

All commands below should complete successfully:

    cargo fmt
    SQLX_OFFLINE=false DATABASE_URL="$TEST_DATABASE_URL" cargo sqlx prepare --check -- --all-targets --locked
    cargo clippy --locked --all-targets
    cargo test --locked


## Idempotence and Recovery

The migration is additive and safe to run once through SQLx migrations. If a local test database has already applied only version 1, rerunning `cargo sqlx database setup` with the new migration should apply version 2. If local test data causes conflicts, use a disposable test database because the test harness expects to write and clean up registry rows.

The limiter is process-local state only. Restarting the gateway clears all buckets. That is acceptable for this proof of concept and should be documented as a limitation.

If the e2e timing test is flaky, first loosen its lower bound or reduce scheduler sensitivity. Do not replace it with only a pure unit test unless the user agrees, because the feature must be demonstrated on actual proxied data.


## Artifacts and Notes

Current tunnel forwarding code in `src/proxy.rs`:

    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok((up, down)) => {
            info!(
                bytes_client_to_dest = up,
                bytes_dest_to_client = down,
                "tunnel closed"
            );
        }
        Err(e) => { ... }
    }

Target policy decision shape:

    pub enum PolicyDecision {
        Allow {
            subject_identity: SubjectIdentity,
        },
        Deny {
            source_identity: Option<String>,
            reason: String,
        },
    }

Target migration shape:

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


## Interfaces and Dependencies

Use only existing project dependencies for the proof of concept. Do not add a rate-limiting crate unless implementation uncovers a concrete blocker.

In `src/policy.rs`, define:

    #[derive(Debug, Clone)]
    pub struct SubjectIdentity { ... }

    impl SubjectIdentity {
        pub(crate) fn new(
            value: String,
            rate_limit_bytes_per_second: Option<std::num::NonZeroU64>,
        ) -> Self;

        pub fn value(&self) -> &str;

        pub fn rate_limit_bytes_per_second(
            &self,
        ) -> Option<std::num::NonZeroU64>;
    }

In `src/rate_limit.rs`, define:

    #[derive(Clone, Default)]
    pub struct RateLimiter {
        buckets: Arc<Mutex<HashMap<String, Arc<Mutex<Bucket>>>>>,
    }

    impl RateLimiter {
        pub fn configure_identity(&self, identity: &crate::policy::SubjectIdentity);

        pub async fn acquire(&self, identity_value: &str, bytes: usize);
    }

In `src/registry.rs`, define:

    pub(crate) async fn subject_identity(
        &self,
        subject_identity: String,
    ) -> anyhow::Result<crate::policy::SubjectIdentity>;

In `src/proxy.rs`, keep the external constructor shape:

    impl MakeProxyService {
        pub fn new(policy_engine: Arc<dyn PolicyEngine>) -> Self;
    }

This preserves existing call sites in `src/main.rs` and `tests/common/mod.rs`.


## Plan Change Notes

2026-05-17 / Codex: Initial plan created for user review. The plan deliberately scopes rate limiting to a single gateway process and refreshes the process-local bucket configuration when an identity opens a new CONNECT because the task is a simple proof of concept with a couple-hour implementation budget.

2026-05-17 / Codex: Updated the plan after ajd added the `SubjectIdentity` decision. The plan now makes `SubjectIdentity` the policy-to-proxy carrier for the authenticated identity value and its optional rate-limit metadata.

2026-05-17 / Codex: Updated the registry lookup design so `RegistryStore::subject_identity` returns a complete `SubjectIdentity`. Missing `identity_metadata` rows now map to an unlimited `SubjectIdentity` instead of an optional result.

2026-05-17 / Codex: Updated the limiter design to keep `std::sync::Mutex` but use per-bucket locking. The global map lock is now only for managing bucket handles, and each identity's token accounting happens under that identity's own bucket lock.
