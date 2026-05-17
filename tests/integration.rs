mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use common::{TestAuthzRegistry, TestPki, certificate_spki_der, unique_test_identity};
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use agent_gateway::policy::{PolicyDecision, PolicyEngine, RequestContext};

const EXT_OID: &str = "1.3.6.1.4.1.57264.1.1";

async fn eval(engine: &dyn PolicyEngine, pki: &TestPki, dest: &str) -> PolicyDecision {
    let ctx = RequestContext {
        peer_certificates: pki.client_cert_chain(),
        destination: dest.into(),
    };
    engine.evaluate(&ctx).await
}

fn assert_allow(decision: PolicyDecision) {
    if let PolicyDecision::Deny { reason, .. } = decision {
        panic!("expected Allow, got Deny: {reason}");
    }
}

fn assert_deny(decision: &PolicyDecision) {
    if let PolicyDecision::Allow { .. } = decision {
        panic!("expected Deny, got Allow");
    }
}

// ---- Policy: allow / deny ----

#[tokio::test]
async fn policy_allows_matching_cert_and_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "api.example.com:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_allows_explicit_non_default_port() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "custom.example.com:8443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "custom.example.com:8443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_wrong_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    match eval(engine.as_ref(), &pki, "evil.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some(subject.as_str())),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_wrong_port() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_deny(&eval(engine.as_ref(), &pki, "api.example.com:8080").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_unknown_extension_value() {
    let subject = unique_test_identity("agent-alpha");
    let unknown_subject = unique_test_identity("agent-unknown");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&unknown_subject);
    let authorized_pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&authorized_pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert_eq!(source_identity.as_deref(), Some(unknown_subject.as_str())),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_same_identity_and_destination_with_different_key() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let authorized_pki = TestPki::new(&subject);
    let different_key_pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&authorized_pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    match eval(engine.as_ref(), &different_key_pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("no active signed permission"),
                "denial should be caused by missing key-bound permission, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_no_cert() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    let ctx = RequestContext {
        peer_certificates: vec![],
        destination: "api.example.com:443".into(),
    };
    match engine.evaluate(&ctx).await {
        PolicyDecision::Deny {
            source_identity, ..
        } => assert!(source_identity.is_none()),
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

// ---- Default port (443) ----

#[tokio::test]
async fn policy_config_without_port_defaults_to_443() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "api.example.com").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_config_without_port_denies_non_443() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_deny(&eval(engine.as_ref(), &pki, "api.example.com:8080").await);
    registry.cleanup().await;
}

// ---- IPv6 policy matching ----

#[tokio::test]
async fn policy_ipv6_config_matches_bracketed_request() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "[::1]:8443").await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "[::1]:8443").await);
    assert_deny(&eval(engine.as_ref(), &pki, "[::1]:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_bare_ipv6_config_matches_bracketed_request() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "[::1]:443").await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "::1").await);
    assert_deny(&eval(engine.as_ref(), &pki, "[::1]:8080").await);
    registry.cleanup().await;
}

// ---- Case insensitivity ----

#[tokio::test]
async fn policy_destination_matching_is_case_insensitive() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_allow(eval(engine.as_ref(), &pki, "API.EXAMPLE.COM:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_tampered_permission_destination() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let permission = registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry
        .tamper_permission_destination(&permission.permission_id, "evil.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_deny(&eval(engine.as_ref(), &pki, "evil.example.com:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_revoked_permission() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let permission = registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry.revoke_permission(&permission.permission_id).await;
    let engine = registry.engine(EXT_OID).await;
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("no active signed permission"),
                "denial should be caused by revoked permission, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_revoked_signer() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    registry.revoke_signer().await;
    let engine = registry.engine(EXT_OID).await;
    match eval(engine.as_ref(), &pki, "api.example.com:443").await {
        PolicyDecision::Deny {
            source_identity,
            reason,
        } => {
            assert_eq!(source_identity.as_deref(), Some(subject.as_str()));
            assert!(
                reason.contains("is not active"),
                "denial should be caused by inactive signer, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => panic!("expected Deny"),
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_denies_signer_scope_violation() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry
        .allow_without_signer_scope_for_pki(&pki, &subject, "api.example.com:443")
        .await;
    let engine = registry.engine(EXT_OID).await;
    assert_deny(&eval(engine.as_ref(), &pki, "api.example.com:443").await);
    registry.cleanup().await;
}

// ---- TLS PKI ----

#[test]
fn test_pki_generates_valid_mtls_config() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .ok();

    let pki = TestPki::new("agent-alpha");

    let mut ca_store = RootCertStore::empty();
    ca_store.add(pki.ca_cert_der()).unwrap();

    let _server_config = ServerConfig::builder()
        .with_client_cert_verifier(agent_gateway::tls::db_rooted_client_cert_verifier())
        .with_single_cert(pki.server_cert_chain(), pki.server_key_der())
        .unwrap();

    let _client_config = ClientConfig::builder()
        .with_root_certificates(ca_store)
        .with_client_auth_cert(pki.client_cert_chain(), pki.client_key_der())
        .unwrap();
}

#[test]
fn openssl_spki_extraction_matches_gateway_parser() {
    if Command::new("openssl").arg("version").output().is_err() {
        return;
    }

    let pki = TestPki::new("agent-alpha");
    let cert_der = pki.client_cert.der().to_vec();
    let expected = certificate_spki_der(&cert_der);
    let temp_dir = std::env::temp_dir().join(format!(
        "agent-gateway-spki-test-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&temp_dir).unwrap();
    let cert_path = temp_dir.join("client.der");
    std::fs::write(&cert_path, cert_der).unwrap();

    let pubkey = Command::new("openssl")
        .args(["x509", "-inform", "DER", "-in"])
        .arg(&cert_path)
        .args(["-pubkey", "-noout"])
        .output()
        .expect("run openssl x509");
    assert!(
        pubkey.status.success(),
        "openssl x509 failed: {}",
        String::from_utf8_lossy(&pubkey.stderr)
    );

    let mut pkey = Command::new("openssl")
        .args(["pkey", "-pubin", "-outform", "DER"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run openssl pkey");
    pkey.stdin
        .as_mut()
        .unwrap()
        .write_all(&pubkey.stdout)
        .unwrap();
    let output = pkey.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "openssl pkey failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, expected);

    let _ = std::fs::remove_dir_all(temp_dir);
}

// ---- Config validation ----

#[test]
fn config_validates_oid() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "not-a-valid-oid"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_bad_oid.toml");
    std::fs::write(&path, toml).unwrap();
    assert!(agent_gateway::config::Config::load(&path).is_err());
}

#[test]
fn config_requires_exactly_one_database_url_source() {
    let make = |policy: &str| {
        let toml = format!(
            r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
{policy}
"#
        );
        let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
        std::fs::create_dir_all(&tmpdir).ok();
        let path = tmpdir.join(format!("policy_{}.toml", policy.len()));
        std::fs::write(&path, &toml).unwrap();
        agent_gateway::config::Config::load(&path)
    };

    assert!(make("").is_err());
    assert!(make("database_url = \"postgres://example.invalid/agent_gateway\"").is_ok());
    assert!(make("database_url_env = \"TEST_DATABASE_URL\"").is_ok());
    assert!(
        make(
            "database_url = \"postgres://example.invalid/agent_gateway\"\ndatabase_url_env = \"TEST_DATABASE_URL\""
        )
        .is_err()
    );
}

#[test]
fn config_rejects_removed_client_ca_path() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"
client_ca_path = "ca.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_client_ca_path.toml");
    std::fs::write(&path, toml).unwrap();
    let result = agent_gateway::config::Config::load(&path);
    assert!(
        result.is_err(),
        "client_ca_path should be rejected as an unknown field"
    );
}

#[test]
fn config_rejects_removed_policy_rules() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"

[[policy.rules]]
extension_value = "x"
allowed_destinations = ["api.example.com"]
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_policy_rules.toml");
    std::fs::write(&path, toml).unwrap();
    assert!(agent_gateway::config::Config::load(&path).is_err());
}

#[test]
fn config_rejects_removed_metrics_bind_field() {
    let toml = r#"
[server]
listen_addr = "0.0.0.0:8443"
tls_cert_path = "c.pem"
tls_key_path = "k.pem"

[observability]
log_level = "info"
metrics_bind = "0.0.0.0:9090"

[policy]
client_ext_oid = "1.3.6.1.4.1.57264.1.1"
database_url = "postgres://example.invalid/agent_gateway"
"#;
    let tmpdir = std::env::temp_dir().join("agent_gw_test_config");
    std::fs::create_dir_all(&tmpdir).ok();
    let path = tmpdir.join("reject_metrics_bind.toml");
    std::fs::write(&path, toml).unwrap();
    let result = agent_gateway::config::Config::load(&path);
    assert!(
        result.is_err(),
        "metrics_bind should be rejected as an unknown field"
    );
}

#[tokio::test]
async fn proxy_dest_ipv6_matches_policy() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    registry.allow_for_pki(&pki, &subject, "[::1]:8443").await;
    let engine = registry.engine(EXT_OID).await;

    assert_allow(eval(engine.as_ref(), &pki, "[::1]:8443").await);

    assert_deny(&eval(engine.as_ref(), &pki, "[::1]:443").await);
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_rejects_tampered_capacity_column() {
    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let seeded = registry
        .allow_with_limits_for_pki(&pki, &subject, "api.example.com:443", 1000, 100)
        .await;

    sqlx::query!(
        "UPDATE permission_registry SET capacity_bytes = capacity_bytes * 10 WHERE permission_id = $1",
        &seeded.permission_id
    )
    .execute(&registry.pool)
    .await
    .expect("tamper capacity_bytes");

    let engine = registry.engine(EXT_OID).await;
    let ctx = agent_gateway::policy::RequestContext {
        peer_certificates: pki.client_cert_chain(),
        destination: "api.example.com:443".into(),
    };
    match engine.evaluate(&ctx).await {
        PolicyDecision::Deny { reason, .. } => {
            assert!(
                reason.contains("invalid permission signature"),
                "expected signature verification failure, got: {reason}"
            );
        }
        PolicyDecision::Allow { .. } => {
            panic!("tampered row should not verify, but policy allowed it")
        }
    }
    registry.cleanup().await;
}

#[tokio::test]
async fn policy_with_rate_limit_exhausts_then_denies() {
    let _guard = common::serial_test_lock().await;
    let log = common::init_tracing_capture();
    common::drain_events(&log);

    let subject = unique_test_identity("agent-alpha");
    let registry = TestAuthzRegistry::new().await;
    let pki = TestPki::new(&subject);
    let (echo_addr, _echo_guard) = common::start_echo_server().await;
    let dest = format!("127.0.0.1:{}", echo_addr.port());

    let seeded = registry
        .allow_with_limits_for_pki(&pki, &subject, &dest, 100, 0)
        .await;

    let engine = registry.engine(EXT_OID).await;
    let (proxy_addr, _proxy_guard, store) =
        common::start_proxy_with_store(&pki, engine).await;

    // First CONNECT: should succeed because the bucket starts at full capacity.
    let mut send_req = common::connect_client(proxy_addr, &pki).await;
    let req = hyper::Request::connect(&dest)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200, "first CONNECT should be allowed");
    drop(resp);

    // Drain the bucket directly via the test-held store. Mid-tunnel
    // enforcement lands in the next commit; at this stage the tunnel
    // writes do not yet flow through MeteredStream, so we drain
    // explicitly. get_or_create returns the existing bucket because
    // the proxy already created it during the first CONNECT.
    let bucket = store.get_or_create(&seeded.permission_id, 100, 0, seeded.not_after);
    assert_eq!(
        bucket.try_consume_up_to(100),
        100,
        "drain should consume exactly the bucket's capacity"
    );

    // Second CONNECT on a fresh client: bucket is now empty, expect 429.
    let mut send_req2 = common::connect_client(proxy_addr, &pki).await;
    let req2 = hyper::Request::connect(&dest)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp2 = send_req2.send_request(req2).await.unwrap();
    assert_eq!(
        resp2.status(),
        429,
        "second CONNECT should be rate-limited"
    );

    registry.cleanup().await;
}

#[tokio::test]
async fn tunnel_closes_when_permission_revoked() {
    let _guard = common::serial_test_lock().await;
    let log = common::init_tracing_capture();
    common::drain_events(&log);

    let (echo_addr, _echo_guard) = common::start_echo_server().await;
    let dest = format!("127.0.0.1:{}", echo_addr.port());

    let subject = unique_test_identity("agent-alpha");
    let pki = TestPki::new(&subject);
    let registry = TestAuthzRegistry::new().await;
    let seeded = registry
        .allow_with_limits_for_pki(&pki, &subject, &dest, 1_000_000, 1_000_000)
        .await;
    let engine = registry.engine(EXT_OID).await;
    let (proxy_addr, _proxy_guard, bucket_store) =
        common::start_proxy_with_store(&pki, engine).await;

    let mut send_req = common::connect_client(proxy_addr, &pki).await;
    let req = hyper::Request::connect(&dest)
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = send_req.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);

    let upgraded = hyper::upgrade::on(resp).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);

    // Confirm the tunnel works for a small write before revocation.
    tokio::io::AsyncWriteExt::write_all(&mut io, b"hello")
        .await
        .expect("first write should succeed");

    // Revoke the permission via the same SQL the registry-cli would issue.
    sqlx::query!(
        "UPDATE permission_registry SET revoked_at = now() WHERE permission_id = $1",
        &seeded.permission_id
    )
    .execute(&registry.pool)
    .await
    .expect("revoke permission");

    // Simulate the revocation-poll task's work directly. Keeps the test
    // deterministic without waiting on the 30-second timer.
    let revoked_ids: Vec<String> = sqlx::query_scalar!(
        "SELECT permission_id FROM permission_registry WHERE revoked_at IS NOT NULL"
    )
    .fetch_all(&registry.pool)
    .await
    .expect("list revoked");
    assert!(
        revoked_ids.contains(&seeded.permission_id),
        "revoked list should include our permission"
    );
    for id in &revoked_ids {
        bucket_store.mark_revoked(id);
    }

    // The next write should fail because the bucket is now dead. We loop
    // a small number of times because the tunnel write path may buffer
    // a tiny amount in the h2 layer before the error surfaces.
    let mut closed = false;
    for _ in 0..16 {
        if tokio::io::AsyncWriteExt::write_all(&mut io, b"more data")
            .await
            .is_err()
        {
            closed = true;
            break;
        }
    }
    assert!(closed, "write after revocation should eventually fail");

    registry.cleanup().await;
}
