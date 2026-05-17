use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use agent_gateway::proxy::MakeProxyService;
use agent_gateway::rate_limit::BucketStore;
use agent_gateway::{config, observability, policy, proxy, tls};
use anyhow::Context;
use clap::Parser;
use hyper_util::rt::TokioExecutor;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

/// How often the background task polls `permission_registry` for newly
/// revoked rows and propagates their `revoked` flag to the matching
/// in-process buckets. Bounded latency for explicit revocation.
const REVOCATION_POLL_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Parser)]
#[command(name = "agent_gateway", about = "mTLS HTTP/2 CONNECT proxy")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install default crypto provider");

    let cli = Cli::parse();
    let config = config::Config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;

    serve(config).await
}

async fn serve(config: config::Config) -> anyhow::Result<()> {
    observability::init(&config.observability)?;

    let server_tls = tls::build_server_config(&config.server)?;
    let tls_acceptor = tls::TlsAcceptor::from(server_tls);

    let policy_engine = policy::build_engine(&config.policy).await?;
    let bucket_store = Arc::new(BucketStore::new());
    let make_service = Arc::new(MakeProxyService::new(
        policy_engine,
        bucket_store.clone(),
    ));

    let revocation_pool = policy::build_pool(&config.policy).await?;
    let revocation_task = tokio::spawn(run_revocation_poll(revocation_pool, bucket_store));

    let listen_addr: std::net::SocketAddr = config.server.listen_addr.parse()?;
    let listener = TcpListener::bind(listen_addr).await?;
    info!(%listen_addr, "listening");

    tokio::select! {
        result = serve_loop(&listener, &tls_acceptor, &make_service) => {
            result?;
        }
        _ = tokio::signal::ctrl_c() => {
            info!("received shutdown signal");
        }
    }

    revocation_task.abort();
    observability::shutdown();
    Ok(())
}

/// Background task that propagates explicit permission revocations
/// (`revoked_at` set on `permission_registry`) to the matching in-process
/// buckets. Bounded latency = `REVOCATION_POLL_INTERVAL`.
async fn run_revocation_poll(pool: PgPool, store: Arc<BucketStore>) {
    let mut ticker = tokio::time::interval(REVOCATION_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        ticker.tick().await;
        match query_revoked_permission_ids(&pool).await {
            Ok(ids) => {
                for id in ids {
                    store.mark_revoked(&id);
                }
            }
            Err(e) => warn!(error = ?e, "revocation poll query failed"),
        }
    }
}

/// Read-only query that returns every `permission_id` with `revoked_at` set.
/// The gateway calls this on a 30-second timer; integration tests call it
/// directly so they don't have to wait on the timer.
async fn query_revoked_permission_ids(pool: &PgPool) -> anyhow::Result<Vec<String>> {
    let rows = sqlx::query_scalar!(
        "SELECT permission_id FROM permission_registry WHERE revoked_at IS NOT NULL"
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

async fn serve_loop(
    listener: &TcpListener,
    tls_acceptor: &tls::TlsAcceptor,
    make_service: &Arc<MakeProxyService>,
) -> anyhow::Result<()> {
    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!(error = %e, "TCP accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let make_svc = make_service.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(tcp_stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(source_peer_addr = %peer_addr, error = %e, "TLS handshake failed");
                    return;
                }
            };

            let peer_certs = proxy::extract_peer_certs(tls_stream.get_ref().1);
            let service = make_svc.make_service(peer_certs, peer_addr);

            let io = hyper_util::rt::TokioIo::new(tls_stream);
            if let Err(e) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .http2_only()
                .serve_connection_with_upgrades(io, service)
                .await
            {
                error!(source_peer_addr = %peer_addr, error = %e, "connection error");
            }
        });
    }
}
