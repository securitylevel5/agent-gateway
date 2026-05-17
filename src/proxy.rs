use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::Service;
use hyper::{Method, Request, Response, StatusCode};
use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use rustls::ServerConnection;
use rustls_pki_types::CertificateDer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{Instrument, error, info, warn};
use tracing_opentelemetry::OpenTelemetrySpanExt;

use crate::policy::{self, PolicyDecision, PolicyEngine, RequestContext};
use crate::rate_limit::{RateLimitHandle, RateLimiter};

type ProxyBody = BoxBody<Bytes, Infallible>;

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|value| value.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(http::HeaderName::as_str).collect()
    }
}

fn extract_trace_context(headers: &HeaderMap) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderExtractor(headers)))
}

#[derive(Clone)]
pub struct ProxyService {
    policy_engine: Arc<dyn PolicyEngine>,
    rate_limiter: RateLimiter,
    peer_certs: Vec<CertificateDer<'static>>,
    source_peer_addr: SocketAddr,
}

impl ProxyService {
    fn new(
        policy_engine: Arc<dyn PolicyEngine>,
        rate_limiter: RateLimiter,
        peer_certs: Vec<CertificateDer<'static>>,
        source_peer_addr: SocketAddr,
    ) -> Self {
        Self {
            policy_engine,
            rate_limiter,
            peer_certs,
            source_peer_addr,
        }
    }

    async fn handle(self, req: Request<Incoming>) -> Response<ProxyBody> {
        if req.method() != Method::CONNECT {
            return response(StatusCode::METHOD_NOT_ALLOWED, "only CONNECT is supported");
        }

        let parent_context = extract_trace_context(req.headers());
        let dest = match Destination::from_request(&req) {
            Ok(d) => d,
            Err(reason) => return response(StatusCode::BAD_REQUEST, &reason),
        };

        let span = tracing::info_span!(
            "gateway CONNECT",
            source_peer_addr = %self.source_peer_addr,
            dest_authority = %dest.authority,
        );
        let _ = span.set_parent(parent_context);

        async move {
            let ctx = RequestContext {
                peer_certificates: self.peer_certs.clone(),
                destination: dest.authority.clone(),
            };

            let subject_identity = match self.policy_engine.evaluate(&ctx).await {
                PolicyDecision::Allow { subject_identity } => {
                    info!(
                        source_identity = %subject_identity.value(),
                        source_peer_addr = %self.source_peer_addr,
                        dest_authority = %dest.authority,
                        policy_decision = "allow",
                        "CONNECT allowed"
                    );
                    subject_identity
                }
                PolicyDecision::Deny {
                    source_identity,
                    reason,
                } => {
                    log_denial(
                        source_identity.as_deref(),
                        self.source_peer_addr,
                        &dest.authority,
                        &reason,
                    );
                    return response(StatusCode::FORBIDDEN, "forbidden");
                }
            };
            let source_identity = subject_identity.value().to_owned();

            // Connect to destination BEFORE returning 200 so the client knows
            // the tunnel is actually established.
            let upstream = match TcpStream::connect((&*dest.host, dest.port)).await {
                Ok(s) => s,
                Err(e) => {
                    error!(
                        source_identity = %source_identity,
                        source_peer_addr = %self.source_peer_addr,
                        dest_authority = %dest.authority,
                        error = %e,
                        "TCP connect failed"
                    );
                    return response(StatusCode::BAD_GATEWAY, "bad gateway");
                }
            };

            let on_upgrade = hyper::upgrade::on(req);
            let rate_limit = self.rate_limiter.configure_identity(&subject_identity);
            spawn_tunnel(
                on_upgrade,
                upstream,
                rate_limit,
                source_identity,
                self.source_peer_addr,
                dest.authority,
            );

            response(StatusCode::OK, "")
        }
        .instrument(span)
        .await
    }
}

impl Service<Request<Incoming>> for ProxyService {
    type Response = Response<ProxyBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { Ok(this.handle(req).await) })
    }
}

pub struct MakeProxyService {
    policy_engine: Arc<dyn PolicyEngine>,
    rate_limiter: RateLimiter,
}

impl MakeProxyService {
    pub fn new(policy_engine: Arc<dyn PolicyEngine>) -> Self {
        Self {
            policy_engine,
            rate_limiter: RateLimiter::default(),
        }
    }

    #[must_use]
    pub fn make_service(
        &self,
        peer_certs: Vec<CertificateDer<'static>>,
        source_peer_addr: SocketAddr,
    ) -> ProxyService {
        ProxyService::new(
            self.policy_engine.clone(),
            self.rate_limiter.clone(),
            peer_certs,
            source_peer_addr,
        )
    }
}

#[must_use]
pub fn extract_peer_certs(conn: &ServerConnection) -> Vec<CertificateDer<'static>> {
    conn.peer_certificates()
        .map(<[CertificateDer<'_>]>::to_vec)
        .unwrap_or_default()
}

fn log_denial(
    source_identity: Option<&str>,
    source_peer_addr: SocketAddr,
    dest_authority: &str,
    reason: &str,
) {
    if let Some(source_identity) = source_identity {
        warn!(
            source_identity = %source_identity,
            source_peer_addr = %source_peer_addr,
            dest_authority = %dest_authority,
            policy_decision = "deny",
            deny_reason = %reason,
            "CONNECT denied"
        );
    } else {
        warn!(
            source_peer_addr = %source_peer_addr,
            dest_authority = %dest_authority,
            policy_decision = "deny",
            deny_reason = %reason,
            "CONNECT denied"
        );
    }
}

fn spawn_tunnel(
    on_upgrade: hyper::upgrade::OnUpgrade,
    upstream: TcpStream,
    rate_limit: RateLimitHandle,
    source_identity: String,
    source_peer_addr: SocketAddr,
    dest_authority: String,
) {
    let tunnel_span = tracing::Span::current();
    tokio::spawn(
        async move {
            let upgraded = match on_upgrade.await {
                Ok(u) => u,
                Err(e) => {
                    warn!(
                        source_identity = %source_identity,
                        source_peer_addr = %source_peer_addr,
                        dest_authority = %dest_authority,
                        error = %e,
                        "upgrade failed"
                    );
                    return;
                }
            };

            let mut downstream = hyper_util::rt::TokioIo::new(upgraded);
            let (downstream_read, downstream_write) = tokio::io::split(&mut downstream);
            let (upstream_read, upstream_write) = tokio::io::split(upstream);

            let client_to_dest =
                rate_limited_copy(downstream_read, upstream_write, rate_limit.clone());
            let dest_to_client = rate_limited_copy(upstream_read, downstream_write, rate_limit);

            match tokio::try_join!(client_to_dest, dest_to_client) {
                Ok((up, down)) => {
                    info!(
                        source_identity = %source_identity,
                        source_peer_addr = %source_peer_addr,
                        dest_authority = %dest_authority,
                        bytes_client_to_dest = up,
                        bytes_dest_to_client = down,
                        "tunnel closed"
                    );
                }
                Err(e) => {
                    error!(
                        source_identity = %source_identity,
                        source_peer_addr = %source_peer_addr,
                        dest_authority = %dest_authority,
                        error = %e,
                        "tunnel error"
                    );
                }
            }
        }
        .instrument(tunnel_span),
    );
}

async fn rate_limited_copy<R, W>(
    mut reader: R,
    mut writer: W,
    rate_limit: RateLimitHandle,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0_u8; 16 * 1024];
    let mut total = 0_u64;

    loop {
        let bytes_read = reader.read(&mut buf).await?;
        if bytes_read == 0 {
            writer.shutdown().await?;
            return Ok(total);
        }

        rate_limit.acquire(bytes_read).await;
        writer.write_all(&buf[..bytes_read]).await?;
        total = total.saturating_add(u64::try_from(bytes_read).unwrap_or(u64::MAX));
    }
}

fn response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    let body: ProxyBody = if message.is_empty() {
        Empty::<Bytes>::new().boxed()
    } else {
        Full::new(Bytes::from(message.to_owned())).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

#[derive(Clone)]
struct Destination {
    host: String,
    port: u16,
    authority: String,
}

impl Destination {
    fn from_request(req: &Request<Incoming>) -> Result<Self, String> {
        let authority = req
            .uri()
            .authority()
            .ok_or("CONNECT request missing authority")?;
        Self::from_authority(authority)
    }

    fn from_authority(authority: &http::uri::Authority) -> Result<Self, String> {
        let raw_host = authority.host();
        if raw_host.is_empty() {
            return Err("empty host in CONNECT authority".into());
        }

        // Authority::host() preserves brackets for IPv6 (e.g. "[::1]").
        // Strip them so `host` is always the bare address for TcpStream::connect.
        let host = raw_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();

        let port = authority.port_u16().unwrap_or(443);

        // Reconstruct with brackets for IPv6 to feed the canonical normalizer
        let formatted = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let authority_str = policy::normalize_destination(&formatted)
            .map_err(|e| format!("bad destination: {e}"))?;

        Ok(Self {
            host,
            port,
            authority: authority_str,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry::trace::TraceContextExt;
    use opentelemetry_sdk::propagation::TraceContextPropagator;

    fn parse_dest(authority: &str) -> Result<Destination, String> {
        let authority: http::uri::Authority = authority.parse().map_err(|e| format!("{e}"))?;
        Destination::from_authority(&authority)
    }

    #[test]
    fn proxy_dest_hostname_with_port() {
        let d = parse_dest("api.example.com:443").unwrap();
        assert_eq!(d.host, "api.example.com");
        assert_eq!(d.port, 443);
        assert_eq!(d.authority, "api.example.com:443");
    }

    #[test]
    fn proxy_dest_hostname_without_port_defaults_443() {
        let d = parse_dest("api.example.com").unwrap();
        assert_eq!(d.host, "api.example.com");
        assert_eq!(d.port, 443);
        assert_eq!(d.authority, "api.example.com:443");
    }

    #[test]
    fn proxy_dest_hostname_non_default_port() {
        let d = parse_dest("api.example.com:8080").unwrap();
        assert_eq!(d.host, "api.example.com");
        assert_eq!(d.port, 8080);
        assert_eq!(d.authority, "api.example.com:8080");
    }

    #[test]
    fn proxy_dest_hostname_uppercased_is_lowered() {
        let d = parse_dest("API.EXAMPLE.COM:443").unwrap();
        assert_eq!(d.authority, "api.example.com:443");
    }

    #[test]
    fn proxy_dest_ipv6_with_port() {
        let d = parse_dest("[::1]:8443").unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, 8443);
        assert_eq!(d.authority, "[::1]:8443");
    }

    #[test]
    fn proxy_dest_ipv6_default_port() {
        let d = parse_dest("[::1]").unwrap();
        assert_eq!(d.host, "::1");
        assert_eq!(d.port, 443);
        assert_eq!(d.authority, "[::1]:443");
    }

    #[test]
    fn proxy_dest_ipv6_full_address() {
        let d = parse_dest("[2001:db8::1]:443").unwrap();
        assert_eq!(d.host, "2001:db8::1");
        assert_eq!(d.port, 443);
        assert_eq!(d.authority, "[2001:db8::1]:443");
    }

    #[test]
    fn extracts_trace_context_from_headers() {
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::new());

        let mut headers = HeaderMap::new();
        headers.insert(
            "traceparent",
            http::HeaderValue::from_static(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            ),
        );

        let context = extract_trace_context(&headers);
        let span = context.span();
        let span_context = span.span_context();

        assert!(span_context.is_valid());
        assert_eq!(
            span_context.trace_id().to_string(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
    }
}
