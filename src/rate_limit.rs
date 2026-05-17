//! Byte-denominated token bucket for per-permission egress limiting.
//! Internally "tokens" are bytes (1 token = 1 byte); the field name
//! follows the standard token-bucket algorithm vocabulary.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Instant;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct Inner {
    tokens: f64,
    last_refill: Instant,
}

pub struct TokenBucket {
    inner: Mutex<Inner>,
    capacity_bytes: u64,
    refill_bytes_per_sec: u64,
    permission_not_after: DateTime<Utc>,
    revoked: AtomicBool,
}

impl TokenBucket {
    /// Construct a bucket starting at full capacity. The signed permission
    /// values flow directly into this constructor; the bucket's parameters
    /// are immutable after this point.
    #[must_use]
    #[allow(clippy::cast_precision_loss)]
    pub fn new(
        capacity_bytes: u64,
        refill_bytes_per_sec: u64,
        permission_not_after: DateTime<Utc>,
    ) -> Self {
        Self {
            inner: Mutex::new(Inner {
                tokens: capacity_bytes as f64,
                last_refill: Instant::now(),
            }),
            capacity_bytes,
            refill_bytes_per_sec,
            permission_not_after,
            revoked: AtomicBool::new(false),
        }
    }

    /// Mark this bucket as revoked. Subsequent consume and peek operations
    /// return 0. Idempotent: calling on an already-revoked bucket is a
    /// no-op. The Release ordering on the store pairs with the Acquire
    /// load in `is_dead` so the revocation is visible to every subsequent
    /// dead-check across threads.
    pub fn mark_revoked(&self) {
        self.revoked.store(true, Ordering::Release);
    }

    /// Atomically grants up to `max` bytes of budget. Returns the number
    /// of bytes actually consumed from the bucket. Returns 0 if the bucket
    /// is empty or expired. The returned value is the amount the caller is
    /// committed to either using or refunding.
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn try_consume_up_to(&self, max: u64) -> u64 {
        if self.is_dead() {
            return 0;
        }
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refill_locked(&mut inner);
        // `tokens` is bounded above by `capacity_bytes` (a u64) after every
        // refill, and clamped at 0 below. The floor-then-cast to u64 is safe.
        let available = inner.tokens.max(0.0).floor() as u64;
        let granted = std::cmp::min(available, max);
        if granted > 0 {
            inner.tokens -= granted as f64;
        }
        granted
    }

    /// Return budget previously consumed (e.g. because the inner write was
    /// partial, errored, or returned Pending). Refund never raises tokens
    /// above capacity.
    #[allow(clippy::cast_precision_loss)]
    pub fn refund(&self, bytes: u64) {
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let cap = self.capacity_bytes as f64;
        inner.tokens = (inner.tokens + bytes as f64).min(cap);
    }

    /// How many whole bytes the bucket currently holds. Returns 0 if the
    /// bucket is expired. Useful for the CONNECT-time peek.
    #[must_use]
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn available_bytes(&self) -> u64 {
        if self.is_dead() {
            return 0;
        }
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refill_locked(&mut inner);
        inner.tokens.max(0.0).floor() as u64
    }

    /// Seconds until at least one byte is available, or `None` if the bucket
    /// already has budget, refill is zero, or the permission has expired
    /// (in any of these cases no amount of waiting will make budget appear).
    #[must_use]
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    pub fn seconds_until_one_byte(&self) -> Option<u64> {
        if self.is_dead() {
            return None;
        }
        let mut inner = self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        self.refill_locked(&mut inner);
        if inner.tokens >= 1.0 || self.refill_bytes_per_sec == 0 {
            return None;
        }
        let deficit = 1.0 - inner.tokens;
        let seconds = (deficit / self.refill_bytes_per_sec as f64).ceil() as u64;
        Some(seconds.max(1))
    }

    fn is_dead(&self) -> bool {
        self.revoked.load(Ordering::Acquire) || Utc::now() >= self.permission_not_after
    }

    #[allow(clippy::cast_precision_loss)]
    fn refill_locked(&self, inner: &mut Inner) {
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(inner.last_refill)
            .as_secs_f64();
        let cap = self.capacity_bytes as f64;
        inner.tokens = (inner.tokens + elapsed * (self.refill_bytes_per_sec as f64)).min(cap);
        inner.last_refill = now;
    }
}

/// Per-process store of `TokenBucket`s keyed on `permission_id`. The store is
/// shared between the proxy (which calls `get_or_create` per CONNECT) and
/// the revocation poll task (added in a later commit).
pub struct BucketStore {
    map: Mutex<HashMap<String, Arc<TokenBucket>>>,
}

impl BucketStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Return the bucket for `permission_id`, creating it with the supplied
    /// parameters if absent. The supplied parameters are ignored on
    /// subsequent calls; a bucket's parameters are fixed at construction.
    pub fn get_or_create(
        &self,
        permission_id: &str,
        capacity_bytes: u64,
        refill_bytes_per_sec: u64,
        permission_not_after: DateTime<Utc>,
    ) -> Arc<TokenBucket> {
        let mut map = self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(existing) = map.get(permission_id) {
            return existing.clone();
        }
        let bucket = Arc::new(TokenBucket::new(
            capacity_bytes,
            refill_bytes_per_sec,
            permission_not_after,
        ));
        map.insert(permission_id.to_owned(), bucket.clone());
        bucket
    }

    /// Mark the bucket for `permission_id` as revoked, if one exists.
    /// No-op for `permission_id`s the gateway has not seen yet. Called by
    /// the background revocation poll task in `main.rs`.
    pub fn mark_revoked(&self, permission_id: &str) {
        let map = self.map.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(bucket) = map.get(permission_id) {
            bucket.mark_revoked();
        }
    }
}

impl Default for BucketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// IO wrapper that meters writes against a `TokenBucket` while delegating
/// reads straight through. Designed for the upstream side of the
/// CONNECT-tunnel `copy_bidirectional` call.
pub struct MeteredStream<S> {
    inner: S,
    bucket: Arc<TokenBucket>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, bucket: Arc<TokenBucket>) -> Self {
        Self { inner, bucket }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Empty write is not a rate-limit event; delegate. Required because
        // `try_consume_up_to(0)` returns 0, which would otherwise trip the
        // empty-bucket branch below.
        if buf.is_empty() {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        // `buf.len()` is usize; on 64-bit platforms (the only ones rustls
        // supports here) this fits a u64 without loss.
        #[allow(clippy::cast_possible_truncation)]
        let granted = me.bucket.try_consume_up_to(buf.len() as u64);
        if granted == 0 {
            return Poll::Ready(Err(io::Error::other("rate_limit_exceeded")));
        }
        #[allow(clippy::cast_possible_truncation)]
        let granted_usize = granted as usize;
        match Pin::new(&mut me.inner).poll_write(cx, &buf[..granted_usize]) {
            Poll::Ready(Ok(n)) => {
                if n < granted_usize {
                    me.bucket.refund((granted_usize - n) as u64);
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                me.bucket.refund(granted);
                Poll::Ready(Err(e))
            }
            Poll::Pending => {
                me.bucket.refund(granted);
                Poll::Pending
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn far_future() -> DateTime<Utc> {
        Utc::now() + ChronoDuration::hours(1)
    }

    fn far_past() -> DateTime<Utc> {
        Utc::now() - ChronoDuration::hours(1)
    }

    #[test]
    fn try_consume_up_to_grants_at_most_max() {
        let bucket = TokenBucket::new(1000, 0, far_future());
        let granted = bucket.try_consume_up_to(500);
        assert_eq!(granted, 500);
        assert_eq!(bucket.available_bytes(), 500);
    }

    #[test]
    fn try_consume_up_to_grants_at_most_available() {
        let bucket = TokenBucket::new(1000, 0, far_future());
        bucket.try_consume_up_to(800);
        let granted = bucket.try_consume_up_to(500);
        assert_eq!(granted, 200);
        assert_eq!(bucket.available_bytes(), 0);
    }

    #[test]
    fn try_consume_up_to_zero_when_empty() {
        let bucket = TokenBucket::new(100, 0, far_future());
        bucket.try_consume_up_to(100);
        assert_eq!(bucket.try_consume_up_to(50), 0);
    }

    #[test]
    fn bucket_refills_over_time() {
        let bucket = TokenBucket::new(1000, 1000, far_future());
        bucket.try_consume_up_to(900);
        assert_eq!(bucket.available_bytes(), 100);
        std::thread::sleep(std::time::Duration::from_millis(200));
        let available = bucket.available_bytes();
        // After ~200ms with refill=1000 bytes/sec from 100 starting tokens
        // we expect roughly 300 tokens. Use a broad tolerance to avoid CI
        // flakiness on slow runners; the property under test is "some
        // refill happened, still capped at capacity".
        assert!(
            available > 100 && available <= 1000,
            "expected some refill after sleep, got {available}"
        );
    }

    #[test]
    fn concurrent_consume_no_overshoot() {
        use std::thread;

        let bucket = Arc::new(TokenBucket::new(1000, 0, far_future()));
        let total = Arc::new(AtomicU64::new(0));
        let mut handles = Vec::new();
        for _ in 0..100 {
            let bucket = bucket.clone();
            let total = total.clone();
            handles.push(thread::spawn(move || {
                let granted = bucket.try_consume_up_to(10);
                total.fetch_add(granted, Ordering::Relaxed);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let final_total = total.load(Ordering::Relaxed);
        assert!(
            final_total <= 1000,
            "total granted {final_total} must not exceed capacity 1000"
        );
        assert_eq!(final_total, 1000);
    }

    #[test]
    fn refund_does_not_exceed_capacity() {
        let bucket = TokenBucket::new(1000, 0, far_future());
        bucket.try_consume_up_to(500);
        bucket.refund(1000);
        assert_eq!(bucket.available_bytes(), 1000);
    }

    #[test]
    fn refund_after_partial_write_pattern() {
        let bucket = TokenBucket::new(1000, 0, far_future());
        let granted = bucket.try_consume_up_to(1000);
        assert_eq!(granted, 1000);
        bucket.refund(200);
        assert_eq!(bucket.available_bytes(), 200);
    }

    #[test]
    fn seconds_until_one_byte_when_empty_with_refill() {
        let bucket = TokenBucket::new(100, 10, far_future());
        bucket.try_consume_up_to(100);
        assert_eq!(bucket.seconds_until_one_byte(), Some(1));
    }

    #[test]
    fn seconds_until_one_byte_when_empty_no_refill() {
        let bucket = TokenBucket::new(100, 0, far_future());
        bucket.try_consume_up_to(100);
        assert_eq!(bucket.seconds_until_one_byte(), None);
    }

    #[test]
    fn seconds_until_one_byte_when_already_full() {
        let bucket = TokenBucket::new(100, 10, far_future());
        assert_eq!(bucket.seconds_until_one_byte(), None);
    }

    #[test]
    fn expired_bucket_returns_zero() {
        let bucket = TokenBucket::new(1000, 100, far_past());
        assert_eq!(bucket.try_consume_up_to(100), 0);
        assert_eq!(bucket.available_bytes(), 0);
        assert_eq!(bucket.seconds_until_one_byte(), None);
    }

    #[test]
    fn revoked_bucket_returns_zero() {
        let bucket = TokenBucket::new(1000, 100, far_future());
        assert!(bucket.available_bytes() > 0);
        bucket.mark_revoked();
        assert_eq!(bucket.try_consume_up_to(100), 0);
        assert_eq!(bucket.available_bytes(), 0);
        assert_eq!(bucket.seconds_until_one_byte(), None);
    }

    #[test]
    fn mark_revoked_is_idempotent() {
        let bucket = TokenBucket::new(1000, 100, far_future());
        bucket.mark_revoked();
        bucket.mark_revoked();
        assert_eq!(bucket.try_consume_up_to(1), 0);
    }

    #[test]
    fn bucket_store_mark_revoked_revokes_existing_bucket() {
        let store = BucketStore::new();
        let bucket = store.get_or_create("perm-1", 1000, 100, far_future());
        assert!(bucket.available_bytes() > 0);
        store.mark_revoked("perm-1");
        assert_eq!(bucket.available_bytes(), 0);
    }

    #[test]
    fn bucket_store_mark_revoked_is_noop_for_unknown_permission_id() {
        let store = BucketStore::new();
        store.mark_revoked("never-seen");
        // No panic, no error. Acceptable; the poll task may query
        // permission_ids the gateway has not yet served.
    }

    #[test]
    fn bucket_store_returns_same_instance_for_same_permission_id() {
        let store = BucketStore::new();
        let a = store.get_or_create("perm-1", 1000, 100, far_future());
        let b = store.get_or_create("perm-1", 9999, 9999, far_future());
        assert!(Arc::ptr_eq(&a, &b));
        // The second call's parameters are ignored; the original bucket's
        // capacity stands.
        assert_eq!(a.available_bytes(), 1000);
    }

    #[tokio::test]
    async fn metered_stream_caps_writes_at_capacity_no_overshoot() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let bucket = Arc::new(TokenBucket::new(1024, 0, far_future()));
        let (sender, mut receiver) = tokio::io::duplex(8192);
        let mut metered = MeteredStream::new(sender, bucket.clone());

        let payload = vec![0u8; 4096];
        // write_all will fail when the bucket drains; we don't assert on the
        // result type, only on the bytes that actually arrived.
        let _ = metered.write_all(&payload).await;
        drop(metered);

        let mut received_bytes = Vec::new();
        let _ = receiver.read_to_end(&mut received_bytes).await;

        assert!(
            received_bytes.len() <= 1024,
            "receiver got {} bytes; bucket capacity was 1024 — overshoot detected!",
            received_bytes.len()
        );
    }
}
