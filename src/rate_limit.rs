use std::collections::HashMap;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::policy::SubjectIdentity;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

#[derive(Clone, Default)]
pub struct RateLimiter {
    buckets: Arc<Mutex<HashMap<String, Arc<Mutex<Bucket>>>>>,
}

#[derive(Clone, Default)]
pub struct RateLimitHandle {
    bucket: Option<Arc<Mutex<Bucket>>>,
}

struct Bucket {
    limit_bytes_per_second: NonZeroU64,
    capacity: u64,
    tokens: u64,
    refill_remainder: u128,
    last_refill: Instant,
}

impl Bucket {
    fn new(limit_bytes_per_second: NonZeroU64) -> Self {
        let capacity = limit_bytes_per_second.get();
        Self {
            limit_bytes_per_second,
            capacity,
            tokens: capacity,
            refill_remainder: 0,
            last_refill: Instant::now(),
        }
    }

    fn update_limit(&mut self, limit_bytes_per_second: NonZeroU64) {
        self.refill(Instant::now());
        self.limit_bytes_per_second = limit_bytes_per_second;
        self.capacity = limit_bytes_per_second.get();
        self.tokens = self.tokens.min(self.capacity);
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_refill);
        if elapsed.is_zero() {
            return;
        }

        let elapsed_nanos = elapsed.as_nanos();
        let total =
            elapsed_nanos * u128::from(self.limit_bytes_per_second.get()) + self.refill_remainder;
        let added = (total / NANOS_PER_SECOND).min(u128::from(u64::MAX));
        self.refill_remainder = total % NANOS_PER_SECOND;
        self.last_refill = now;

        if added == 0 {
            return;
        }

        let added = u64::try_from(added).unwrap_or(u64::MAX);
        self.tokens = self.tokens.saturating_add(added).min(self.capacity);
    }

    fn try_acquire(&mut self, requested: u64, now: Instant) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= requested {
            self.tokens -= requested;
            None
        } else {
            let missing = requested - self.tokens;
            let nanos = (u128::from(missing) * NANOS_PER_SECOND)
                .div_ceil(u128::from(self.limit_bytes_per_second.get()));
            Some(duration_from_nanos(nanos))
        }
    }
}

impl RateLimiter {
    pub fn configure_identity(&self, identity: &SubjectIdentity) -> RateLimitHandle {
        if let Some(limit) = identity.rate_limit_bytes_per_second() {
            let bucket = {
                let mut buckets = self.buckets.lock().unwrap_or_else(PoisonError::into_inner);
                buckets
                    .entry(identity.value().to_owned())
                    .or_insert_with(|| Arc::new(Mutex::new(Bucket::new(limit))))
                    .clone()
            };
            bucket
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .update_limit(limit);
            RateLimitHandle {
                bucket: Some(bucket),
            }
        } else {
            self.buckets
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(identity.value());
            RateLimitHandle::default()
        }
    }
}

impl RateLimitHandle {
    pub async fn acquire(&self, bytes: usize) {
        let Some(bucket) = self.bucket.as_ref() else {
            return;
        };
        let mut remaining = u64::try_from(bytes).unwrap_or(u64::MAX);
        if remaining == 0 {
            return;
        }

        while remaining > 0 {
            let requested = {
                let bucket = bucket.lock().unwrap_or_else(PoisonError::into_inner);
                remaining.min(bucket.capacity)
            };

            loop {
                let wait = {
                    let mut bucket = bucket.lock().unwrap_or_else(PoisonError::into_inner);
                    bucket.try_acquire(requested, Instant::now())
                };
                if let Some(wait) = wait {
                    tokio::time::sleep(wait).await;
                } else {
                    remaining -= requested;
                    break;
                }
            }
        }
    }
}

fn duration_from_nanos(nanos: u128) -> Duration {
    let nanos = u64::try_from(nanos).unwrap_or(u64::MAX);
    Duration::from_nanos(nanos)
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;
    use std::time::{Duration, Instant};

    use super::*;

    fn subject(value: &str, limit: Option<u64>) -> SubjectIdentity {
        SubjectIdentity::new(value.to_owned(), limit.and_then(NonZeroU64::new))
    }

    #[tokio::test]
    async fn unlimited_identity_returns_immediately() {
        let limiter = RateLimiter::default();
        let handle = limiter.configure_identity(&subject("agent-alpha", None));
        handle
            .acquire(usize::try_from(u64::MAX).unwrap_or(usize::MAX))
            .await;
    }

    #[tokio::test]
    async fn configured_identity_waits_for_refill() {
        let limiter = RateLimiter::default();
        let handle = limiter.configure_identity(&subject("agent-alpha", Some(10_000)));
        handle.acquire(10_000).await;

        let start = Instant::now();
        handle.acquire(1_000).await;

        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "second acquire should wait for bucket refill"
        );
    }

    #[tokio::test]
    async fn different_identities_have_independent_buckets() {
        let limiter = RateLimiter::default();
        let alpha = limiter.configure_identity(&subject("agent-alpha", Some(10_000)));
        let beta = limiter.configure_identity(&subject("agent-beta", Some(10_000)));

        alpha.acquire(10_000).await;

        let start = Instant::now();
        beta.acquire(10_000).await;

        assert!(
            start.elapsed() < Duration::from_millis(50),
            "agent-beta should have its own full bucket"
        );
    }

    #[tokio::test]
    async fn cloned_handles_share_the_same_bucket() {
        let limiter = RateLimiter::default();
        let first = limiter.configure_identity(&subject("agent-alpha", Some(10_000)));
        let second = first.clone();

        first.acquire(10_000).await;

        let start = Instant::now();
        second.acquire(1_000).await;

        assert!(
            start.elapsed() >= Duration::from_millis(50),
            "second handle should wait for the shared bucket to refill"
        );
    }

    #[tokio::test]
    async fn removing_limit_makes_identity_unlimited() {
        let limiter = RateLimiter::default();
        let rate_limit = limiter.configure_identity(&subject("agent-alpha", Some(10_000)));
        rate_limit.acquire(10_000).await;
        let unlimited = limiter.configure_identity(&subject("agent-alpha", None));

        let start = Instant::now();
        unlimited.acquire(10_000).await;

        assert!(
            start.elapsed() < Duration::from_millis(50),
            "unlimited identity should not wait"
        );
    }
}
