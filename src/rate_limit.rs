use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub window_secs: u64,
    pub max_bytes_per_identity: u64,
}

impl RateLimitConfig {
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            window_secs: 60,
            max_bytes_per_identity: 10 * 1024 * 1024,
        }
    }

    #[must_use]
    pub fn window(&self) -> Duration {
        Duration::from_secs(self.window_secs)
    }
}

#[derive(Debug)]
struct IdentityUsage {
    window_start: Instant,
    bytes_used: u64,
}

#[derive(Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    usage: Mutex<HashMap<String, IdentityUsage>>,
}

impl RateLimiter {
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            usage: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_record(&self, identity: &str, bytes: u64) -> RateLimitDecision {
        if !self.config.enabled {
            return RateLimitDecision::Allowed;
        }

        let now = Instant::now();
        let mut usage = self.usage.lock().expect("rate limiter mutex poisoned");

        let entry = usage
            .entry(identity.to_owned())
            .or_insert_with(|| IdentityUsage {
                window_start: now,
                bytes_used: 0,
            });

        if now.duration_since(entry.window_start) >= self.config.window() {
            entry.window_start = now;
            entry.bytes_used = 0;
        }

        let next_total = entry.bytes_used.saturating_add(bytes);

        if next_total > self.config.max_bytes_per_identity {
            return RateLimitDecision::Limited {
                bytes_used: entry.bytes_used,
                attempted_bytes: bytes,
                max_bytes: self.config.max_bytes_per_identity,
                window_secs: self.config.window_secs,
            };
        }

        entry.bytes_used = next_total;
        RateLimitDecision::Allowed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitDecision {
    Allowed,
    Limited {
        bytes_used: u64,
        attempted_bytes: u64,
        max_bytes: u64,
        window_secs: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_bytes_under_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            window_secs: 60,
            max_bytes_per_identity: 100,
        });

        assert_eq!(
            limiter.check_and_record("agent-alpha", 40),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_and_record("agent-alpha", 50),
            RateLimitDecision::Allowed
        );
    }

    #[test]
    fn blocks_bytes_over_limit() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            window_secs: 60,
            max_bytes_per_identity: 100,
        });

        assert_eq!(
            limiter.check_and_record("agent-alpha", 80),
            RateLimitDecision::Allowed
        );

        match limiter.check_and_record("agent-alpha", 30) {
            RateLimitDecision::Limited { max_bytes, .. } => assert_eq!(max_bytes, 100),
            RateLimitDecision::Allowed => panic!("expected rate limit"),
        }
    }

    #[test]
    fn keeps_identities_separate() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: true,
            window_secs: 60,
            max_bytes_per_identity: 100,
        });

        assert_eq!(
            limiter.check_and_record("agent-alpha", 100),
            RateLimitDecision::Allowed
        );
        assert_eq!(
            limiter.check_and_record("agent-beta", 100),
            RateLimitDecision::Allowed
        );

        assert!(matches!(
            limiter.check_and_record("agent-alpha", 1),
            RateLimitDecision::Limited { .. }
        ));
    }

    #[test]
    fn disabled_limiter_allows_without_tracking() {
        let limiter = RateLimiter::new(RateLimitConfig {
            enabled: false,
            window_secs: 60,
            max_bytes_per_identity: 1,
        });

        assert_eq!(
            limiter.check_and_record("agent-alpha", 1_000_000),
            RateLimitDecision::Allowed
        );
    }
}
