//! Per-class token-bucket rate limiting (design §5.3, AC5, C-9).
//!
//! Every allowlisted method belongs to exactly one [`CommandClass`]; each
//! class with a quota owns an independent `governor` direct limiter with
//! `Quota::per_minute(n)` (burst `n`, replenished evenly over a minute).
//! [`CommandClass::Unlimited`] (`guest-fsfreeze-status`, `guest-fsfreeze-thaw`)
//! never denies: a frozen filesystem must always be thaw-able.
#![forbid(unsafe_code)]

use std::num::NonZeroU32;

use governor::Quota;
use governor::clock::{Clock, DefaultClock};
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed};

use crate::config::RateLimits;

/// The rate-limit class of a command (§5.3 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandClass {
    /// `guest-ping`, `guest-sync`, `guest-sync-delimited`, `guest-info` (C-9).
    PingSync,
    /// `guest-get-osinfo`, `guest-get-fsinfo`, `guest-network-get-interfaces`.
    Get,
    /// `guest-fsfreeze-freeze`, `guest-fsfreeze-freeze-list`.
    FsfreezeFreeze,
    /// `guest-fsfreeze-status`, `guest-fsfreeze-thaw`: never limited.
    Unlimited,
    /// `guest-fstrim`.
    Fstrim,
    /// `guest-shutdown`, `guest-suspend-ram`.
    Shutdown,
}

impl CommandClass {
    /// Classifies an allowlisted method; `None` for anything else.
    pub fn of(method: &str) -> Option<CommandClass> {
        Some(match method {
            "guest-ping" | "guest-sync" | "guest-sync-delimited" | "guest-info" => {
                CommandClass::PingSync
            }
            "guest-get-osinfo" | "guest-get-fsinfo" | "guest-network-get-interfaces" => {
                CommandClass::Get
            }
            "guest-fsfreeze-freeze" | "guest-fsfreeze-freeze-list" => CommandClass::FsfreezeFreeze,
            "guest-fsfreeze-status" | "guest-fsfreeze-thaw" => CommandClass::Unlimited,
            "guest-fstrim" => CommandClass::Fstrim,
            "guest-shutdown" | "guest-suspend-ram" => CommandClass::Shutdown,
            _ => return None,
        })
    }

    /// The name used in error descriptions and audit records; matches the
    /// `[rate_limits]` key without the `_per_min` suffix.
    pub const fn name(self) -> &'static str {
        match self {
            CommandClass::PingSync => "ping_sync",
            CommandClass::Get => "get_commands",
            CommandClass::FsfreezeFreeze => "fsfreeze_freeze",
            CommandClass::Unlimited => "unlimited",
            CommandClass::Fstrim => "fstrim",
            CommandClass::Shutdown => "shutdown",
        }
    }

    /// The configured per-minute quota, or `None` for [`Self::Unlimited`].
    pub fn quota(self, limits: &RateLimits) -> Option<u32> {
        match self {
            CommandClass::PingSync => Some(limits.ping_sync_per_min),
            CommandClass::Get => Some(limits.get_commands_per_min),
            CommandClass::FsfreezeFreeze => Some(limits.fsfreeze_freeze_per_min),
            CommandClass::Unlimited => None,
            CommandClass::Fstrim => Some(limits.fstrim_per_min),
            CommandClass::Shutdown => Some(limits.shutdown_per_min),
        }
    }
}

/// The limiter denied a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("rate limit exceeded for {}", class.name())]
pub struct RateLimited {
    /// The exhausted class.
    pub class: CommandClass,
}

impl From<RateLimited> for crate::proto::Error {
    fn from(err: RateLimited) -> Self {
        crate::proto::Error::RateLimited {
            class: err.class.name().to_owned(),
        }
    }
}

type Direct<C> =
    governor::RateLimiter<NotKeyed, InMemoryState, C, NoOpMiddleware<<C as Clock>::Instant>>;

/// One independent token bucket per limited class.
///
/// `Send + Sync`; a `check` is a few atomic operations.
pub struct RateLimiter<C: Clock = DefaultClock> {
    ping_sync: Direct<C>,
    get: Direct<C>,
    fsfreeze_freeze: Direct<C>,
    fstrim: Direct<C>,
    shutdown: Direct<C>,
}

impl<C: Clock> std::fmt::Debug for RateLimiter<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RateLimiter")
    }
}

impl RateLimiter<DefaultClock> {
    /// Builds the limiter with the real monotonic clock.
    pub fn new(limits: &RateLimits) -> Self {
        Self::with_clock(limits, DefaultClock::default())
    }
}

impl<C: Clock + Clone> RateLimiter<C> {
    /// Builds the limiter over an explicit clock (tests use
    /// `governor::clock::FakeRelativeClock`).
    pub fn with_clock(limits: &RateLimits, clock: C) -> Self {
        let bucket = |per_minute: u32| {
            // Config validation rejects zero quotas; a zero here can only come
            // from a hand-built `RateLimits`, and one per minute is the
            // strictest meaningful fallback.
            let n = NonZeroU32::new(per_minute).unwrap_or(NonZeroU32::MIN);
            Direct::direct_with_clock(Quota::per_minute(n), clock.clone())
        };
        RateLimiter {
            ping_sync: bucket(limits.ping_sync_per_min),
            get: bucket(limits.get_commands_per_min),
            fsfreeze_freeze: bucket(limits.fsfreeze_freeze_per_min),
            fstrim: bucket(limits.fstrim_per_min),
            shutdown: bucket(limits.shutdown_per_min),
        }
    }

    /// Consumes one token from the class's bucket, or reports denial.
    pub fn check(&self, class: CommandClass) -> Result<(), RateLimited> {
        let bucket = match class {
            CommandClass::PingSync => &self.ping_sync,
            CommandClass::Get => &self.get,
            CommandClass::FsfreezeFreeze => &self.fsfreeze_freeze,
            CommandClass::Fstrim => &self.fstrim,
            CommandClass::Shutdown => &self.shutdown,
            CommandClass::Unlimited => return Ok(()),
        };
        bucket.check().map_err(|_| RateLimited { class })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use governor::clock::FakeRelativeClock;
    use std::time::Duration;

    fn limiter() -> (RateLimiter<FakeRelativeClock>, FakeRelativeClock) {
        let clock = FakeRelativeClock::default();
        (
            RateLimiter::with_clock(&RateLimits::default(), clock.clone()),
            clock,
        )
    }

    const LIMITED: [(CommandClass, u32); 5] = [
        (CommandClass::PingSync, 120),
        (CommandClass::Get, 30),
        (CommandClass::FsfreezeFreeze, 10),
        (CommandClass::Fstrim, 5),
        (CommandClass::Shutdown, 2),
    ];

    #[test]
    fn classify_every_allowlisted_method() {
        let table = [
            ("guest-ping", Some(CommandClass::PingSync)),
            ("guest-sync", Some(CommandClass::PingSync)),
            ("guest-sync-delimited", Some(CommandClass::PingSync)),
            ("guest-info", Some(CommandClass::PingSync)),
            ("guest-get-osinfo", Some(CommandClass::Get)),
            ("guest-get-fsinfo", Some(CommandClass::Get)),
            ("guest-network-get-interfaces", Some(CommandClass::Get)),
            ("guest-fsfreeze-freeze", Some(CommandClass::FsfreezeFreeze)),
            (
                "guest-fsfreeze-freeze-list",
                Some(CommandClass::FsfreezeFreeze),
            ),
            ("guest-fsfreeze-status", Some(CommandClass::Unlimited)),
            ("guest-fsfreeze-thaw", Some(CommandClass::Unlimited)),
            ("guest-fstrim", Some(CommandClass::Fstrim)),
            ("guest-shutdown", Some(CommandClass::Shutdown)),
            ("guest-suspend-ram", Some(CommandClass::Shutdown)),
            ("guest-exec", None),
            ("guest-get-time", None),
            ("guest-network-get-route", None),
            ("", None),
            ("GUEST-PING", None),
        ];
        for (method, class) in table {
            assert_eq!(CommandClass::of(method), class, "{method}");
        }
    }

    #[test]
    fn quota_allows_n_then_denies() {
        for (class, quota) in LIMITED {
            let (limiter, _clock) = limiter();
            assert_eq!(class.quota(&RateLimits::default()), Some(quota));
            for i in 0..quota {
                assert_eq!(limiter.check(class), Ok(()), "{class:?} call {i}");
            }
            let denied = limiter.check(class).unwrap_err();
            assert_eq!(denied, RateLimited { class });
            assert_eq!(
                denied.to_string(),
                format!("rate limit exceeded for {}", class.name())
            );
            let err: crate::proto::Error = denied.into();
            assert_eq!(
                err,
                crate::proto::Error::RateLimited {
                    class: class.name().to_owned()
                }
            );
        }
    }

    #[test]
    fn unlimited_class_never_denies() {
        let (limiter, _clock) = limiter();
        assert_eq!(CommandClass::Unlimited.quota(&RateLimits::default()), None);
        for _ in 0..100_000 {
            assert_eq!(limiter.check(CommandClass::Unlimited), Ok(()));
        }
    }

    #[test]
    fn tokens_refill_over_time() {
        for (class, quota) in LIMITED {
            let (limiter, clock) = limiter();
            for _ in 0..quota {
                limiter.check(class).unwrap();
            }
            assert!(limiter.check(class).is_err());
            // Just under one replenish interval: still denied.
            let interval = Duration::from_secs(60) / quota;
            clock.advance(interval - Duration::from_millis(1));
            assert!(limiter.check(class).is_err(), "{class:?}");
            // At the interval: exactly one more.
            clock.advance(Duration::from_millis(1));
            assert_eq!(limiter.check(class), Ok(()), "{class:?}");
            assert!(limiter.check(class).is_err(), "{class:?}");
            // A full minute restores the whole burst.
            clock.advance(Duration::from_secs(60));
            for i in 0..quota {
                assert_eq!(limiter.check(class), Ok(()), "{class:?} call {i}");
            }
            assert!(limiter.check(class).is_err());
        }
    }

    #[test]
    fn classes_have_independent_buckets() {
        let (limiter, _clock) = limiter();
        for _ in 0..120 {
            limiter.check(CommandClass::PingSync).unwrap();
        }
        assert!(limiter.check(CommandClass::PingSync).is_err());
        for _ in 0..30 {
            assert_eq!(limiter.check(CommandClass::Get), Ok(()));
        }
        assert!(limiter.check(CommandClass::Get).is_err());
        assert_eq!(limiter.check(CommandClass::Shutdown), Ok(()));
        assert_eq!(limiter.check(CommandClass::Unlimited), Ok(()));
    }

    #[test]
    fn flood_of_1000_pings_in_one_second_is_limited() {
        // A single write of 1000 pings is processed faster than one refill
        // interval (500 ms): exactly the burst gets through.
        let (limiter, clock) = limiter();
        let denied = (0..1000)
            .filter(|_| limiter.check(CommandClass::PingSync).is_err())
            .count();
        assert_eq!(denied, 880);
        // The limiter recovers: a minute later the full burst is back.
        clock.advance(Duration::from_secs(60));
        for _ in 0..120 {
            assert_eq!(limiter.check(CommandClass::PingSync), Ok(()));
        }

        // Spread evenly over the whole second, GCRA refills one token per
        // 500 ms, so at most two extra pings are admitted.
        let (spread, clock) = self::limiter();
        let step = Duration::from_secs(1) / 1000;
        let mut denied = 0;
        for _ in 0..1000 {
            if spread.check(CommandClass::PingSync).is_err() {
                denied += 1;
            }
            clock.advance(step);
        }
        assert!((878..=880).contains(&denied), "denied {denied}");
    }

    #[test]
    fn configured_quotas_are_honoured() {
        let limits = RateLimits {
            ping_sync_per_min: 3,
            get_commands_per_min: 1,
            fsfreeze_freeze_per_min: 2,
            fstrim_per_min: 1,
            shutdown_per_min: 1,
        };
        let limiter = RateLimiter::with_clock(&limits, FakeRelativeClock::default());
        for _ in 0..3 {
            limiter.check(CommandClass::PingSync).unwrap();
        }
        assert!(limiter.check(CommandClass::PingSync).is_err());
        limiter.check(CommandClass::Get).unwrap();
        assert!(limiter.check(CommandClass::Get).is_err());
    }

    #[test]
    fn limiter_is_send_and_sync_and_real_clock_constructor_works() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RateLimiter>();
        assert_send_sync::<RateLimiter<FakeRelativeClock>>();
        let real = RateLimiter::new(&RateLimits::default());
        assert_eq!(real.check(CommandClass::Shutdown), Ok(()));
        assert_eq!(real.check(CommandClass::Shutdown), Ok(()));
        assert!(real.check(CommandClass::Shutdown).is_err());
        assert_eq!(format!("{real:?}"), "RateLimiter");
    }
}
