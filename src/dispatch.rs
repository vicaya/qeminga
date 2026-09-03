//! Request dispatch: the static allowlist, the gates, and the rate limiter
//! (design §4.3, §5.1, §5.3).
//!
//! The dispatcher itself is added by T1.8; this module currently hosts the
//! per-class token-bucket limiter ([`ratelimit`]).
#![forbid(unsafe_code)]

pub mod ratelimit;
