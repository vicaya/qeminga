//! Request dispatch: the static allowlist, the gates, and the rate limiter
//! (design §4.3, §5.1, §5.3, §9; AC1, AC9; C-2, C-7).
//!
//! Order of evaluation for every frame (C-7):
//!
//! 1. parse ([`crate::proto::parse_request`], bounds first);
//! 2. allowlist ([`is_allowlisted`], a `match` on the method string);
//! 3. runtime feature gate (`guest-fstrim`, `guest-suspend-ram` may be
//!    disabled by configuration → `CommandNotFound`, C-2);
//! 4. rate limiter ([`ratelimit`]);
//! 5. freeze gate ([`is_frozen_safe`]; anything else is rejected while the
//!    state is not `Thawed`, AC9);
//! 6. the handler, chosen by a static `match` (§5.1). There is no lookup
//!    table, registry, or plugin mechanism.
//!
//! Every received frame produces exactly one audit record (§9), emitted
//! before the handler runs so that a `guest-shutdown` record precedes the
//! reboot.
#![forbid(unsafe_code)]

pub mod ratelimit;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

use crate::audit::{AuditRecord, Disposition, Router, project_method};
use crate::config::Config;
use crate::framing::{DecodeEvent, encode};
use crate::handlers;
use crate::proto::{Error, Request, Response, parse_request};
use crate::state::FreezeStateMachine;
use ratelimit::{CommandClass, RateLimiter};

/// `true` for the commands in the design §3 allowlist.
///
/// A `match`, not a table lookup (§5.1); the consistency test keeps it in
/// step with [`handlers::SUPPORTED_COMMANDS`].
pub fn is_allowlisted(method: &str) -> bool {
    matches!(
        method,
        "guest-ping"
            | "guest-info"
            | "guest-sync"
            | "guest-sync-delimited"
            | "guest-get-osinfo"
            | "guest-network-get-interfaces"
            | "guest-get-fsinfo"
            | "guest-fsfreeze-status"
            | "guest-fsfreeze-freeze"
            | "guest-fsfreeze-freeze-list"
            | "guest-fsfreeze-thaw"
            | "guest-fstrim"
            | "guest-shutdown"
            | "guest-suspend-ram"
    )
}

/// `true` for the six commands accepted while filesystems are frozen
/// (§5.3): status, thaw, ping, sync, sync-delimited, info.
pub fn is_frozen_safe(method: &str) -> bool {
    matches!(
        method,
        "guest-fsfreeze-status"
            | "guest-fsfreeze-thaw"
            | "guest-ping"
            | "guest-sync"
            | "guest-sync-delimited"
            | "guest-info"
    )
}

/// Audit `reason` values for denied frames.
pub mod reason {
    /// The frame exceeded the frame length bound (AC4).
    pub const OVERSIZED_FRAME: &str = "oversized_frame";
    /// The frame was not a valid request (bounds, JSON, or schema).
    pub const PARSE_ERROR: &str = "parse_error";
    /// The method is not allowlisted (AC1).
    pub const COMMAND_NOT_FOUND: &str = "command_not_found";
    /// The method is allowlisted but disabled by configuration.
    pub const DISABLED: &str = "disabled";
    /// The class's token bucket was empty (AC5).
    pub const RATE_LIMITED: &str = "rate_limited";
    /// The method is not frozen-safe and filesystems are frozen (AC9).
    pub const FROZEN: &str = "frozen";
}

/// Everything handlers need, shared behind an `Arc`. Tests build it with
/// fakes; later tasks add the kernel shim and information sources.
pub struct Context {
    /// Validated configuration.
    pub config: Arc<Config>,
    /// The freeze state machine (C-6).
    pub state: Arc<FreezeStateMachine>,
    /// The audit router (ring/normal mode switch, §9.1).
    pub audit: Router,
    handler_calls: AtomicU64,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Context")
            .field("state", &self.state.current())
            .field("audit", &self.audit)
            .finish_non_exhaustive()
    }
}

impl Context {
    /// Builds a context from its parts.
    pub fn new(config: Arc<Config>, state: Arc<FreezeStateMachine>, audit: Router) -> Self {
        Context {
            config,
            state,
            audit,
            handler_calls: AtomicU64::new(0),
        }
    }

    /// Number of times a handler was invoked (gates passed).
    pub fn handler_calls(&self) -> u64 {
        self.handler_calls.load(Ordering::SeqCst)
    }

    /// A context with default configuration, a thawed state machine, and
    /// an audit router that discards output.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
        )
    }
}

/// The dispatcher: gates plus the static `match`.
#[derive(Debug)]
pub struct Dispatcher {
    ctx: Arc<Context>,
    limiter: RateLimiter,
}

impl Dispatcher {
    /// Builds a dispatcher whose limiter is configured from `ctx.config`.
    pub fn new(ctx: Arc<Context>) -> Self {
        let limiter = RateLimiter::new(&ctx.config.rate_limits);
        Dispatcher { ctx, limiter }
    }

    /// The shared context.
    pub fn context(&self) -> &Arc<Context> {
        &self.ctx
    }

    /// Handles one decoder event and returns the encoded reply, if any.
    ///
    /// `None` is returned for an oversized frame (nothing to reply to) and
    /// for a successful `guest-shutdown` (`success-response: false`).
    pub async fn handle(&self, event: DecodeEvent) -> Option<Vec<u8>> {
        let freeze_state_before = self.ctx.state.current().as_str();
        let bytes = match event {
            DecodeEvent::Oversized { discarded } => {
                AuditRecord {
                    method: project_method(""),
                    id: None,
                    disposition: Disposition::Denied,
                    reason: Some(reason::OVERSIZED_FRAME),
                    freeze_state_before,
                }
                .emit();
                tracing::warn!(event = "oversized_frame", discarded, "frame discarded");
                return None;
            }
            DecodeEvent::Frame { bytes, .. } => bytes,
        };

        let req = match parse_request(&bytes) {
            Ok(req) => req,
            Err(err) => {
                AuditRecord {
                    method: project_method(""),
                    id: None,
                    disposition: Disposition::Denied,
                    reason: Some(reason::PARSE_ERROR),
                    freeze_state_before,
                }
                .emit();
                return Some(encode(&Response::error(None, &err).to_json(), false));
            }
        };

        let result = match self.gates(&req) {
            Ok(()) => {
                AuditRecord {
                    method: project_method(&req.method),
                    id: req.id,
                    disposition: Disposition::Allowed,
                    reason: None,
                    freeze_state_before,
                }
                .emit();
                self.run_handler(&req).await
            }
            Err((denial, err)) => {
                AuditRecord {
                    method: project_method(&req.method),
                    id: req.id,
                    disposition: Disposition::Denied,
                    reason: Some(denial),
                    freeze_state_before,
                }
                .emit();
                Err(err)
            }
        };

        let suppress_success = handlers::spec(&req.method).is_some_and(|s| !s.success_response);
        if result.is_ok() && suppress_success {
            return None;
        }
        // Every reply to `guest-sync-delimited` (success or error) carries
        // the sentinel so a client that is resynchronising can find it (C-10).
        let sentinel = req.method == "guest-sync-delimited";
        Some(encode(
            &Response::from_result(req.id, result).to_json(),
            sentinel,
        ))
    }

    /// Steps 2–5 of the dispatch order (C-7). On denial returns the audit
    /// reason together with the wire error.
    fn gates(&self, req: &Request) -> Result<(), (&'static str, Error)> {
        let method = req.method.as_str();
        if !is_allowlisted(method) {
            return Err((
                reason::COMMAND_NOT_FOUND,
                Error::CommandNotFound(method.to_owned()),
            ));
        }
        self.runtime_feature_gate(method)
            .map_err(|err| (reason::DISABLED, err))?;
        // Every allowlisted method has a class; treat the impossible `None`
        // as the strictest class rather than skipping the limiter.
        let class = CommandClass::of(method).unwrap_or(CommandClass::Shutdown);
        self.limiter
            .check(class)
            .map_err(|err| (reason::RATE_LIMITED, Error::from(err)))?;
        if self.ctx.state.is_frozen_for_gate() && !is_frozen_safe(method) {
            return Err((reason::FROZEN, Error::Frozen));
        }
        Ok(())
    }

    /// Runtime half of the two-level feature switches (§8.1, C-2).
    fn runtime_feature_gate(&self, method: &str) -> Result<(), Error> {
        let config = &self.ctx.config;
        match method {
            "guest-fstrim" if !config.fstrim_enabled() => Err(Error::Disabled(method.to_owned())),
            "guest-suspend-ram" if !config.suspend_ram_enabled() => {
                Err(Error::Disabled(method.to_owned()))
            }
            _ => Ok(()),
        }
    }

    /// Step 6: the static allowlist `match` (§5.1). Handlers that later
    /// tasks implement return `Internal("not implemented")` from their own
    /// arm; nothing is looked up in a table.
    async fn run_handler(&self, req: &Request) -> Result<Value, Error> {
        self.ctx.handler_calls.fetch_add(1, Ordering::SeqCst);
        let ctx = &*self.ctx;
        match req.method.as_str() {
            "guest-ping" => handlers::ping::handle(ctx, req).await,
            "guest-info" => not_implemented(),
            "guest-sync" => handlers::sync::sync(ctx, req).await,
            "guest-sync-delimited" => handlers::sync::sync_delimited(ctx, req).await,
            "guest-get-osinfo" => not_implemented(),
            "guest-network-get-interfaces" => not_implemented(),
            "guest-get-fsinfo" => not_implemented(),
            "guest-fsfreeze-status" => not_implemented(),
            "guest-fsfreeze-freeze" => not_implemented(),
            "guest-fsfreeze-freeze-list" => not_implemented(),
            "guest-fsfreeze-thaw" => not_implemented(),
            "guest-fstrim" => not_implemented(),
            // Placeholder until T4.2: a successful shutdown produces no
            // reply (AC12), which is what this arm exercises.
            "guest-shutdown" => Ok(json!({})),
            "guest-suspend-ram" => not_implemented(),
            other => Err(Error::CommandNotFound(other.to_owned())),
        }
    }
}

fn not_implemented() -> Result<Value, Error> {
    Err(Error::Internal("not implemented".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit;
    use crate::framing::MAX_FRAME_LEN;
    use crate::state::FreezeState;
    use std::io::Write;
    use std::sync::Mutex;
    use tracing::Level;
    use tracing::instrument::WithSubscriber;

    /// The §2.3 denied-command table.
    const DENIED: &[&str] = &[
        "guest-exec",
        "guest-exec-status",
        "guest-file-open",
        "guest-file-read",
        "guest-file-write",
        "guest-file-close",
        "guest-file-seek",
        "guest-file-flush",
        "guest-set-user-password",
        "guest-ssh-add-authorized-keys",
        "guest-ssh-remove-authorized-keys",
        "guest-ssh-get-authorized-keys",
        "guest-set-time",
        "guest-set-vcpus",
        "guest-set-memory-blocks",
        "guest-suspend-disk",
        "guest-suspend-hybrid",
        "guest-get-users",
        "guest-get-host-name",
        "guest-get-time",
        "guest-get-timezone",
        "guest-get-devices",
        "guest-get-disks",
        "guest-get-diskstats",
        "guest-get-cpustats",
        "guest-get-load",
        "guest-get-vcpus",
        "guest-get-memory-blocks",
        "guest-get-memory-block-info",
        "guest-network-get-route",
    ];

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl SharedSink {
        fn lines(&self) -> Vec<Value> {
            let bytes = self.0.lock().unwrap().clone();
            String::from_utf8(bytes)
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Harness {
        dispatcher: Dispatcher,
        sink: SharedSink,
    }

    impl Harness {
        fn new(state: FreezeState, config: Config) -> Self {
            let sink = SharedSink::default();
            let router = Router::new(Box::new(sink.clone()));
            let ctx = Context::new(
                Arc::new(config),
                Arc::new(FreezeStateMachine::starting_in(state)),
                router,
            );
            Harness {
                dispatcher: Dispatcher::new(Arc::new(ctx)),
                sink,
            }
        }

        fn thawed() -> Self {
            Self::new(FreezeState::Thawed, Config::default())
        }

        fn ctx(&self) -> &Context {
            self.dispatcher.context()
        }

        async fn send(&self, frame: &[u8]) -> Option<Vec<u8>> {
            let router = self.ctx().audit.clone();
            self.dispatcher
                .handle(DecodeEvent::Frame {
                    bytes: frame.to_vec(),
                    sentinel: false,
                })
                .with_subscriber(audit::subscriber(Level::TRACE, router))
                .await
        }

        async fn send_json(&self, frame: &[u8]) -> Value {
            let reply = self.send(frame).await.expect("expected a reply");
            assert_eq!(reply.last(), Some(&b'\n'));
            let body = reply.strip_prefix(&[0xFF]).unwrap_or(&reply);
            serde_json::from_slice(&body[..body.len() - 1]).unwrap()
        }

        async fn execute(&self, method: &str) -> Value {
            self.send_json(format!(r#"{{"execute":"{method}"}}"#).as_bytes())
                .await
        }

        fn audit_records(&self) -> Vec<Value> {
            self.sink
                .lines()
                .into_iter()
                .filter(|l| l["event"] == audit::EVENT_COMMAND_RECEIVED)
                .collect()
        }
    }

    fn error_class(reply: &Value) -> &str {
        reply["error"]["class"].as_str().unwrap()
    }

    fn error_desc(reply: &Value) -> &str {
        reply["error"]["desc"].as_str().unwrap()
    }

    #[tokio::test]
    async fn every_denied_command_in_design_table_returns_command_not_found() {
        let h = Harness::thawed();
        for method in DENIED {
            assert!(!is_allowlisted(method), "{method}");
            let reply = h.execute(method).await;
            assert_eq!(error_class(&reply), "CommandNotFound", "{method}");
            assert_eq!(
                error_desc(&reply),
                format!("The command {method} has not been found")
            );
        }
        assert_eq!(
            h.ctx().handler_calls(),
            0,
            "denied commands never reach a handler"
        );
        let records = h.audit_records();
        assert_eq!(records.len(), DENIED.len());
        for record in records {
            assert_eq!(record["disposition"], "denied");
            assert_eq!(record["reason"], reason::COMMAND_NOT_FOUND);
        }
    }

    #[tokio::test]
    async fn unknown_method_returns_command_not_found() {
        let h = Harness::thawed();
        for method in ["", "ping", "GUEST-PING", "guest-ping ", "guest-pingx"] {
            let reply = h.execute(method).await;
            assert_eq!(error_class(&reply), "CommandNotFound", "{method:?}");
        }
        // A method longer than 64 bytes is projected in the audit record.
        let long = "guest-".to_owned() + &"x".repeat(100);
        let reply = h.execute(&long).await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        let record = h.audit_records().pop().unwrap();
        assert!(record.get("method").is_none());
        assert_eq!(record["method_len_bytes"], 106);
        assert_eq!(h.ctx().handler_calls(), 0);
    }

    #[tokio::test]
    async fn ping_returns_empty_object() {
        let h = Harness::thawed();
        let reply = h.send(br#"{"execute":"guest-ping"}"#).await.unwrap();
        assert_eq!(reply, b"{\"return\":{}}\n");
        let reply = h.send_json(br#"{"execute":"guest-ping","id":9}"#).await;
        assert_eq!(reply, json!({"return": {}, "id": 9}));
        assert_eq!(h.ctx().handler_calls(), 2);
    }

    #[tokio::test]
    async fn frozen_gate_rejects_non_safe_commands_with_exact_desc() {
        for state in [
            FreezeState::Frozen,
            FreezeState::Freezing,
            FreezeState::Thawing,
        ] {
            let h = Harness::new(state, Config::default());
            for method in [
                "guest-get-osinfo",
                "guest-get-fsinfo",
                "guest-network-get-interfaces",
                "guest-fsfreeze-freeze",
                "guest-fsfreeze-freeze-list",
                "guest-fstrim",
                "guest-shutdown",
                "guest-suspend-ram",
            ] {
                let reply = h.execute(method).await;
                if method == "guest-suspend-ram" && !h.ctx().config.suspend_ram_enabled() {
                    // The runtime gate precedes the freeze gate (C-7).
                    assert_eq!(error_class(&reply), "CommandNotFound", "{state} {method}");
                    continue;
                }
                assert_eq!(error_class(&reply), "GenericError", "{state} {method}");
                assert_eq!(
                    error_desc(&reply),
                    "filesystems are frozen; retry after thaw",
                    "{state} {method}"
                );
            }
            assert_eq!(h.ctx().handler_calls(), 0, "{state}: no handler ran");
            let records = h.audit_records();
            assert!(!records.is_empty());
            for record in records.iter().filter(|r| r["reason"] == reason::FROZEN) {
                assert_eq!(record["disposition"], "denied");
                assert_eq!(record["freeze_state_before"], state.as_str());
            }
        }
    }

    #[tokio::test]
    async fn frozen_safe_set_is_exactly_six() {
        let safe: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .map(|s| s.name)
            .filter(|name| is_frozen_safe(name))
            .collect();
        assert_eq!(
            safe,
            [
                "guest-ping",
                "guest-info",
                "guest-sync",
                "guest-sync-delimited",
                "guest-fsfreeze-status",
                "guest-fsfreeze-thaw",
            ]
        );
        assert!(!is_frozen_safe("guest-exec"));
        let h = Harness::new(FreezeState::Frozen, Config::default());
        for method in &safe {
            let reply = h.execute(method).await;
            assert_ne!(
                error_desc_opt(&reply),
                Some("filesystems are frozen; retry after thaw"),
                "{method} must pass the gate"
            );
        }
        assert_eq!(h.ctx().handler_calls(), safe.len() as u64);
    }

    fn error_desc_opt(reply: &Value) -> Option<&str> {
        reply.get("error").and_then(|e| e["desc"].as_str())
    }

    #[tokio::test]
    async fn rate_limited_request_returns_generic_error() {
        let h = Harness::thawed();
        for _ in 0..120 {
            assert_eq!(h.execute("guest-ping").await, json!({"return": {}}));
        }
        let reply = h.execute("guest-ping").await;
        assert_eq!(error_class(&reply), "GenericError");
        assert_eq!(error_desc(&reply), "rate limit exceeded for ping_sync");
        let record = h.audit_records().pop().unwrap();
        assert_eq!(record["disposition"], "denied");
        assert_eq!(record["reason"], reason::RATE_LIMITED);
        assert_eq!(h.ctx().handler_calls(), 120);
    }

    #[tokio::test]
    async fn thaw_is_never_rate_limited_even_after_flood() {
        let h = Harness::new(FreezeState::Frozen, Config::default());
        for _ in 0..1000 {
            h.execute("guest-ping").await;
        }
        for _ in 0..1000 {
            let reply = h.execute("guest-fsfreeze-thaw").await;
            // The handler is a placeholder; the point is that neither the
            // limiter nor the freeze gate rejected it.
            assert_ne!(
                error_desc_opt(&reply),
                Some("rate limit exceeded for unlimited")
            );
            assert_ne!(
                error_desc_opt(&reply),
                Some("filesystems are frozen; retry after thaw")
            );
            let reply = h.execute("guest-fsfreeze-status").await;
            assert_ne!(
                error_desc_opt(&reply),
                Some("rate limit exceeded for unlimited")
            );
        }
        assert_eq!(h.ctx().handler_calls(), 120 + 2000);
    }

    #[tokio::test]
    async fn disabled_fstrim_returns_command_not_found_with_disabled_desc() {
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let h = Harness::new(FreezeState::Thawed, config);
        let reply = h.execute("guest-fstrim").await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        assert_eq!(error_desc(&reply), "command guest-fstrim has been disabled");
        assert_eq!(h.ctx().handler_calls(), 0);
        let record = h.audit_records().pop().unwrap();
        assert_eq!(record["reason"], reason::DISABLED);

        // Enabled: reaches the (placeholder) handler.
        let h = Harness::thawed();
        let reply = h.execute("guest-fstrim").await;
        assert_eq!(error_desc(&reply), "not implemented");
        assert_eq!(h.ctx().handler_calls(), 1);

        // suspend-ram: disabled by default at runtime regardless of build.
        let h = Harness::thawed();
        let reply = h.execute("guest-suspend-ram").await;
        assert_eq!(error_class(&reply), "CommandNotFound");
        assert_eq!(
            error_desc(&reply),
            "command guest-suspend-ram has been disabled"
        );
    }

    #[tokio::test]
    async fn parse_error_returns_generic_error_and_no_panic() {
        let h = Harness::thawed();
        for frame in [
            &b"garbage"[..],
            b"{",
            b"[\"guest-ping\"]",
            b"{\"execute\":\"guest-ping\",\"id\":\"x\"}",
            b"{\"execute\":\"guest-ping\"} trailing",
            b"\xff\xfe",
            b"{\"execute\":\"\xff\"}",
        ] {
            let reply = h.send_json(frame).await;
            assert_eq!(error_class(&reply), "GenericError", "{frame:?}");
            assert!(reply.get("id").is_none());
        }
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        let reply = h.send_json(deep.as_bytes()).await;
        assert_eq!(error_class(&reply), "GenericError");

        let none = h
            .dispatcher
            .handle(DecodeEvent::Oversized {
                discarded: MAX_FRAME_LEN + 1,
            })
            .await;
        assert!(none.is_none(), "an oversized frame gets no reply");
        assert_eq!(h.ctx().handler_calls(), 0);
    }

    #[tokio::test]
    async fn oversized_event_is_audited_as_denied_without_reply() {
        let h = Harness::thawed();
        let router = h.ctx().audit.clone();
        let reply = h
            .dispatcher
            .handle(DecodeEvent::Oversized { discarded: 70_000 })
            .with_subscriber(audit::subscriber(Level::TRACE, router))
            .await;
        assert!(reply.is_none());
        let records = h.audit_records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["disposition"], "denied");
        assert_eq!(records[0]["reason"], reason::OVERSIZED_FRAME);
        assert_eq!(records[0]["freeze_state_before"], "thawed");
    }

    #[tokio::test]
    async fn every_request_emits_one_audit_record_with_disposition() {
        let h = Harness::thawed();
        h.send(br#"{"execute":"guest-ping","id":1}"#).await;
        h.send(br#"{"execute":"guest-exec","id":2}"#).await;
        h.send(b"not json").await;
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let frozen = Harness::new(FreezeState::Frozen, config);
        frozen
            .send(br#"{"execute":"guest-get-osinfo","id":3}"#)
            .await;
        frozen.send(br#"{"execute":"guest-fstrim","id":4}"#).await;
        frozen
            .send(br#"{"execute":"guest-fsfreeze-thaw","id":5}"#)
            .await;

        let mut records = h.audit_records();
        records.extend(frozen.audit_records());
        assert_eq!(records.len(), 6);
        let expect = [
            (Some(1), "allowed", None, "thawed"),
            (Some(2), "denied", Some(reason::COMMAND_NOT_FOUND), "thawed"),
            (None, "denied", Some(reason::PARSE_ERROR), "thawed"),
            (Some(3), "denied", Some(reason::FROZEN), "frozen"),
            (Some(4), "denied", Some(reason::DISABLED), "frozen"),
            (Some(5), "allowed", None, "frozen"),
        ];
        for (record, (id, disposition, reason, state)) in records.iter().zip(expect) {
            assert_eq!(record["event"], audit::EVENT_COMMAND_RECEIVED);
            assert_eq!(record["id"].as_i64(), id, "{record}");
            assert_eq!(record["disposition"], disposition, "{record}");
            assert_eq!(
                record.get("reason").and_then(Value::as_str),
                reason,
                "{record}"
            );
            assert_eq!(record["freeze_state_before"], state, "{record}");
            assert_eq!(
                record["level"],
                if disposition == "allowed" {
                    "INFO"
                } else {
                    "WARN"
                }
            );
        }
    }

    #[tokio::test]
    async fn sync_delimited_reply_starts_with_0xff() {
        let h = Harness::thawed();
        // Without a sentinel on the request frame.
        let reply = h
            .send(br#"{"execute":"guest-sync-delimited","arguments":{"id":1}}"#)
            .await
            .unwrap();
        assert_eq!(reply[0], 0xFF);
        assert_eq!(&reply[1..], b"{\"return\":1}\n");
        // With one.
        let router = h.ctx().audit.clone();
        let reply = h
            .dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-sync-delimited","arguments":{"id":2},"id":7}"#
                    .to_vec(),
                sentinel: true,
            })
            .with_subscriber(audit::subscriber(Level::TRACE, router))
            .await
            .unwrap();
        assert_eq!(&reply[..2], b"\xff{");
        assert_eq!(&reply[1..], b"{\"return\":2,\"id\":7}\n");
        // Errors for that method carry it too; other methods never do.
        let reply = h
            .send(br#"{"execute":"guest-sync-delimited"}"#)
            .await
            .unwrap();
        assert_eq!(reply[0], 0xFF);
        assert!(reply[1..].starts_with(b"{\"error\""));
        let reply = h
            .send(br#"{"execute":"guest-sync","arguments":{"id":1}}"#)
            .await
            .unwrap();
        assert_eq!(reply, b"{\"return\":1}\n");
    }

    #[tokio::test]
    async fn shutdown_success_yields_no_response() {
        let h = Harness::thawed();
        assert!(
            h.send(br#"{"execute":"guest-shutdown","id":1}"#)
                .await
                .is_none()
        );
        assert_eq!(h.ctx().handler_calls(), 1);
        assert_eq!(h.audit_records().len(), 1);
        // Errors are still reported (rate limit: 2/min).
        h.send(br#"{"execute":"guest-shutdown"}"#).await;
        let reply = h.execute("guest-shutdown").await;
        assert_eq!(error_class(&reply), "GenericError");
        assert_eq!(error_desc(&reply), "rate limit exceeded for shutdown");
        // While frozen the gate error is reported too.
        let frozen = Harness::new(FreezeState::Frozen, Config::default());
        let reply = frozen.execute("guest-shutdown").await;
        assert_eq!(
            error_desc(&reply),
            "filesystems are frozen; retry after thaw"
        );
    }

    #[tokio::test]
    async fn supported_command_table_and_match_arms_agree() {
        let config = Config::parse("[features]\nfstrim = true\nsuspend_ram = true\n").unwrap();
        let enabled_suspend = config.suspend_ram_enabled();
        let h = Harness::new(FreezeState::Thawed, config);
        let mut names: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .map(|s| s.name)
            .collect();
        for name in &names {
            assert!(
                is_allowlisted(name),
                "{name} in table but not in allowlist match"
            );
            assert!(
                CommandClass::of(name).is_some(),
                "{name} has no rate-limit class"
            );
            let Some(reply) = h
                .send(format!(r#"{{"execute":"{name}"}}"#).as_bytes())
                .await
            else {
                assert_eq!(*name, "guest-shutdown", "only shutdown is silent");
                continue;
            };
            let body = reply.strip_prefix(&[0xFF]).unwrap_or(&reply);
            let reply: Value = serde_json::from_slice(&body[..body.len() - 1]).unwrap();
            let class = reply
                .get("error")
                .map(|e| e["class"].as_str().unwrap().to_owned());
            if *name == "guest-suspend-ram" && !enabled_suspend {
                assert_eq!(class.as_deref(), Some("CommandNotFound"));
            } else {
                assert_ne!(class.as_deref(), Some("CommandNotFound"), "{name}");
            }
        }
        // Each name appears exactly once and `guest-shutdown` is the only
        // command without a success response.
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count);
        assert_eq!(count, 14);
        let no_success: Vec<&str> = handlers::SUPPORTED_COMMANDS
            .iter()
            .filter(|s| !s.success_response)
            .map(|s| s.name)
            .collect();
        assert_eq!(no_success, ["guest-shutdown"]);
        // Every match arm's name is in the table: probing the arms with a
        // method that is allowlisted but absent from the table is impossible
        // by construction, so check the inverse direction on the allowlist.
        for method in DENIED {
            assert!(handlers::spec(method).is_none());
        }
    }
}
