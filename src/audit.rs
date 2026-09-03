//! Audit records, method projection, and the freeze-safe log ring
//! (design §4.1 Logging, §5.2, §9, §9.1; G7; AC13).
//!
//! Every received command produces exactly one [`AuditRecord`], emitted as
//! a structured `tracing` event with flattened fields. The subscriber
//! installed by [`init_tracing`] formats each event as one JSON line and
//! hands it to a [`Router`], which either writes it through to the normal
//! sink (stderr) or, while filesystems are frozen, keeps it in a
//! byte-bounded in-memory [`LineRing`] so no descriptor that might reach a
//! frozen filesystem is written until thaw (§9.1).
//!
//! Attacker-controlled method names are projected by [`project_method`]
//! to at most 64 UTF-8 bytes at a character boundary before they reach a
//! record; longer names are recorded as a prefix, their byte length, and a
//! SHA-256 digest. Field values are always structured, never formatted into
//! a message string.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::FormatTime;

/// Maximum number of method-name bytes recorded verbatim (§5.2).
pub const MAX_METHOD_BYTES: usize = 64;

/// Capacity of the freeze-safe ring in bytes (§9.1).
pub const RING_CAPACITY: usize = 64 * 1024;

/// The `event` value of a per-command audit record (§9).
pub const EVENT_COMMAND_RECEIVED: &str = "command_received";

/// The `event` value of the record that reports ring overflow after thaw.
pub const EVENT_AUDIT_RECORDS_LOST: &str = "audit_records_lost";

/// A method name as it appears in an audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MethodField {
    /// The method was at most [`MAX_METHOD_BYTES`] long and is recorded
    /// verbatim.
    Full(String),
    /// The method was longer; only a bounded prefix, the original length,
    /// and a digest are recorded.
    Projected {
        /// Longest prefix of at most [`MAX_METHOD_BYTES`] bytes that ends
        /// on a character boundary.
        method_prefix: String,
        /// Length of the original method in bytes.
        method_len_bytes: usize,
        /// Lowercase hex SHA-256 of the original method bytes.
        method_digest: String,
    },
}

/// Projects an attacker-controlled method name to a bounded field (§5.2).
pub fn project_method(method: &str) -> MethodField {
    if method.len() <= MAX_METHOD_BYTES {
        return MethodField::Full(method.to_owned());
    }
    let mut cut = MAX_METHOD_BYTES;
    while !method.is_char_boundary(cut) {
        cut -= 1;
    }
    let digest = Sha256::digest(method.as_bytes());
    let mut method_digest = String::with_capacity(64);
    for byte in digest {
        method_digest.push_str(&format!("{byte:02x}"));
    }
    MethodField::Projected {
        method_prefix: method[..cut].to_owned(),
        method_len_bytes: method.len(),
        method_digest,
    }
}

/// Whether a command was accepted for execution or rejected by a gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The command passed every gate and was handed to its handler.
    Allowed,
    /// The command was rejected before reaching a handler.
    Denied,
}

impl Disposition {
    /// Lowercase wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Disposition::Allowed => "allowed",
            Disposition::Denied => "denied",
        }
    }
}

/// One per-command audit record (§9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The (projected) method name.
    pub method: MethodField,
    /// The request id, if the request carried one.
    pub id: Option<i64>,
    /// Allowed or denied.
    pub disposition: Disposition,
    /// Why the command was denied; `None` for allowed commands.
    pub reason: Option<&'static str>,
    /// Freeze state when the command arrived (lowercase).
    pub freeze_state_before: &'static str,
}

impl AuditRecord {
    /// Emits this record as one `tracing` event.
    ///
    /// Denied commands are logged at `WARN`, allowed ones at `INFO`.
    /// `id` and `reason` are omitted from the output when `None`.
    pub fn emit(&self) {
        // `tracing::event!` needs a constant level, hence one arm per
        // (method shape, level) combination.
        match (&self.method, self.disposition) {
            (MethodField::Full(method), Disposition::Allowed) => {
                audit_event!(Level::INFO, self, method = method.as_str(),);
            }
            (MethodField::Full(method), Disposition::Denied) => {
                audit_event!(Level::WARN, self, method = method.as_str(),);
            }
            (
                MethodField::Projected {
                    method_prefix,
                    method_len_bytes,
                    method_digest,
                },
                Disposition::Allowed,
            ) => {
                audit_event!(
                    Level::INFO,
                    self,
                    method_prefix = method_prefix.as_str(),
                    method_len_bytes = *method_len_bytes as u64,
                    method_digest = method_digest.as_str(),
                );
            }
            (
                MethodField::Projected {
                    method_prefix,
                    method_len_bytes,
                    method_digest,
                },
                Disposition::Denied,
            ) => {
                audit_event!(
                    Level::WARN,
                    self,
                    method_prefix = method_prefix.as_str(),
                    method_len_bytes = *method_len_bytes as u64,
                    method_digest = method_digest.as_str(),
                );
            }
        }
    }
}

/// Emits one `command_received` event with the method field(s) given
/// first and the common fields after them. Absent `id`/`reason` values are
/// `None`, which `tracing` omits from the output.
macro_rules! audit_event {
    ($level:expr, $record:expr, $($method_fields:tt)*) => {
        tracing::event!(
            $level,
            event = EVENT_COMMAND_RECEIVED,
            $($method_fields)*
            id = $record.id,
            disposition = $record.disposition.as_str(),
            reason = $record.reason,
            freeze_state_before = $record.freeze_state_before,
        )
    };
}
use audit_event;

/// Emits an audit record (convenience wrapper around [`AuditRecord::emit`]).
pub fn emit(record: &AuditRecord) {
    record.emit();
}

/// A byte-bounded FIFO of whole log lines (§9.1).
///
/// Lines are stored in order. When a push would exceed the capacity the
/// oldest lines are evicted and counted as lost; a single line larger than
/// the whole capacity is dropped and counted as lost.
#[derive(Debug)]
pub struct LineRing {
    capacity: usize,
    used: usize,
    lines: VecDeque<Vec<u8>>,
    lost: u64,
}

impl LineRing {
    /// Creates a ring holding at most `capacity` bytes of lines.
    pub fn with_capacity(capacity: usize) -> Self {
        LineRing {
            capacity,
            used: 0,
            lines: VecDeque::new(),
            lost: 0,
        }
    }

    /// The configured capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Bytes currently held.
    pub fn len(&self) -> usize {
        self.used
    }

    /// `true` when no line is held.
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Lines lost since the last [`drain`](Self::drain).
    pub fn lost(&self) -> u64 {
        self.lost
    }

    /// Stores one line, evicting the oldest lines as needed.
    pub fn push(&mut self, line: &[u8]) {
        if line.len() > self.capacity {
            self.lost = self.lost.saturating_add(1);
            return;
        }
        while self.used.saturating_add(line.len()) > self.capacity {
            match self.lines.pop_front() {
                Some(old) => {
                    self.used -= old.len();
                    self.lost = self.lost.saturating_add(1);
                }
                None => break,
            }
        }
        self.used += line.len();
        self.lines.push_back(line.to_vec());
    }

    /// Removes and returns every held line in order together with the
    /// number of lines lost since the previous drain, and resets both.
    pub fn drain(&mut self) -> (u64, Vec<Vec<u8>>) {
        let lost = std::mem::take(&mut self.lost);
        self.used = 0;
        (lost, self.lines.drain(..).collect())
    }
}

/// Where the router currently sends records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Records are written through to the sink.
    Normal,
    /// Records are held in the ring; the sink is never touched.
    Ring,
}

struct Inner {
    mode: Mode,
    ring: LineRing,
    sink: Box<dyn Write + Send>,
}

/// Routes formatted log lines either to the normal sink or to the ring.
///
/// Cheap to clone (shared state behind an `Arc<Mutex>`); implements
/// [`MakeWriter`] so it can be installed as the subscriber's writer. Each
/// `write` call carries exactly one record because the `fmt` layer writes
/// one line per event.
#[derive(Clone)]
pub struct Router {
    inner: Arc<Mutex<Inner>>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("mode", &self.mode())
            .finish()
    }
}

impl Router {
    /// Creates a router in [`Mode::Normal`] writing to `sink`, with a ring
    /// of [`RING_CAPACITY`] bytes.
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self::with_ring_capacity(sink, RING_CAPACITY)
    }

    /// Creates a router in [`Mode::Normal`] writing to standard error.
    pub fn stderr() -> Self {
        Self::new(Box::new(io::stderr()))
    }

    /// Creates a router with an explicit ring capacity (tests).
    pub fn with_ring_capacity(sink: Box<dyn Write + Send>, capacity: usize) -> Self {
        Router {
            inner: Arc::new(Mutex::new(Inner {
                mode: Mode::Normal,
                ring: LineRing::with_capacity(capacity),
                sink,
            })),
        }
    }

    /// The current mode.
    pub fn mode(&self) -> Mode {
        self.lock().mode
    }

    /// Switches to [`Mode::Ring`]. Synchronous and free of I/O, so it can be
    /// called before the recovery marker and the first `FIFREEZE` (§4.2).
    pub fn enter_ring(&self) {
        self.lock().mode = Mode::Ring;
    }

    /// Flushes the ring to the sink and switches to [`Mode::Normal`].
    ///
    /// If any records were lost, a loss record is written first, then the
    /// buffered records in their original order. Returns the loss count.
    pub fn flush_to_normal(&self) -> u64 {
        let mut inner = self.lock();
        let (lost, lines) = inner.ring.drain();
        if lost > 0 {
            let record = loss_record(lost);
            // Sink failures are deliberately ignored: there is no better
            // place to report them, and blocking here is the hazard §9.1
            // guards against.
            let _ = inner.sink.write_all(record.as_bytes());
        }
        for line in &lines {
            let _ = inner.sink.write_all(line);
        }
        let _ = inner.sink.flush();
        inner.mode = Mode::Normal;
        lost
    }

    /// Number of lines lost since the last flush.
    pub fn lost(&self) -> u64 {
        self.lock().ring.lost()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A poisoned lock only means another thread panicked while holding
        // it; the state is a mode flag and a byte ring, so it is still
        // usable and audit output must not stop.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_record(&self, buf: &[u8]) -> io::Result<usize> {
        let mut inner = self.lock();
        match inner.mode {
            Mode::Ring => inner.ring.push(buf),
            Mode::Normal => {
                let _ = inner.sink.write_all(buf);
            }
        }
        Ok(buf.len())
    }
}

/// Builds the JSON line reporting `lost` dropped records.
fn loss_record(lost: u64) -> String {
    let mut line = serde_json::json!({
        "timestamp": format_utc(SystemTime::now()),
        "level": "WARN",
        "event": EVENT_AUDIT_RECORDS_LOST,
        "lost": lost,
    })
    .to_string();
    line.push('\n');
    line
}

/// The writer handed to the `fmt` layer; forwards each record to its router.
#[derive(Debug, Clone)]
pub struct RouterWriter(Router);

impl Write for RouterWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_record(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Router {
    type Writer = RouterWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RouterWriter(self.clone())
    }
}

/// Formats a `SystemTime` as RFC 3339 UTC with millisecond precision, the
/// shape shown in design §9 (`2026-08-16T20:00:00.000Z`).
pub fn format_utc(time: SystemTime) -> String {
    let since_epoch = time.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = since_epoch.as_secs();
    let millis = since_epoch.subsec_millis();
    let days = secs / 86_400;
    let secs_of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Converts days since 1970-01-01 to a proleptic Gregorian (year, month,
/// day). Howard Hinnant's `civil_from_days`, valid for any `u64` day count
/// that fits the arithmetic below.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// `tracing-subscriber` timer producing [`format_utc`] timestamps.
#[derive(Debug, Clone, Copy, Default)]
pub struct UtcTimestamp;

impl FormatTime for UtcTimestamp {
    fn format_time(&self, w: &mut Writer<'_>) -> std::fmt::Result {
        w.write_str(&format_utc(SystemTime::now()))
    }
}

/// Builds the JSON subscriber used by qeminga: one flattened JSON object
/// per event, written through `router`.
pub fn subscriber(
    level: Level,
    router: Router,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_timer(UtcTimestamp)
        .with_max_level(level)
        .with_writer(router)
        .finish()
}

/// Installs the qeminga subscriber as the global default (called once by
/// `main`).
pub fn init_tracing(level: Level, router: Router) -> Result<(), InitError> {
    tracing::subscriber::set_global_default(subscriber(level, router))
        .map_err(|_| InitError::AlreadyInitialised)
}

/// Failure to install the global subscriber.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InitError {
    /// A global subscriber was already installed.
    #[error("a global tracing subscriber is already installed")]
    AlreadyInitialised,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// A sink that records everything written and counts bytes.
    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl SharedSink {
        fn bytes(&self) -> Vec<u8> {
            self.0.lock().unwrap().clone()
        }
        fn len(&self) -> usize {
            self.0.lock().unwrap().len()
        }
        fn lines(&self) -> Vec<String> {
            String::from_utf8(self.bytes())
                .unwrap()
                .lines()
                .map(str::to_owned)
                .collect()
        }
    }

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn router_over(sink: &SharedSink, capacity: usize) -> Router {
        Router::with_ring_capacity(Box::new(sink.clone()), capacity)
    }

    #[test]
    fn short_method_is_recorded_verbatim() {
        let exactly_64 = "m".repeat(64);
        assert_eq!(
            project_method(&exactly_64),
            MethodField::Full(exactly_64.clone())
        );
        assert_eq!(
            project_method("guest-ping"),
            MethodField::Full("guest-ping".to_owned())
        );
    }

    #[test]
    fn long_method_is_projected_at_char_boundary() {
        // 62 ASCII bytes, then a 4-byte char spanning bytes 62..66, then
        // more: byte 64 falls inside the multi-byte character.
        let method = format!("{}\u{1F512}{}", "a".repeat(62), "b".repeat(4));
        assert_eq!(method.len(), 70);
        let expected_digest = {
            let d = Sha256::digest(method.as_bytes());
            d.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        match project_method(&method) {
            MethodField::Projected {
                method_prefix,
                method_len_bytes,
                method_digest,
            } => {
                assert_eq!(method_prefix, "a".repeat(62));
                assert!(method_prefix.len() <= MAX_METHOD_BYTES);
                assert_eq!(method_len_bytes, 70);
                assert_eq!(method_digest, expected_digest);
                assert_eq!(method_digest.len(), 64);
                assert!(method_digest.bytes().all(|b| b.is_ascii_hexdigit()));
                assert_eq!(method_digest.to_lowercase(), method_digest);
            }
            other => panic!("expected Projected, got {other:?}"),
        }
        // 65 ASCII bytes cut cleanly at 64.
        match project_method(&"x".repeat(65)) {
            MethodField::Projected { method_prefix, .. } => {
                assert_eq!(method_prefix.len(), 64);
            }
            other => panic!("expected Projected, got {other:?}"),
        }
    }

    fn emit_and_parse(record: &AuditRecord) -> Value {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        tracing::subscriber::with_default(subscriber(Level::TRACE, router), || {
            record.emit();
        });
        let lines = sink.lines();
        assert_eq!(lines.len(), 1, "expected one line, got {lines:?}");
        serde_json::from_str(&lines[0]).unwrap()
    }

    #[test]
    fn record_serialises_to_expected_json_keys() {
        let allowed = AuditRecord {
            method: MethodField::Full("guest-fsfreeze-freeze".to_owned()),
            id: Some(42),
            disposition: Disposition::Allowed,
            reason: None,
            freeze_state_before: "thawed",
        };
        let json = emit_and_parse(&allowed);
        let obj = json.as_object().unwrap();
        assert_eq!(obj["level"], "INFO");
        assert_eq!(obj["event"], EVENT_COMMAND_RECEIVED);
        assert_eq!(obj["method"], "guest-fsfreeze-freeze");
        assert_eq!(obj["id"], 42);
        assert_eq!(obj["disposition"], "allowed");
        assert_eq!(obj["freeze_state_before"], "thawed");
        assert!(!obj.contains_key("reason"));
        assert!(!obj.contains_key("message"));
        assert!(!obj.contains_key("fields"));
        let ts = obj["timestamp"].as_str().unwrap();
        assert_eq!(ts.len(), "2026-08-16T20:00:00.000Z".len(), "{ts}");
        assert!(ts.ends_with('Z'));

        let denied = AuditRecord {
            method: project_method(&"guest-exec".repeat(10)),
            id: None,
            disposition: Disposition::Denied,
            reason: Some("command_not_found"),
            freeze_state_before: "frozen",
        };
        let json = emit_and_parse(&denied);
        let obj = json.as_object().unwrap();
        assert_eq!(obj["level"], "WARN");
        assert_eq!(obj["disposition"], "denied");
        assert_eq!(obj["reason"], "command_not_found");
        assert!(!obj.contains_key("id"));
        assert!(!obj.contains_key("method"));
        assert!(obj["method_prefix"].is_string());
        assert_eq!(obj["method_len_bytes"], 100);
        assert_eq!(obj["method_digest"].as_str().unwrap().len(), 64);
        assert_eq!(obj["freeze_state_before"], "frozen");
    }

    #[test]
    fn i64_extremes_survive_the_json_pipeline() {
        for id in [i64::MIN, i64::MAX] {
            let record = AuditRecord {
                method: MethodField::Full("guest-ping".to_owned()),
                id: Some(id),
                disposition: Disposition::Allowed,
                reason: None,
                freeze_state_before: "thawed",
            };
            let json = emit_and_parse(&record);
            assert_eq!(json["id"].as_i64(), Some(id));
        }
    }

    #[test]
    fn method_value_is_a_json_string_never_interpolated() {
        let hostile = "guest-ping\",\"disposition\":\"allowed\",\"x\":\"\n{}";
        let record = AuditRecord {
            method: MethodField::Full(hostile.to_owned()),
            id: None,
            disposition: Disposition::Denied,
            reason: Some("command_not_found"),
            freeze_state_before: "thawed",
        };
        let json = emit_and_parse(&record);
        assert_eq!(json["method"], hostile);
        assert_eq!(json["disposition"], "denied");
        assert!(json.get("x").is_none());
    }

    #[test]
    fn ring_stores_whole_lines_in_order() {
        let mut ring = LineRing::with_capacity(100);
        ring.push(b"one\n");
        ring.push(b"two\n");
        ring.push(b"three\n");
        assert_eq!(ring.len(), 14);
        let (lost, lines) = ring.drain();
        assert_eq!(lost, 0);
        assert_eq!(
            lines,
            vec![b"one\n".to_vec(), b"two\n".to_vec(), b"three\n".to_vec()]
        );
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn ring_evicts_oldest_on_overflow_and_counts_loss() {
        let mut ring = LineRing::with_capacity(10);
        ring.push(b"aaaa"); // 4
        ring.push(b"bbbb"); // 8
        ring.push(b"cccc"); // 12 > 10: evict aaaa -> 8
        assert_eq!(ring.lost(), 1);
        ring.push(b"dddddddd"); // 16 > 10: evict bbbb (12), evict cccc (8)
        assert_eq!(ring.lost(), 3);
        let (lost, lines) = ring.drain();
        assert_eq!(lost, 3);
        assert_eq!(lines, vec![b"dddddddd".to_vec()]);
        // Loss counter resets after a drain.
        assert_eq!(ring.lost(), 0);
    }

    #[test]
    fn ring_rejects_single_line_larger_than_capacity_and_counts_it() {
        let mut ring = LineRing::with_capacity(8);
        ring.push(b"keep");
        ring.push(b"far-too-long-line");
        assert_eq!(ring.lost(), 1);
        let (lost, lines) = ring.drain();
        assert_eq!(lost, 1);
        assert_eq!(lines, vec![b"keep".to_vec()]);
    }

    #[test]
    fn ring_capacity_is_64_kib() {
        assert_eq!(RING_CAPACITY, 65_536);
        let sink = SharedSink::default();
        let router = Router::new(Box::new(sink));
        assert_eq!(router.lock().ring.capacity(), 65_536);
        let mut ring = LineRing::with_capacity(RING_CAPACITY);
        let line = vec![b'x'; 1024];
        for _ in 0..64 {
            ring.push(&line);
        }
        assert_eq!(ring.lost(), 0);
        assert_eq!(ring.len(), RING_CAPACITY);
        ring.push(&line);
        assert_eq!(ring.lost(), 1);
        assert_eq!(ring.len(), RING_CAPACITY);
    }

    #[test]
    fn router_in_normal_mode_writes_through() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        assert_eq!(router.mode(), Mode::Normal);
        let mut w = router.make_writer();
        w.write_all(b"line\n").unwrap();
        assert_eq!(sink.bytes(), b"line\n");
    }

    #[test]
    fn router_in_ring_mode_performs_no_write_to_sink() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        router.enter_ring();
        assert_eq!(router.mode(), Mode::Ring);
        let before = sink.len();
        let mut w = router.make_writer();
        for _ in 0..1000 {
            w.write_all(&[b'x'; 200]).unwrap();
        }
        assert_eq!(sink.len(), before);
        assert!(router.lost() > 0, "the ring must have overflowed");
    }

    #[test]
    fn flush_emits_loss_record_first_when_nonzero() {
        let sink = SharedSink::default();
        let router = router_over(&sink, 16);
        router.enter_ring();
        let mut w = router.make_writer();
        w.write_all(b"first-line\n").unwrap();
        w.write_all(b"second-ln\n").unwrap();
        assert_eq!(sink.len(), 0);
        let lost = router.flush_to_normal();
        assert_eq!(lost, 1);
        assert_eq!(router.mode(), Mode::Normal);
        let lines = sink.lines();
        assert_eq!(lines.len(), 2, "{lines:?}");
        let loss: Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(loss["event"], EVENT_AUDIT_RECORDS_LOST);
        assert_eq!(loss["lost"], 1);
        assert_eq!(loss["level"], "WARN");
        assert!(loss["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(lines[1], "second-ln");
    }

    #[test]
    fn flush_emits_nothing_extra_when_no_loss() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        router.enter_ring();
        let mut w = router.make_writer();
        w.write_all(b"a\n").unwrap();
        assert_eq!(router.flush_to_normal(), 0);
        assert_eq!(sink.bytes(), b"a\n");
        // A second flush with nothing buffered writes nothing.
        router.enter_ring();
        assert_eq!(router.flush_to_normal(), 0);
        assert_eq!(sink.bytes(), b"a\n");
    }

    #[test]
    fn flush_preserves_order() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        let mut w = router.make_writer();
        w.write_all(b"before\n").unwrap();
        router.enter_ring();
        for i in 0..50 {
            w.write_all(format!("ring-{i}\n").as_bytes()).unwrap();
        }
        router.flush_to_normal();
        w.write_all(b"after\n").unwrap();
        let lines = sink.lines();
        assert_eq!(lines[0], "before");
        for (i, line) in lines[1..51].iter().enumerate() {
            assert_eq!(line, &format!("ring-{i}"));
        }
        assert_eq!(lines[51], "after");
        assert_eq!(lines.len(), 52);
    }

    #[test]
    fn tracing_pipeline_produces_one_json_line_per_event() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        let record = AuditRecord {
            method: MethodField::Full("guest-ping".to_owned()),
            id: Some(7),
            disposition: Disposition::Allowed,
            reason: None,
            freeze_state_before: "thawed",
        };
        tracing::subscriber::with_default(subscriber(Level::INFO, router.clone()), || {
            emit(&record);
            router.enter_ring();
            emit(&record);
            emit(&record);
            tracing::debug!(event = "filtered_out", "below max level");
            router.flush_to_normal();
            emit(&record);
        });
        let lines = sink.lines();
        assert_eq!(lines.len(), 4, "{lines:?}");
        for line in &lines {
            let json: Value = serde_json::from_str(line).unwrap();
            let obj = json.as_object().unwrap();
            let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(
                keys,
                [
                    "disposition",
                    "event",
                    "freeze_state_before",
                    "id",
                    "level",
                    "method",
                    "timestamp"
                ]
            );
        }
    }

    #[test]
    fn format_utc_matches_design_shape() {
        assert_eq!(format_utc(UNIX_EPOCH), "1970-01-01T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_millis(1_786_910_400_123);
        assert_eq!(format_utc(t), "2026-08-16T20:00:00.123Z");
        // Leap day and year boundary.
        let t = UNIX_EPOCH + Duration::from_secs(1_709_164_800);
        assert_eq!(format_utc(t), "2024-02-29T00:00:00.000Z");
        let t = UNIX_EPOCH + Duration::from_secs(1_704_067_199);
        assert_eq!(format_utc(t), "2023-12-31T23:59:59.000Z");
    }

    #[test]
    fn init_tracing_reports_double_initialisation() {
        // Whether or not another test installed a global subscriber first,
        // the second call in this process must fail cleanly, never panic.
        let sink = SharedSink::default();
        let first = init_tracing(Level::INFO, router_over(&sink, RING_CAPACITY));
        let second = init_tracing(Level::INFO, router_over(&sink, RING_CAPACITY));
        assert!(first.is_ok() || first == Err(InitError::AlreadyInitialised));
        assert_eq!(second, Err(InitError::AlreadyInitialised));
    }
}
