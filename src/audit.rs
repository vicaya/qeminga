//! Audit records, method projection, and the freeze-safe log ring
//! (design §4.1 Logging, §5.2, §9, §9.1; G7; AC13).
//!
//! Every received command produces exactly one [`AuditRecord`], emitted as
//! a structured `tracing` event with flattened fields. The subscriber
//! installed by [`init_tracing`] formats each event as one JSON line and
//! hands it to a [`Router`], which either queues it for a dedicated writer
//! thread that delivers to the normal sink (stderr) or, while filesystems
//! are frozen, keeps it in a byte-bounded in-memory [`LineRing`] so no
//! descriptor that might reach a frozen filesystem is written until thaw
//! (§9.1). No caller ever performs sink I/O: a sink that blocks blocks
//! its thread and nothing else, and records beyond the bounded queue are
//! dropped and counted rather than the daemon held (#43 §3).
//!
//! Attacker-controlled method names are projected by [`project_method`]
//! to at most 64 UTF-8 bytes at a character boundary before they reach a
//! record; longer names are recorded as a prefix, their byte length, and a
//! SHA-256 digest. Field values are always structured, never formatted into
//! a message string.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tracing::Level;
use tracing_subscriber::filter::Targets;
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

/// `tracing` target of every audit record. The subscriber keeps this
/// target at INFO whatever `log_level` says, so audit records are never
/// filtered out with the diagnostics (§9).
pub const AUDIT_TARGET: &str = "qeminga::audit";

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
            target: AUDIT_TARGET,
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
    /// Records are queued for the writer thread, which delivers them to
    /// the sink.
    Normal,
    /// Records are held in the ring; the sink is never touched and the
    /// writer thread parks.
    Ring,
}

/// Bytes of formatted records the delivery queue holds for the writer
/// thread before further records are dropped and counted (§9.1).
pub const SINK_QUEUE_CAPACITY: usize = 256 * 1024;

/// How long the last [`Router`] handle waits, when dropped, for the
/// writer thread to deliver what is queued (tests; the daemon's router
/// lives in the global subscriber until the process exits).
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// How long a path that is about to leave the process (`guest-shutdown`
/// before `reboot(2)`, the daemon's exit) waits for the writer thread to
/// deliver what is queued. Bounded: a sink that is not reading delays the
/// leaving by this much and no more, and is never waited on for a lock.
pub const DELIVERY_GRACE: Duration = Duration::from_secs(2);

/// Why records were lost, as reported in the loss record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LossReason {
    /// The freeze-safe ring overflowed while frozen.
    RingOverflow,
    /// The delivery queue was full: the sink was not keeping up (a
    /// blocked journald) and the records were dropped rather than the
    /// caller blocked.
    SinkBackpressure,
    /// The sink refused a write.
    SinkError,
}

impl LossReason {
    const fn as_str(self) -> &'static str {
        match self {
            LossReason::RingOverflow => "ring_overflow",
            LossReason::SinkBackpressure => "sink_backpressure",
            LossReason::SinkError => "sink_error",
        }
    }
}

/// One entry of the delivery queue: a formatted line, or the place where
/// lines were lost (dropped at a full queue, or refused by the sink), so
/// the loss record is delivered exactly where the gap is.
enum Item {
    Line(Vec<u8>),
    Lost(u64, LossReason),
}

struct State {
    mode: Mode,
    ring: LineRing,
    /// Lines (and loss markers) awaiting delivery, in order.
    queue: VecDeque<Item>,
    /// Bytes of lines in `queue`.
    queued: usize,
    capacity: usize,
    /// The writer thread is inside a sink write.
    writing: bool,
    /// The last handle was dropped: deliver what is queued and exit.
    shutdown: bool,
    /// The writer thread has exited (or never started).
    exited: bool,
    /// Bumped on every push, so a writer parked after a sink failure
    /// retries only once something new arrived.
    pushes: u64,
}

struct Shared {
    state: Mutex<State>,
    changed: Condvar,
}

impl Shared {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock only means another thread panicked while holding
        // it; the state is a mode flag and byte queues, so it is still
        // usable and audit output must not stop.
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Marks the last user-side handle: its drop tells the writer thread to
/// finish. The writer holds only the [`Shared`] state, never this.
struct Alive(Arc<Shared>);

impl Drop for Alive {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.shutdown = true;
        self.0.changed.notify_all();
        // Bounded: a sink that is blocked keeps its thread, not the drop.
        let deadline = std::time::Instant::now() + SHUTDOWN_GRACE;
        while !state.exited && state.mode == Mode::Normal {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                break;
            }
            state = self
                .0
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }
}

/// Routes formatted log lines either to the delivery queue of a dedicated
/// writer thread or to the ring (§9.1, #43 §3).
///
/// No sink I/O ever happens on a caller's thread or under the lock: a
/// `write` queues the line (or drops it, counted, when the queue holds
/// [`SINK_QUEUE_CAPACITY`] bytes), [`enter_ring`](Self::enter_ring) and
/// [`flush_to_normal`](Self::flush_to_normal) only move lines between the
/// ring and the queue, and the writer thread alone calls the sink, one
/// line at a time. A sink that blocks (a journald whose journal is
/// frozen) therefore blocks that thread and nothing else. While the mode
/// is [`Mode::Ring`] the writer parks even with lines queued from before
/// the window, so no descriptor is written between the first `FIFREEZE`
/// and the thaw; a write already in flight when the window opened
/// completes on its own thread. Delivery is in order: the queue is FIFO
/// and a flush appends the ring's lines behind whatever was queued
/// before the window. Lost lines (queue full, sink error, ring overflow)
/// are reported by a loss record ahead of the next delivered line.
///
/// Cheap to clone; implements [`MakeWriter`] so it can be installed as
/// the subscriber's writer. Each `write` call carries exactly one record
/// because the `fmt` layer writes one line per event.
#[derive(Clone)]
pub struct Router {
    shared: Arc<Shared>,
    /// Dropped with the last handle: the writer thread's cue to finish.
    _alive: Arc<Alive>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Router")
            .field("mode", &self.mode())
            .finish()
    }
}

impl Router {
    /// Creates a router in [`Mode::Normal`] delivering to `sink` on a
    /// writer thread, with a ring of [`RING_CAPACITY`] bytes. Should the
    /// thread not start, every record is counted lost instead (use
    /// [`try_new`](Self::try_new) where that must be an error).
    pub fn new(sink: Box<dyn Write + Send>) -> Self {
        Self::with_capacities(sink, RING_CAPACITY, SINK_QUEUE_CAPACITY)
            .unwrap_or_else(|(_, router)| router)
    }

    /// Like [`new`](Self::new), reporting a writer thread that could not
    /// be started.
    pub fn try_new(sink: Box<dyn Write + Send>) -> io::Result<Self> {
        Self::with_capacities(sink, RING_CAPACITY, SINK_QUEUE_CAPACITY).map_err(|(err, _)| err)
    }

    /// Creates a router in [`Mode::Normal`] writing to standard error.
    pub fn stderr() -> io::Result<Self> {
        Self::try_new(Box::new(io::stderr()))
    }

    /// Creates a router with an explicit ring capacity (tests).
    pub fn with_ring_capacity(sink: Box<dyn Write + Send>, capacity: usize) -> Self {
        Self::with_capacities(sink, capacity, SINK_QUEUE_CAPACITY)
            .unwrap_or_else(|(_, router)| router)
    }

    /// Creates a router with explicit ring and queue capacities (tests).
    pub fn with_queue_capacity(sink: Box<dyn Write + Send>, queue: usize) -> Self {
        Self::with_capacities(sink, RING_CAPACITY, queue).unwrap_or_else(|(_, router)| router)
    }

    fn with_capacities(
        sink: Box<dyn Write + Send>,
        ring: usize,
        queue: usize,
    ) -> Result<Self, (io::Error, Self)> {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                mode: Mode::Normal,
                ring: LineRing::with_capacity(ring),
                queue: VecDeque::new(),
                queued: 0,
                capacity: queue,
                writing: false,
                shutdown: false,
                exited: false,
                pushes: 0,
            }),
            changed: Condvar::new(),
        });
        let router = Router {
            _alive: Arc::new(Alive(Arc::clone(&shared))),
            shared: Arc::clone(&shared),
        };
        let spawned = std::thread::Builder::new()
            .name("qeminga-audit".to_owned())
            .spawn(move || writer_thread(&shared, sink));
        match spawned {
            Ok(_) => Ok(router),
            Err(err) => {
                router.shared.lock().exited = true;
                Err((err, router))
            }
        }
    }

    /// The current mode.
    pub fn mode(&self) -> Mode {
        self.shared.lock().mode
    }

    /// Switches to [`Mode::Ring`]. Synchronous and free of I/O, so it can be
    /// called before the recovery marker and the first `FIFREEZE` (§4.2);
    /// the writer thread parks at its next line.
    pub fn enter_ring(&self) {
        self.shared.lock().mode = Mode::Ring;
        self.shared.changed.notify_all();
    }

    /// Moves the ring's lines to the delivery queue and switches to
    /// [`Mode::Normal`], without touching the sink: delivery is the
    /// writer thread's, so the caller (the thaw's finalisation) never
    /// waits for the sink.
    ///
    /// If any records were lost in the ring, a loss record is queued
    /// first, then the buffered records in their original order, behind
    /// whatever was queued before the window. Lines the queue cannot hold
    /// are dropped and counted, and reported like any other drop. Returns
    /// the ring's loss count.
    pub fn flush_to_normal(&self) -> u64 {
        let mut state = self.shared.lock();
        let (lost, lines) = state.ring.drain();
        if lost > 0 {
            // A marker, not a line: it takes no queue space, so a queue
            // that is already full cannot lose the report of the loss.
            state.lose(lost, LossReason::RingOverflow);
        }
        for line in lines {
            state.enqueue(line);
        }
        state.mode = Mode::Normal;
        drop(state);
        self.shared.changed.notify_all();
        lost
    }

    /// Number of lines lost in the ring since the last flush.
    pub fn lost(&self) -> u64 {
        self.shared.lock().ring.lost()
    }

    /// Number of lines dropped at the delivery queue or refused by the
    /// sink and not yet reported by a loss record.
    pub fn unreported_losses(&self) -> u64 {
        self.shared
            .lock()
            .queue
            .iter()
            .map(|item| match item {
                Item::Lost(count, _) => *count,
                Item::Line(_) => 0,
            })
            .sum()
    }

    /// Bytes queued for the writer thread.
    pub fn queued_bytes(&self) -> usize {
        self.shared.lock().queued
    }

    /// Waits until every queued line has been handed to the sink and no
    /// write is in flight, at most `timeout`; `false` on timeout. For
    /// tests that read the sink: a blocked sink never blocks anything
    /// but its own thread, so a caller must ask before looking.
    pub fn settle(&self, timeout: Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        let mut state = self.shared.lock();
        loop {
            let idle = state.exited
                || state.mode == Mode::Ring
                || (state.queue.is_empty() && !state.writing);
            if idle {
                return true;
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return false;
            }
            state = self
                .shared
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    fn write_record(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.shared.lock();
        match state.mode {
            Mode::Ring => state.ring.push(buf),
            Mode::Normal => {
                if state.exited && !state.shutdown {
                    // No writer thread: nothing can deliver it.
                    state.lose(1, LossReason::SinkError);
                } else {
                    state.enqueue(buf.to_vec());
                }
            }
        }
        drop(state);
        self.shared.changed.notify_all();
        Ok(buf.len())
    }
}

impl State {
    /// Queues a line for delivery, or drops and counts it where it would
    /// have gone when the queue is full. A loss marker takes no space, so
    /// the losses are always accounted for.
    fn enqueue(&mut self, line: Vec<u8>) {
        if self.queued.saturating_add(line.len()) > self.capacity && self.queued > 0 {
            self.lose(1, LossReason::SinkBackpressure);
            return;
        }
        self.queued = self.queued.saturating_add(line.len());
        self.queue.push_back(Item::Line(line));
        self.pushes = self.pushes.wrapping_add(1);
    }

    /// Records `count` lost lines at the tail of the queue, merged into a
    /// marker already there for the same reason.
    fn lose(&mut self, count: u64, reason: LossReason) {
        if let Some(Item::Lost(n, r)) = self.queue.back_mut()
            && *r == reason
        {
            *n = n.saturating_add(count);
        } else {
            self.queue.push_back(Item::Lost(count, reason));
        }
        self.pushes = self.pushes.wrapping_add(1);
    }

    /// Puts a loss back at the head of the queue (a line the sink refused
    /// belongs where it was; a loss record the sink refused stays until
    /// it can be written).
    fn lose_at_front(&mut self, count: u64, reason: LossReason) {
        if let Some(Item::Lost(n, r)) = self.queue.front_mut()
            && *r == reason
        {
            *n = n.saturating_add(count);
        } else {
            self.queue.push_front(Item::Lost(count, reason));
        }
    }
}

/// The writer thread: takes one item at a time, outside the lock, and
/// writes it to the sink (a loss marker becomes its loss record); parks
/// while the ring is in use; after a sink failure waits for something
/// new before retrying a loss record, so a dead sink is never spun on;
/// exits once the last handle is gone and the queue is delivered (or the
/// mode is still `Ring`: nothing may be written then).
fn writer_thread(shared: &Shared, mut sink: Box<dyn Write + Send>) {
    let mut failed_at: Option<u64> = None;
    loop {
        let item = {
            let mut state = shared.lock();
            let item = loop {
                // A writer declared gone (`exited`) delivers nothing more
                // and leaves: what a caller then writes is counted lost,
                // consistently with what the caller was told.
                if state.exited {
                    break None;
                }
                if state.mode == Mode::Normal
                    && let Some(front) = state.queue.front()
                    && failed_at != Some(state.pushes)
                {
                    break Some(match front {
                        Item::Line(line) => Item::Line(line.clone()),
                        Item::Lost(count, reason) => Item::Lost(*count, *reason),
                    });
                }
                if state.shutdown && (state.queue.is_empty() || state.mode == Mode::Ring) {
                    break None;
                }
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            };
            let Some(item) = item else {
                state.exited = true;
                shared.changed.notify_all();
                return;
            };
            state.writing = true;
            item
        };
        let (bytes, marker) = match &item {
            Item::Line(line) => (line.clone(), None),
            Item::Lost(count, reason) => (
                loss_record(*count, *reason).into_bytes(),
                Some((*count, *reason)),
            ),
        };
        let delivered = sink.write_all(&bytes).is_ok();
        let _ = sink.flush();
        let mut state = shared.lock();
        // The item stayed at the front while it was written, so the queue
        // never looked empty to `settle` before delivery.
        match state.queue.pop_front() {
            Some(Item::Line(line)) => state.queued -= line.len(),
            Some(Item::Lost(..)) | None => {}
        }
        if delivered {
            failed_at = None;
        } else {
            failed_at = Some(state.pushes);
            match marker {
                // The loss record itself was refused: keep it for later.
                Some((count, reason)) => state.lose_at_front(count, reason),
                // The line is lost; say so where it was.
                None => state.lose_at_front(1, LossReason::SinkError),
            }
        }
        state.writing = false;
        shared.changed.notify_all();
    }
}

/// Builds the JSON line reporting `lost` dropped records.
fn loss_record(lost: u64, reason: LossReason) -> String {
    let mut line = serde_json::json!({
        "timestamp": format_utc(SystemTime::now()),
        "level": "WARN",
        "event": EVENT_AUDIT_RECORDS_LOST,
        "lost": lost,
        "reason": reason.as_str(),
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
        // Delivery is the writer thread's; waiting for it here would put
        // the sink back on the caller's path.
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
/// per event, written through `router`. `level` filters diagnostics only;
/// the [`AUDIT_TARGET`] stays at INFO so every audit record is written.
pub fn subscriber(
    level: Level,
    router: Router,
) -> impl tracing::Subscriber + Send + Sync + 'static {
    use tracing_subscriber::layer::SubscriberExt as _;
    let filter = Targets::new()
        .with_default(level)
        .with_target(AUDIT_TARGET, Level::INFO);
    tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_timer(UtcTimestamp)
        .with_writer(router)
        .finish()
        .with(filter)
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

    /// Waits for the writer thread to deliver everything queued.
    fn settled(router: &Router) {
        assert!(router.settle(Duration::from_secs(10)), "delivery stalled");
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
        assert_eq!(router.shared.lock().ring.capacity(), 65_536);
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
        settled(&router);
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
        settled(&router);
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
        settled(&router);
        assert_eq!(sink.bytes(), b"a\n");
        // A second flush with nothing buffered writes nothing.
        router.enter_ring();
        assert_eq!(router.flush_to_normal(), 0);
        settled(&router);
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
        settled(&router);
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
        settled(&router);
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

    /// A sink that blocks inside `write` for as long as the test says
    /// (a journald whose journal is on a frozen filesystem), then records
    /// what it was given.
    #[derive(Clone, Default)]
    struct BlockingSink {
        blocked: Arc<(Mutex<bool>, std::sync::Condvar)>,
        written: Arc<Mutex<Vec<u8>>>,
        entered: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl BlockingSink {
        fn blocked() -> Self {
            let sink = BlockingSink::default();
            sink.set_blocked(true);
            sink
        }
        fn set_blocked(&self, blocked: bool) {
            *self.blocked.0.lock().unwrap() = blocked;
            self.blocked.1.notify_all();
        }
        fn text(&self) -> String {
            String::from_utf8(self.written.lock().unwrap().clone()).unwrap()
        }
        fn lines(&self) -> Vec<String> {
            self.text().lines().map(str::to_owned).collect()
        }
        /// Waits until a write is blocked inside the sink.
        fn wait_entered(&self, n: usize) {
            let start = std::time::Instant::now();
            while self.entered.load(std::sync::atomic::Ordering::SeqCst) < n {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "no write entered"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    impl Write for BlockingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut blocked = self.blocked.0.lock().unwrap();
            while *blocked {
                blocked = self.blocked.1.wait(blocked).unwrap();
            }
            drop(blocked);
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Asserts that `f` returns within a bound a blocked sink would
    /// breach.
    fn promptly<T>(what: &str, f: impl FnOnce() -> T) -> T {
        let start = std::time::Instant::now();
        let out = f();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "{what} waited on the sink ({:?})",
            start.elapsed()
        );
        out
    }

    #[test]
    fn a_blocked_sink_blocks_only_the_writer_thread() {
        // The first line enters the sink and blocks there. Every later
        // write, the switch to the ring and the flush back return at
        // once; the lines wait in the queue and are delivered, in order,
        // once the sink moves again.
        let sink = BlockingSink::blocked();
        let router = Router::new(Box::new(sink.clone()));
        let mut w = router.make_writer();
        w.write_all(b"one\n").unwrap();
        sink.wait_entered(1);
        promptly("write", || w.write_all(b"two\n").unwrap());
        promptly("enter_ring", || router.enter_ring());
        w.write_all(b"three\n").unwrap();
        assert_eq!(promptly("flush_to_normal", || router.flush_to_normal()), 0);
        assert_eq!(router.mode(), Mode::Normal);
        assert_eq!(router.queued_bytes(), 14, "one (in flight), two, three");
        assert!(sink.text().is_empty(), "nothing delivered yet");
        assert!(!router.settle(Duration::from_millis(50)), "still blocked");
        sink.set_blocked(false);
        settled(&router);
        assert_eq!(sink.lines(), ["one", "two", "three"]);
        assert_eq!(router.unreported_losses(), 0);
    }

    #[test]
    fn the_writer_parks_while_the_ring_is_in_use() {
        // A line queued before the window is not written during it (no
        // descriptor is touched between FIFREEZE and thaw), even once the
        // sink would accept it; the flush releases it ahead of the ring's
        // lines, in order.
        let sink = BlockingSink::blocked();
        let router = Router::new(Box::new(sink.clone()));
        let mut w = router.make_writer();
        w.write_all(b"one\n").unwrap();
        sink.wait_entered(1);
        w.write_all(b"two\n").unwrap();
        router.enter_ring();
        sink.set_blocked(false);
        // `one` was in flight and completes; `two` must wait.
        let start = std::time::Instant::now();
        while sink.lines().is_empty() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(sink.lines(), ["one"], "parked while the ring is in use");
        assert_eq!(router.queued_bytes(), 4);
        w.write_all(b"three\n").unwrap();
        router.flush_to_normal();
        settled(&router);
        assert_eq!(sink.lines(), ["one", "two", "three"]);
    }

    #[test]
    fn a_full_queue_drops_the_newest_and_reports_the_loss_where_it_happened() {
        // Capacity for three 20-byte lines with the first blocked in the
        // sink: the fourth and fifth are dropped and counted; the loss
        // record is delivered where the gap is, after the third.
        let sink = BlockingSink::blocked();
        let router = Router::with_queue_capacity(Box::new(sink.clone()), 64);
        let mut w = router.make_writer();
        let line = |n: u8| format!("{{\"n\":{n},\"pad\":\"xxx\"}}\n");
        assert_eq!(line(1).len(), 20);
        for n in 1..=5 {
            promptly("write", || w.write_all(line(n).as_bytes()).unwrap());
        }
        assert_eq!(router.queued_bytes(), 60);
        assert_eq!(router.unreported_losses(), 2);
        // A line after the drops that fits again goes behind the marker.
        sink.set_blocked(false);
        settled(&router);
        w.write_all(line(6).as_bytes()).unwrap();
        settled(&router);
        let lines = sink.lines();
        assert_eq!(lines.len(), 5, "{lines:?}");
        assert!(lines[0].contains("\"n\":1"));
        assert!(lines[2].contains("\"n\":3"));
        let loss: Value = serde_json::from_str(&lines[3]).unwrap();
        assert_eq!(loss["event"], EVENT_AUDIT_RECORDS_LOST);
        assert_eq!(loss["lost"], 2);
        assert_eq!(loss["reason"], "sink_backpressure");
        assert!(lines[4].contains("\"n\":6"));
        assert_eq!(router.unreported_losses(), 0);
    }

    /// A sink that refuses its first `failures` writes.
    #[derive(Clone)]
    struct FailingSink {
        failures: Arc<std::sync::atomic::AtomicUsize>,
        written: Arc<Mutex<Vec<u8>>>,
        attempts: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Write for FailingSink {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let left = self.failures.load(std::sync::atomic::Ordering::SeqCst);
            if left > 0 {
                self.failures
                    .store(left - 1, std::sync::atomic::Ordering::SeqCst);
                return Err(io::Error::from(io::ErrorKind::BrokenPipe));
            }
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_failing_sink_loses_the_refused_records_and_reports_them_without_spinning() {
        // The first two writes fail: `a` is lost, and the loss record for
        // it is refused too; the writer then waits for something new
        // instead of retrying in a loop. `b` arrives: the loss record is
        // written, then `b` and `c`.
        let sink = FailingSink {
            failures: Arc::new(std::sync::atomic::AtomicUsize::new(2)),
            written: Arc::new(Mutex::new(Vec::new())),
            attempts: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        };
        let router = Router::new(Box::new(sink.clone()));
        let mut w = router.make_writer();
        let attempts = |n: usize| {
            let start = std::time::Instant::now();
            while sink.attempts.load(std::sync::atomic::Ordering::SeqCst) < n {
                assert!(start.elapsed() < Duration::from_secs(10));
                std::thread::sleep(Duration::from_millis(1));
            }
            std::thread::sleep(Duration::from_millis(50));
            assert_eq!(
                sink.attempts.load(std::sync::atomic::Ordering::SeqCst),
                n,
                "no spinning on a dead sink"
            );
        };
        w.write_all(b"a\n").unwrap();
        attempts(1);
        assert_eq!(router.unreported_losses(), 1);
        // Something new: the loss record is tried, and refused too.
        w.write_all(b"b\n").unwrap();
        attempts(2);
        assert_eq!(router.unreported_losses(), 1, "the record is kept");
        w.write_all(b"c\n").unwrap();
        settled(&router);
        let text = String::from_utf8(sink.written.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3, "{lines:?}");
        let loss: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(loss["event"], EVENT_AUDIT_RECORDS_LOST);
        assert_eq!(loss["lost"], 1);
        assert_eq!(loss["reason"], "sink_error");
        assert_eq!(&lines[1..], ["b", "c"]);
        assert_eq!(router.unreported_losses(), 0);
    }

    #[test]
    fn the_ring_flush_reports_its_loss_with_its_reason() {
        let sink = SharedSink::default();
        let router = router_over(&sink, 16);
        router.enter_ring();
        let mut w = router.make_writer();
        w.write_all(b"first-line\n").unwrap();
        w.write_all(b"second-ln\n").unwrap();
        router.flush_to_normal();
        settled(&router);
        let loss: Value = serde_json::from_str(&sink.lines()[0]).unwrap();
        assert_eq!(loss["reason"], "ring_overflow");
    }

    #[test]
    fn a_ring_loss_is_reported_by_a_marker_even_when_the_queue_is_full() {
        // The queue is full behind a blocked sink when a window whose
        // ring overflowed is flushed: the ring's loss is a marker, which
        // takes no queue space, so it is reported with its own count and
        // reason; only the ring's lines the queue cannot hold are counted
        // as backpressure, separately.
        let sink = BlockingSink::blocked();
        let router = Router::with_queue_capacity(Box::new(sink.clone()), 64);
        let mut w = router.make_writer();
        let line = |n: u8| format!("{{\"n\":{n},\"pad\":\"xxx\"}}\n");
        for n in 1..=3 {
            promptly("write", || w.write_all(line(n).as_bytes()).unwrap());
        }
        sink.wait_entered(1);
        assert_eq!(router.queued_bytes(), 60, "the queue is full");
        router.enter_ring();
        let filler = line(9);
        let written = RING_CAPACITY / filler.len() + 4;
        for _ in 0..written {
            w.write_all(filler.as_bytes()).unwrap();
        }
        let overflowed = router.lost();
        assert!(overflowed > 0, "the ring overflowed");
        let kept = written as u64 - overflowed;
        assert_eq!(router.flush_to_normal(), overflowed);
        assert_eq!(router.unreported_losses(), overflowed + kept);
        sink.set_blocked(false);
        settled(&router);
        let lines = sink.lines();
        assert_eq!(lines.len(), 5, "{lines:?}");
        let ring_loss: Value = serde_json::from_str(&lines[3]).unwrap();
        assert_eq!(ring_loss["reason"], "ring_overflow", "{lines:?}");
        assert_eq!(ring_loss["lost"], overflowed);
        let queue_loss: Value = serde_json::from_str(&lines[4]).unwrap();
        assert_eq!(queue_loss["reason"], "sink_backpressure");
        assert_eq!(queue_loss["lost"], kept);
    }

    #[test]
    fn dropping_the_last_handle_delivers_the_queue() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        let mut w = router.make_writer();
        w.write_all(b"last\n").unwrap();
        drop(w);
        drop(router);
        assert_eq!(sink.bytes(), b"last\n");
    }

    #[test]
    fn dropping_the_last_handle_never_waits_on_a_blocked_sink_beyond_the_grace() {
        let sink = BlockingSink::blocked();
        let router = Router::new(Box::new(sink.clone()));
        let mut w = router.make_writer();
        w.write_all(b"stuck\n").unwrap();
        sink.wait_entered(1);
        drop(w);
        let start = std::time::Instant::now();
        drop(router);
        assert!(start.elapsed() < SHUTDOWN_GRACE + Duration::from_secs(2));
        sink.set_blocked(false);
    }

    #[test]
    fn a_router_without_a_writer_thread_counts_every_record_lost() {
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        settled(&router);
        // Declared gone, the thread delivers nothing more (it leaves at
        // its next look), so the record is lost at the write, never
        // raced onto the sink.
        router.shared.lock().exited = true;
        router.shared.changed.notify_all();
        let mut w = router.make_writer();
        w.write_all(b"nowhere\n").unwrap();
        assert_eq!(router.unreported_losses(), 1);
        assert!(sink.bytes().is_empty());
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
    fn audit_records_are_written_whatever_the_log_level() {
        // `log_level` governs diagnostics only (§9: every received command
        // is written): under ERROR an allowed record still reaches the sink
        // while an INFO diagnostic does not.
        let sink = SharedSink::default();
        let router = router_over(&sink, RING_CAPACITY);
        let allowed = AuditRecord {
            method: MethodField::Full("guest-fsfreeze-freeze".to_owned()),
            id: Some(1),
            disposition: Disposition::Allowed,
            reason: None,
            freeze_state_before: "thawed",
        };
        tracing::subscriber::with_default(subscriber(Level::ERROR, router), || {
            tracing::info!(target: "qeminga::daemon", event = "diagnostic", "not written under ERROR");
            allowed.emit();
        });
        let lines = sink.lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(EVENT_COMMAND_RECEIVED), "{}", lines[0]);
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
