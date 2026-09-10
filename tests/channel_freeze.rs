//! The freeze operation through the production channel loop and
//! dispatcher (design §4.4 "Operation deadline", §5.7; AC20; #39): a thaw
//! sent while the freeze reply is pending reaches the operation (also
//! behind answered controls), the frozen-safe controls are served while
//! a recovery drain is blocked, replies keep request order (requests
//! with and without `id`, the delimited sync), repeated controls are
//! bounded, a freeze never starts while a trim runs, a reply the host
//! does not read stalls neither the thaw behind it nor a stop, a stop
//! finishes a running trim, and a lost connection leaves the operation
//! owned.
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use qeminga::audit::Router;
use qeminga::channel::{self, MAX_QUEUED, SessionEnd, run_session_until};
use qeminga::config::Config;
use qeminga::dispatch::{Context, Dispatcher};
use qeminga::framing::FrameDecoder;
use qeminga::freeze_op::ManualClock;
use qeminga::kernel::fake::{Call, FakeKernel, Gate, ReleaseOnDrop};
use qeminga::marker::Marker;
use qeminga::mountinfo::StaticMounts;
use qeminga::state::{FreezeState, FreezeStateMachine};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// nested.txt freezes deepest-first: A = /home/data/deep, B = /home/data;
/// D = / is the root.
const A: &str = "/home/data/deep";
const B: &str = "/home/data";
const D: &str = "/";

fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mountinfo")
            .join(name),
    )
    .unwrap()
}

/// The production dispatcher over a context with the gated fake kernel
/// and a manual clock, served by the production session loop over a
/// duplex stream.
struct Rig {
    ctx: Arc<Context>,
    kernel: Arc<FakeKernel>,
    clock: ManualClock,
    peer: DuplexStream,
    /// Bytes the session has read from the stream so far: with a small
    /// stream buffer, the only way to know that a frame written has also
    /// been consumed (the buffer may still hold its tail).
    received: Arc<AtomicU64>,
    cancel: tokio::sync::watch::Sender<bool>,
    session: tokio::task::JoinHandle<SessionEnd>,
    _dir: tempfile::TempDir,
}

/// The session's reader, counting what it reads.
struct Counted<R> {
    inner: R,
    received: Arc<AtomicU64>,
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counted<R> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &polled {
            let read = buf.filled().len() - before;
            self.received
                .fetch_add(u64::try_from(read).unwrap(), Ordering::SeqCst);
        }
        polled
    }
}

fn rig() -> Rig {
    rig_with_buffer(8192)
}

/// A rig whose duplex stream holds `buffer` bytes: a small one makes a
/// reply the peer does not read block the writer.
fn rig_with_buffer(buffer: usize) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(FakeKernel::new());
    let clock = ManualClock::new();
    let ctx = Arc::new(
        Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(fixture("nested.txt"))))
        .with_freeze_clock(Arc::new(clock.clone()))
        .with_freeze_operation_timeout(Duration::from_secs(1)),
    );
    let (peer, ours) = tokio::io::duplex(buffer);
    let (reader, writer) = tokio::io::split(ours);
    let received = Arc::new(AtomicU64::new(0));
    let reader = Counted {
        inner: reader,
        received: Arc::clone(&received),
    };
    let (cancel, mut cancel_rx) = channel::cancel_pair();
    let dispatcher = Dispatcher::new(Arc::clone(&ctx));
    let session = tokio::spawn(async move {
        let mut decoder = FrameDecoder::new();
        run_session_until(reader, writer, &dispatcher, &mut decoder, &mut cancel_rx)
            .await
            .end
    });
    Rig {
        ctx,
        kernel,
        clock,
        peer,
        received,
        cancel,
        session,
        _dir: dir,
    }
}

impl Rig {
    async fn send(&mut self, frame: &str) {
        self.peer.write_all(frame.as_bytes()).await.unwrap();
        self.peer.write_all(b"\n").await.unwrap();
    }

    /// Bytes the session has read so far.
    fn received(&self) -> u64 {
        self.received.load(Ordering::SeqCst)
    }

    /// Reads one reply line (a delimited reply keeps its sentinel).
    async fn reply(&mut self) -> Vec<u8> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), self.peer.read(&mut byte))
                .await
                .expect("a reply within 10 s")
                .unwrap();
            assert_eq!(n, 1, "peer closed");
            line.push(byte[0]);
            if byte[0] == b'\n' {
                return line;
            }
        }
    }

    async fn json_reply(&mut self) -> Value {
        let line = self.reply().await;
        serde_json::from_slice(line.strip_prefix(&[0xFF]).unwrap_or(&line)).unwrap()
    }

    /// `true` when a reply is waiting to be read.
    async fn reply_pending(&mut self) -> bool {
        let mut byte = [0u8; 1];
        // A peek: the byte is consumed, so this is only used where the
        // absence of a reply is asserted.
        tokio::time::timeout(Duration::from_millis(100), self.peer.read(&mut byte))
            .await
            .is_ok()
    }

    fn fithaws(&self) -> Vec<String> {
        self.kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Fithaw(p) => Some(p.display().to_string()),
                _ => None,
            })
            .collect()
    }

    fn opens(&self) -> Vec<String> {
        self.kernel
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::Open(p, _) => Some(p.display().to_string()),
                _ => None,
            })
            .collect()
    }

    async fn wait_for(&self, what: &str, mut done: impl FnMut(&Rig) -> bool) {
        let start = std::time::Instant::now();
        while !done(self) {
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timed out: {what}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn expire(&self) {
        self.clock.advance(Duration::from_millis(1001));
    }

    /// A freeze whose walk is blocked at B; the gate's release guard is
    /// returned with it.
    async fn freeze_blocked_at_b(&mut self) -> (Gate, ReleaseOnDrop) {
        let gate = self.kernel.script_freeze_gate(B);
        let release = gate.release_on_drop();
        self.send(r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
        let g = gate.clone();
        self.wait_for("B blocked", move |_| g.waiting() == 1).await;
        (gate, release)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thaw_sent_while_the_freeze_reply_is_pending_aborts_the_walk() {
    // The freeze reply is pending (B inside FIFREEZE) when the host gives
    // up and sends a thaw: the thaw reaches the operation before its
    // deadline, the walk is aborted and A is recovered. The freeze reply
    // (no id) is written before the thaw reply (id 7), in request order.
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":7}"#)
        .await;
    let freeze = rig.json_reply().await;
    assert_eq!(freeze.get("id"), None);
    assert!(
        freeze["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("freeze aborted: thaw requested"),
        "{freeze}"
    );
    let thaw = rig.json_reply().await;
    assert_eq!(thaw["id"], json!(7));
    assert!(
        thaw["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("recovery pending"),
        "{thaw}"
    );
    rig.wait_for("A drained", |r| r.fithaws() == [A, A]).await;
    assert_eq!(gate.waiting(), 1, "B still inside FIFREEZE");
    assert_eq!(rig.opens(), [A, B], "C never authorised");
    assert!(rig.ctx.marker.exists());
    rig.send(r#"{"execute":"guest-fsfreeze-status"}"#).await;
    assert_eq!(rig.json_reply().await, json!({"return": "frozen"}));
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
    rig.send(r#"{"execute":"guest-fsfreeze-status"}"#).await;
    assert_eq!(rig.json_reply().await, json!({"return": "thawed"}));
    assert!(!rig.ctx.marker.exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_and_ping_are_served_while_a_recovery_drain_is_blocked() {
    // The deadline aborts the walk; A's recovery FITHAW blocks. A thaw is
    // answered at once, then status and ping, without releasing either
    // kernel gate, all in request order.
    let mut rig = rig();
    let a_thaw = rig.kernel.script_thaw_gate(A);
    let _release_a = a_thaw.release_on_drop();
    let (b, _release_b) = rig.freeze_blocked_at_b().await;
    rig.expire();
    let freeze = rig.json_reply().await;
    assert!(
        freeze["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("deadline of 1 s expired"),
        "{freeze}"
    );
    let g = a_thaw.clone();
    rig.wait_for("drain blocked", move |_| g.waiting() == 1)
        .await;
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":1}"#)
        .await;
    rig.send(r#"{"execute":"guest-fsfreeze-status","id":2}"#)
        .await;
    rig.send(r#"{"execute":"guest-ping","id":3}"#).await;
    let thaw = rig.json_reply().await;
    assert_eq!(thaw["id"], json!(1));
    assert!(
        thaw["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("recovery pending"),
        "{thaw}"
    );
    assert_eq!(rig.json_reply().await, json!({"return": "frozen", "id": 2}));
    assert_eq!(rig.json_reply().await, json!({"return": {}, "id": 3}));
    assert_eq!(a_thaw.waiting(), 1, "the drain is still blocked");
    assert_eq!(b.waiting(), 1, "B is still inside FIFREEZE");
    assert_eq!(rig.fithaws(), [A], "no second drain");
    a_thaw.release();
    b.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn replies_keep_request_order_for_id_less_and_delimited_requests() {
    // While the freeze reply is pending, a `guest-sync` (no top-level id)
    // and a delimited sync are handled but their replies wait behind the
    // freeze reply: the host, resynchronising on the sentinel, discards
    // everything before it, so nothing earlier can be mistaken for a
    // later reply.
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    rig.send(r#"{"execute":"guest-sync","arguments":{"id":5}}"#)
        .await;
    rig.peer
        .write_all(b"\xFF{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":42}}\n")
        .await
        .unwrap();
    assert!(
        !rig.reply_pending().await,
        "nothing before the freeze reply"
    );
    rig.expire();
    let freeze = rig.reply().await;
    assert!(
        freeze.starts_with(b"{\"error\""),
        "{}",
        String::from_utf8_lossy(&freeze)
    );
    assert_eq!(rig.reply().await, b"{\"return\":5}\n");
    assert_eq!(rig.reply().await, b"\xFF{\"return\":42}\n");
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_controls_while_a_reply_is_pending_are_bounded_and_answered_in_order() {
    // Twenty status requests behind a pending freeze reply: MAX_QUEUED
    // commands are held (the freeze and the controls answered behind
    // it), the rest wait unread, no ioctl or worker is added, and every
    // reply follows the freeze reply in order.
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    let calls_before = rig.kernel.calls().len();
    for i in 0..MAX_QUEUED - 1 {
        rig.send(&format!(
            r#"{{"execute":"guest-fsfreeze-status","id":{i}}}"#
        ))
        .await;
        let handled = (i + 2) as u64;
        rig.wait_for("status handled", move |r| r.ctx.handler_calls() == handled)
            .await;
    }
    for i in MAX_QUEUED - 1..20 {
        rig.send(&format!(
            r#"{{"execute":"guest-fsfreeze-status","id":{i}}}"#
        ))
        .await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        rig.ctx.handler_calls(),
        MAX_QUEUED as u64,
        "nothing is read while MAX_QUEUED commands are unanswered"
    );
    assert_eq!(rig.kernel.calls().len(), calls_before, "no ioctl, no open");
    rig.expire();
    let freeze = rig.json_reply().await;
    assert!(freeze.get("error").is_some(), "{freeze}");
    for i in 0..20 {
        assert_eq!(rig.json_reply().await, json!({"return": "frozen", "id": i}));
    }
    assert_eq!(gate.waiting(), 1);
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thaw_behind_answered_controls_still_aborts_the_pending_freeze() {
    // The freeze reply is pending; status, ping and sync are answered
    // (their replies wait behind it) and hold no lane: the fifth command,
    // a thaw, is read and aborts the walk well before the deadline (the
    // manual clock never advances).
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    rig.send(r#"{"execute":"guest-fsfreeze-status","id":2}"#)
        .await;
    rig.send(r#"{"execute":"guest-ping","id":3}"#).await;
    rig.send(r#"{"execute":"guest-sync","arguments":{"id":4}}"#)
        .await;
    rig.wait_for("controls handled", |r| r.ctx.handler_calls() == 4)
        .await;
    assert!(
        !rig.reply_pending().await,
        "nothing before the freeze reply"
    );
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":5}"#)
        .await;
    let freeze = rig.json_reply().await;
    assert!(
        freeze["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("freeze aborted: thaw requested"),
        "{freeze}"
    );
    assert_eq!(rig.json_reply().await, json!({"return": "frozen", "id": 2}));
    assert_eq!(rig.json_reply().await, json!({"return": {}, "id": 3}));
    assert_eq!(rig.json_reply().await, json!({"return": 4}));
    let thaw = rig.json_reply().await;
    assert_eq!(thaw["id"], json!(5));
    assert!(
        thaw["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("recovery pending"),
        "{thaw}"
    );
    rig.wait_for("A drained", |r| r.fithaws() == [A, A]).await;
    assert_eq!(gate.waiting(), 1, "B still inside FIFREEZE");
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_freeze_is_not_started_while_a_trim_is_running() {
    // A trim's FITRIM is blocked when the host sends a freeze: the freeze
    // is not started (no target is opened, nothing is frozen, the state
    // stays Thawed) until the trim has finished. The status behind the
    // waiting freeze is answered at once; its reply still leaves last.
    // Once the trim returns, the trim reply, the freeze and the status
    // follow in order.
    let mut rig = rig();
    let trim = rig.kernel.script_trim_gate(D);
    let _release = trim.release_on_drop();
    rig.send(r#"{"execute":"guest-fstrim","id":1}"#).await;
    let g = trim.clone();
    rig.wait_for("trim blocked", move |_| g.waiting() == 1)
        .await;
    rig.send(r#"{"execute":"guest-fsfreeze-freeze","id":2}"#)
        .await;
    rig.send(r#"{"execute":"guest-fsfreeze-status","id":3}"#)
        .await;
    rig.wait_for("status answered beside the trim", |r| {
        r.ctx.handler_calls() == 2
    })
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.ctx.handler_calls(), 2, "the freeze has not started");
    assert!(
        !rig.kernel
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Fifreeze(_))),
        "{:?}",
        rig.kernel.calls()
    );
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
    assert!(rig.ctx.freeze_op().is_none(), "no operation registered");
    assert!(!rig.reply_pending().await);
    trim.release();
    let trimmed = rig.json_reply().await;
    assert_eq!(trimmed["id"], json!(1));
    assert!(trimmed["return"]["paths"].is_array(), "{trimmed}");
    assert_eq!(rig.json_reply().await, json!({"return": 4, "id": 2}));
    assert_eq!(
        rig.json_reply().await,
        json!({"return": "thawed", "id": 3}),
        "answered while the freeze was still waiting"
    );
    let calls = rig.kernel.calls();
    let last_trim = calls
        .iter()
        .rposition(|c| matches!(c, Call::Fitrim(..)))
        .unwrap();
    let first_freeze = calls
        .iter()
        .position(|c| matches!(c, Call::Fifreeze(_)))
        .unwrap();
    assert!(
        last_trim < first_freeze,
        "every FITRIM precedes the first FIFREEZE"
    );
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":4}"#)
        .await;
    assert_eq!(rig.json_reply().await, json!({"return": 4, "id": 4}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocked_reply_does_not_stall_the_thaw_behind_it() {
    // Frozen; the host stops reading, so the `guest-info` reply blocks on
    // the 16-byte stream. The thaw sent after it is still driven to its
    // end: the drains run and `Thawed` is published without the host
    // reading a byte, and a stop then ends the session at once.
    let mut rig = rig_with_buffer(16);
    rig.send(r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert_eq!(rig.json_reply().await, json!({"return": 4}));
    assert_eq!(rig.ctx.state.current(), FreezeState::Frozen);
    rig.send(r#"{"execute":"guest-info","id":1}"#).await;
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":2}"#)
        .await;
    rig.wait_for("thawed without the host reading", |r| {
        r.ctx.state.current() == FreezeState::Thawed
    })
    .await;
    assert_eq!(
        rig.fithaws().len(),
        8,
        "every target drained, by its retained handle and its mount point"
    );
    assert!(!rig.ctx.marker.exists());
    rig.cancel.send(true).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), &mut rig.session)
        .await
        .expect("the stop ends the session without the host draining")
        .unwrap();
    assert!(matches!(end, SessionEnd::Cancelled), "{end}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stop_during_a_blocked_reply_waits_for_the_running_trim() {
    // The host stops reading with an info reply on the wire while a trim
    // is inside FITRIM; the stop is requested (Thawed, so it is accepted)
    // but the session drains: the trim is finished, not dropped, nothing
    // sent meanwhile is started, and the session ends once the trim has
    // returned, without the host reading.
    let mut rig = rig_with_buffer(16);
    let trim = rig.kernel.script_trim_gate(D);
    let _release = trim.release_on_drop();
    rig.send(r#"{"execute":"guest-info","id":1}"#).await;
    rig.send(r#"{"execute":"guest-fstrim","id":2}"#).await;
    let g = trim.clone();
    rig.wait_for("trim blocked", move |_| g.waiting() == 1)
        .await;
    rig.cancel.send(true).unwrap();
    // Nothing is read during the stop: the 16-byte stream fills and the
    // ping's write never completes.
    let unread = tokio::time::timeout(
        Duration::from_millis(200),
        rig.peer
            .write_all(b"{\"execute\":\"guest-ping\",\"id\":3}\n"),
    )
    .await;
    assert!(unread.is_err(), "the session reads nothing during the stop");
    assert!(!rig.session.is_finished(), "waits for the trim");
    assert_eq!(trim.waiting(), 1, "the trim was not dropped");
    assert_eq!(
        rig.ctx.handler_calls(),
        2,
        "nothing started during the stop"
    );
    trim.release();
    let end = tokio::time::timeout(Duration::from_secs(5), &mut rig.session)
        .await
        .expect("the session ends once the trim has returned")
        .unwrap();
    assert!(matches!(end, SessionEnd::Cancelled), "{end}");
    assert_eq!(rig.ctx.handler_calls(), 2);
    let trims = rig
        .kernel
        .calls()
        .into_iter()
        .filter(|c| matches!(c, Call::Fitrim(..)))
        .count();
    assert_eq!(trims, 4, "the trim ran to its end");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thaw_behind_a_waiting_walk_still_aborts_the_pending_freeze() {
    // B is inside FIFREEZE when the host sends a filesystem walk, then,
    // in a later read, a thaw. The walk waits for the serial lane (the
    // freeze gate would refuse it anyway); the thaw is not held back by
    // it: it reaches the operation with the clock never advanced, A is
    // recovered, and the walk never starts. Replies keep request order:
    // the aborted freeze, the walk refused while thawing, the thaw.
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    rig.send(r#"{"execute":"guest-get-fsinfo","id":2}"#).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.ctx.handler_calls(), 1, "the walk waits, unstarted");
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":3}"#)
        .await;
    let freeze = rig.json_reply().await;
    assert!(
        freeze["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("freeze aborted: thaw requested"),
        "{freeze}"
    );
    let walk = rig.json_reply().await;
    assert_eq!(walk["id"], json!(2));
    assert_eq!(walk["error"]["class"], json!("GenericError"));
    assert!(
        walk["error"]["desc"].as_str().unwrap().contains("frozen"),
        "{walk}"
    );
    let thaw = rig.json_reply().await;
    assert_eq!(thaw["id"], json!(3));
    assert!(
        thaw["error"]["desc"]
            .as_str()
            .unwrap()
            .contains("recovery pending"),
        "{thaw}"
    );
    rig.wait_for("A drained", |r| r.fithaws() == [A, A]).await;
    assert_eq!(gate.waiting(), 1, "B still inside FIFREEZE");
    assert_eq!(rig.ctx.handler_calls(), 2, "the walk never ran");
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_thaw_finishes_while_the_outbox_is_saturated() {
    // Frozen; the host stops reading with a `guest-info` reply stuck on
    // the 16-byte stream, a thaw inside FITHAW behind it, and controls
    // answered behind the thaw until MAX_QUEUED are held: nothing more
    // is read. The thaw's kernel work then completes and its lifecycle
    // still reaches `Thawed` with nothing delivered. Once the host
    // reads, every reply arrives once, in order, and the session serves
    // again.
    let mut rig = rig_with_buffer(16);
    rig.send(r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert_eq!(rig.json_reply().await, json!({"return": 4}));
    let a = rig.kernel.script_thaw_gate(A);
    let _release = a.release_on_drop();
    rig.send(r#"{"execute":"guest-info","id":1}"#).await;
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":2}"#)
        .await;
    let g = a.clone();
    rig.wait_for("thaw blocked", move |_| g.waiting() == 1)
        .await;
    // The freeze, the info and the thaw ran; each status adds one.
    for i in 3..=MAX_QUEUED as u64 {
        rig.send(&format!(
            r#"{{"execute":"guest-fsfreeze-status","id":{i}}}"#
        ))
        .await;
        rig.wait_for("status handled", move |r| r.ctx.handler_calls() == i + 1)
            .await;
    }
    // MAX_QUEUED held: the info reply in the outbox, the thaw, six
    // statuses behind it. The next frame is not read: every earlier
    // frame was consumed whole, so the 16 bytes of the stream take the
    // ping's first 16 bytes and the write never completes.
    let ping = b"{\"execute\":\"guest-ping\",\"id\":99}\n";
    let unread = tokio::time::timeout(Duration::from_millis(200), rig.peer.write_all(ping)).await;
    assert!(unread.is_err(), "nothing is read while MAX_QUEUED are held");
    assert_eq!(rig.ctx.handler_calls(), MAX_QUEUED as u64 + 1);
    a.release();
    rig.wait_for("thawed with nothing delivered", |r| {
        r.ctx.state.current() == FreezeState::Thawed
    })
    .await;
    assert!(!rig.ctx.marker.exists());
    let info = rig.json_reply().await;
    assert_eq!(info["id"], json!(1));
    assert!(info["return"]["version"].is_string(), "{info}");
    let thaw = rig.json_reply().await;
    assert_eq!(thaw, json!({"return": 4, "id": 2}));
    for i in 3..=MAX_QUEUED as u64 {
        assert_eq!(rig.json_reply().await, json!({"return": "frozen", "id": i}));
    }
    // Reading freed the queue: the ping's first 16 bytes are read now,
    // and the rest of the frame follows.
    rig.peer.write_all(&ping[16..]).await.unwrap();
    assert_eq!(rig.json_reply().await, json!({"return": {}, "id": 99}));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn controls_overtaking_a_waiting_trim_leave_it_its_place() {
    // Frozen; a thaw is inside FITHAW when the host sends, in one write,
    // a trim and seven statuses. The trim waits for the serial lane; the
    // statuses overtake it and are answered behind the thaw's reply.
    // When the thaw returns, the trim still has its place: it runs, and
    // every reply leaves in request order with the host reading all
    // along.
    let mut rig = rig();
    rig.send(r#"{"execute":"guest-fsfreeze-freeze"}"#).await;
    assert_eq!(rig.json_reply().await, json!({"return": 4}));
    let a = rig.kernel.script_thaw_gate(A);
    let _release = a.release_on_drop();
    rig.send(r#"{"execute":"guest-fsfreeze-thaw","id":1}"#)
        .await;
    let g = a.clone();
    rig.wait_for("thaw blocked", move |_| g.waiting() == 1)
        .await;
    let mut batch = String::from(r#"{"execute":"guest-fstrim","id":2}"#);
    batch.push('\n');
    for i in 3..=9 {
        batch.push_str(&format!(
            r#"{{"execute":"guest-fsfreeze-status","id":{i}}}"#
        ));
        batch.push('\n');
    }
    rig.peer.write_all(batch.as_bytes()).await.unwrap();
    // The freeze, the thaw and the statuses that have a place (the
    // ninth frame waits for one); the trim has not run.
    rig.wait_for("statuses handled", |r| r.ctx.handler_calls() >= 8)
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(rig.ctx.handler_calls(), 8, "the trim waits, one status too");
    assert!(
        !rig.kernel
            .calls()
            .iter()
            .any(|c| matches!(c, Call::Fitrim(..))),
        "no FITRIM while the thaw runs"
    );
    a.release();
    assert_eq!(rig.json_reply().await, json!({"return": 4, "id": 1}));
    let trimmed = rig.json_reply().await;
    assert_eq!(trimmed["id"], json!(2));
    assert!(trimmed["return"]["paths"].is_array(), "{trimmed}");
    for i in 3..=8 {
        assert_eq!(rig.json_reply().await, json!({"return": "frozen", "id": i}));
    }
    // The ninth frame had no place until the thaw's reply was taken: it
    // ran after the thaw.
    assert_eq!(rig.json_reply().await, json!({"return": "thawed", "id": 9}));
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_leaves_the_operation_owned() {
    // The peer goes away while the freeze reply is pending and B is
    // inside FIFREEZE. The session ends once the command in flight has
    // finished (at the deadline); the operation is untouched by that:
    // still registered, still owning B, and it settles when B returns.
    let mut rig = rig();
    let (gate, _release) = rig.freeze_blocked_at_b().await;
    let peer = std::mem::replace(&mut rig.peer, tokio::io::duplex(8).0);
    drop(peer);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !rig.session.is_finished(),
        "the command in flight is finished first"
    );
    rig.expire();
    let end = tokio::time::timeout(Duration::from_secs(10), &mut rig.session)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(end, SessionEnd::Eof | SessionEnd::WriteError(_)),
        "{end}"
    );
    assert!(
        rig.ctx.freeze_op().is_some(),
        "still owned after the session"
    );
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawing);
    rig.wait_for("A drained", |r| r.fithaws() == [A, A]).await;
    assert_eq!(gate.waiting(), 1);
    gate.release();
    rig.wait_for("settled", |r| r.ctx.state.current() == FreezeState::Thawed)
        .await;
    assert!(rig.ctx.freeze_op().is_none());
    assert!(!rig.ctx.marker.exists());
    drop(rig.cancel);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_thaws_behind_a_blocked_drain_are_bounded_and_answered_in_order() {
    // #43 §6: a host that keeps asking for recovery while a drain is
    // blocked inside FITHAW adds no work beyond the queue's places: the
    // thaws behind the running one wait in the serial lane (a thaw runs
    // beside a freeze only), a frame beyond the places is not read, and
    // once the drain moves each thaw is answered from the kernel's own
    // state (the drained targets answer "not frozen" at once), in order.
    // The watchdog and the coordinator hold their own capacity, so the
    // ability to request recovery is never rate-limited away. The stream
    // holds 16 bytes, so a frame the session does not read is a write
    // that does not complete.
    let mut rig = rig_with_buffer(16);
    let freeze = r#"{"execute":"guest-fsfreeze-freeze"}"#;
    rig.send(freeze).await;
    assert_eq!(rig.json_reply().await, json!({"return": 4}));
    let a = rig.kernel.script_thaw_gate(A);
    let _release = a.release_on_drop();
    let mut sent = freeze.len() as u64 + 1;
    for i in 1..=MAX_QUEUED as u64 {
        let thaw = format!(r#"{{"execute":"guest-fsfreeze-thaw","id":{i}}}"#);
        rig.send(&thaw).await;
        sent += thaw.len() as u64 + 1;
    }
    let g = a.clone();
    rig.wait_for("first thaw blocked", move |_| g.waiting() == 1)
        .await;
    // A write completes once the stream holds the bytes, before the
    // session has read them: wait until every frame sent was consumed.
    rig.wait_for("eight frames consumed", move |r| r.received() == sent)
        .await;
    assert_eq!(rig.ctx.handler_calls(), 2, "one thaw runs; the rest wait");
    // The places are taken: a ninth thaw is not read. Every earlier
    // frame was consumed whole, so the stream takes the ninth's first 16
    // bytes and the write never completes while the places are held.
    let ninth = b"{\"execute\":\"guest-fsfreeze-thaw\",\"id\":9}\n";
    let unread = tokio::time::timeout(Duration::from_millis(200), rig.peer.write_all(ninth)).await;
    assert!(unread.is_err(), "nothing is read while MAX_QUEUED are held");
    assert_eq!(rig.ctx.handler_calls(), 2);
    a.release();
    assert_eq!(rig.json_reply().await, json!({"return": 4, "id": 1}));
    for i in 2..=MAX_QUEUED as u64 {
        // Each later thaw is a recovery drain from `Thawed`: every target
        // answers EINVAL at once and the count is 0.
        assert_eq!(rig.json_reply().await, json!({"return": 0, "id": i}));
    }
    // Reading freed the places: the ninth's first 16 bytes are read now
    // and the rest of the frame follows.
    rig.peer.write_all(&ninth[16..]).await.unwrap();
    assert_eq!(rig.json_reply().await, json!({"return": 0, "id": 9}));
    // Bounded work: the first drain issues success + EINVAL per target,
    // every later one a single EINVAL per target.
    let fithaws = rig.fithaws().len();
    assert_eq!(fithaws, 4 * 2 + MAX_QUEUED * 4, "{fithaws}");
    assert_eq!(rig.ctx.state.current(), FreezeState::Thawed);
    assert!(!rig.ctx.marker.exists());
}
