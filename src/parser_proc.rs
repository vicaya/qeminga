//! Unprivileged host-facing QGA protocol parser process (`qeminga-parser`,
//! UID/GID `601`; OQ-10 §3.2, §4, §5.2; #78).
//!
//! Runs a **single-threaded `ppoll(2)` event loop** over the open virtio-serial
//! (or test PTY) channel descriptor and `IPC_FD` (`3`), with zero capabilities,
//! `/dev/null` on fds `0`/`1`/`2`, `RLIMIT_NOFILE <= 64`, `chdir("/")`,
//! `PR_SET_PDEATHSIG(SIGKILL)`, `PR_SET_NO_NEW_PRIVS`, and the parser seccomp
//! filter (`seccomp::parser_profile`).
//!
//! Security & protocol invariants preserved:
//! - Never reads guest files, config, `/proc`, or `/sys`, and never opens
//!   device paths (all channel opens/reopens go through the executor's
//!   `RequestChannelReopen` + `SCM_RIGHTS` verified handoff).
//! - Preserves design §5.7 lane scheduling (`MAX_CONTROLS = 3`,
//!   `MAX_QUEUED = 8`, `MAX_REPLY_BYTES = 64 KiB`, `Thaw` overtaking queued
//!   serial commands while `Freeze` is in flight, strict request-order wire
//!   delivery) and virtio-serial `HostState::VirtioHostDisconnected` draining
//!   without closing `guest_connected`.
//! - Binds every IPC request to a monotonic `session_gen` (incremented on every
//!   channel disconnect/EOF/reopen boundary) and discards any late IPC reply
//!   whose `session_gen` does not match the active host session (OQ-10 §5.2).
//! - Enforces final QGA wire size limits (`1 MiB` for `guest-get-fsinfo` and
//!   `guest-fstrim`, `256 KiB` for `guest-network-get-interfaces`, `512 KiB`
//!   for `guest-get-osinfo`) without truncating replies or dropping the session.
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, ppoll};
use nix::sys::time::TimeSpec;
use serde_json::json;

use crate::audit::project_method;
use crate::channel::{
    DrainOutcome, HOST_WAIT_INITIAL, HOST_WAIT_MAX, HostState, InputQueue, Kind, MAX_CONTROLS,
    MAX_QUEUED, MAX_REPLY_BYTES, POLLRDHUP_FLAG, classify_channel_revents,
    drain_disconnected_input, poll_host_state,
};
use crate::config::Hardening;
use crate::daemon::{EX_CONFIG, EX_NOPERM, EX_OSERR, EX_SOFTWARE, PARSER_USER};
use crate::framing::{DecodeEvent, FrameDecoder, encode};
use crate::handlers::fsfreeze::FreezeListArgs;
use crate::handlers::fsinfo::MAX_FSINFO_REPLY_BYTES;
use crate::handlers::fstrim::{FstrimArgs, bounded_fstrim_reply};
use crate::handlers::info::AgentInfo;
use crate::handlers::interfaces::MAX_INTERFACES_REPLY_BYTES;
use crate::handlers::osinfo::MAX_OSINFO_REPLY_BYTES;
use crate::handlers::shutdown::{ShutdownArgs, ShutdownMode};
use crate::handlers::sync::SyncArgs;
use crate::handlers::{Command, NoArgs, bounded_reply};
use crate::ipc::{
    AssembledMessage, CommandCapability, FlushOutcome, FreezeListSelection, FsInfoDto, IPC_FD,
    InterfaceDto, IpcErrorCode, IpcOutbox, IpcRequest, IpcResponse, MAX_PACKET_BYTES,
    ParseRejection, ParseRejectionKind, PeerRole, ProjectedMethod, ReceivedResponse,
    StreamAssembler, TrimPathDto,
};
use crate::kernel::caps::{Outcome, SystemCaps, drop_parser_privileges};
use crate::kernel::ipc::recv_packet;
use crate::kernel::process::{
    INITIAL_CHANNEL_FD, PARSER_READY_FD, adopt_inherited_fd_cloexec, apply_parser_rlimit_and_chdir,
    arm_pdeathsig_and_verify_parent, verify_stdio_is_dev_null,
};
use crate::proto::{Error as ProtoError, Request, Response, arguments, parse_request};

/// Read buffer size per channel `read(2)`.
const CHANNEL_READ_CHUNK: usize = 4096;

/// Parsed CLI options for the internal `--internal-parser` child entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParserOptions {
    /// Expected executor parent PID for the post-drop `PR_SET_PDEATHSIG`
    /// race check.
    pub parent_pid: u32,
    /// Active hardening mode inherited from the executor's validated config.
    pub hardening: Hardening,
    /// Whether the executor's configuration enables seccomp.
    pub seccomp: bool,
    /// Whether the executor passed an already-open verified channel descriptor
    /// on [`INITIAL_CHANNEL_FD`] (`4`).
    pub has_initial_channel: bool,
}

/// Reason [`run_parser_loop`] returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParserExit {
    /// Executor closed `IPC_FD` cleanly (graceful shutdown or supervision stop).
    IpcClosed,
    /// Executor reported terminal `EBUSY` on channel open/reopen.
    ChannelTerminalBusy,
    /// Malformed IPC packet, unexpected descriptor, or transport error.
    ProtocolViolation,
}

/// Entry point for `qeminga --internal-parser ...` (OQ-10 §3.2, #78).
///
/// Drops to `qeminga-parser` (UID/GID `601`, zero capabilities), changes
/// directory to `/`, sets `RLIMIT_NOFILE <= 64`, arms
/// `PR_SET_PDEATHSIG(SIGKILL)` + `getppid() == parent_pid`, installs
/// `seccomp::parser_profile`, signals readiness on `PARSER_READY_FD` (`5`) and
/// closes it, then runs the single-threaded `ppoll` serving loop.
pub fn run_parser_main(opts: ParserOptions) -> ExitCode {
    if verify_stdio_is_dev_null().is_err() {
        return ExitCode::from(EX_OSERR);
    }
    let Ok(ipc_fd) = adopt_inherited_fd_cloexec(IPC_FD) else {
        return ExitCode::from(EX_OSERR);
    };
    let initial_channel = if opts.has_initial_channel {
        match adopt_inherited_fd_cloexec(INITIAL_CHANNEL_FD) {
            Ok(fd) => Some(fd),
            Err(_) => return ExitCode::from(EX_OSERR),
        }
    } else {
        None
    };
    let Ok(ready_fd) = adopt_inherited_fd_cloexec(PARSER_READY_FD) else {
        return ExitCode::from(EX_OSERR);
    };

    if set_nonblocking(ipc_fd.as_fd()).is_err() {
        return ExitCode::from(EX_OSERR);
    }
    if let Some(ch) = initial_channel.as_ref()
        && set_nonblocking(ch.as_fd()).is_err()
    {
        return ExitCode::from(EX_OSERR);
    }

    match drop_parser_privileges(PARSER_USER, &SystemCaps) {
        Ok(Outcome::Dropped) => {}
        Ok(Outcome::SkippedUnprivileged) if opts.hardening.is_enforced() => {
            return ExitCode::from(EX_CONFIG);
        }
        Ok(Outcome::SkippedUnprivileged) => {}
        Err(_) => return ExitCode::from(EX_NOPERM),
    }

    if apply_parser_rlimit_and_chdir().is_err() {
        return ExitCode::from(EX_OSERR);
    }

    match arm_pdeathsig_and_verify_parent(opts.parent_pid) {
        Ok(true) => {}
        Ok(false) => return ExitCode::SUCCESS,
        Err(_) => return ExitCode::from(EX_OSERR),
    }

    if let Err(code) = install_parser_seccomp(opts.hardening, opts.seccomp) {
        return ExitCode::from(code);
    }

    // Signal readiness to executor and immediately close `ready_fd` so the
    // serving process holds zero extra descriptors beyond 0/1/2, IPC_FD (3),
    // and the channel descriptor (if open).
    if write_all_single_byte(ready_fd.as_fd(), b'R').is_err() {
        return ExitCode::from(EX_OSERR);
    }
    drop(ready_fd);

    match run_parser_loop(ipc_fd, initial_channel) {
        ParserExit::IpcClosed | ParserExit::ChannelTerminalBusy => ExitCode::SUCCESS,
        ParserExit::ProtocolViolation => ExitCode::from(EX_SOFTWARE),
    }
}

fn install_parser_seccomp(hardening: Hardening, enabled: bool) -> Result<(), u8> {
    #[cfg(feature = "seccomp")]
    {
        if !enabled {
            return if hardening.is_enforced() {
                Err(EX_CONFIG)
            } else {
                Ok(())
            };
        }
        let program = match crate::seccomp::parser_profile(crate::seccomp::Target::current()) {
            Ok(p) => p,
            Err(_) => {
                return if hardening.is_enforced() {
                    Err(EX_CONFIG)
                } else {
                    Ok(())
                };
            }
        };
        match crate::seccomp::install(&program) {
            Ok(()) => Ok(()),
            Err(_) if hardening.is_enforced() => Err(EX_CONFIG),
            Err(_) => Ok(()),
        }
    }
    #[cfg(not(feature = "seccomp"))]
    {
        let _ = enabled;
        if hardening.is_enforced() {
            Err(EX_CONFIG)
        } else {
            Ok(())
        }
    }
}

fn set_nonblocking(fd: std::os::fd::BorrowedFd<'_>) -> io::Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    let next = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(next)).map_err(io::Error::from)?;
    Ok(())
}

fn write_all_single_byte(fd: std::os::fd::BorrowedFd<'_>, byte: u8) -> io::Result<()> {
    let buf = [byte];
    loop {
        match nix::unistd::write(fd, &buf) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Err(Errno::EINTR) => continue,
            Err(err) => return Err(io::Error::from(err)),
        }
    }
}

/// Prepared IPC request derived from a decoded host frame (pure, side-effect-free).
#[derive(Debug, Clone)]
struct PreparedRequest {
    lane: Kind,
    ipc_request: IpcRequest,
    meta: ReplyMeta,
}

/// Metadata retained for one in-flight request to format the executor's typed
/// response back into QGA JSON without letting the executor emit raw JSON.
#[derive(Debug, Clone)]
enum ReplyMeta {
    /// Normal allowlisted command with optional QGA `id` and sentinel flag.
    Command {
        cmd: Command,
        id: Option<i64>,
        sentinel: bool,
    },
    /// Rejected frame (`Oversized`, `ParseError`, `UnknownMethod`): parser
    /// sends `ReportParseRejection`, waits for `OkAck`, and emits `reply`.
    LocalRejection { reply: Option<Vec<u8>> },
}

/// Translates one [`DecodeEvent`] from [`FrameDecoder`] into a typed
/// [`PreparedRequest`] while preserving `C-7` exact evaluation precedence.
fn prepare_frame(event: DecodeEvent) -> PreparedRequest {
    match event {
        DecodeEvent::Oversized { discarded } => PreparedRequest {
            lane: Kind::Control,
            ipc_request: IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::Oversized,
                frame_len: u32::try_from(discarded).unwrap_or(u32::MAX),
                id: None,
                method: None,
            }),
            meta: ReplyMeta::LocalRejection { reply: None },
        },
        DecodeEvent::Frame { bytes, .. } => {
            let frame_len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            let req = match parse_request(&bytes) {
                Ok(req) => req,
                Err(err) => {
                    let wire = encode(&Response::error(None, &err).to_json(), false);
                    return PreparedRequest {
                        lane: Kind::Control,
                        ipc_request: IpcRequest::ReportParseRejection(ParseRejection {
                            kind: ParseRejectionKind::ParseError,
                            frame_len,
                            id: None,
                            method: None,
                        }),
                        meta: ReplyMeta::LocalRejection { reply: Some(wire) },
                    };
                }
            };
            let Some(cmd) = Command::from_method(&req.method) else {
                let wire = encode(
                    &Response::error(req.id, &ProtoError::CommandNotFound(req.method.clone()))
                        .to_json(),
                    false,
                );
                return PreparedRequest {
                    lane: Kind::Ordinary,
                    ipc_request: IpcRequest::ReportParseRejection(ParseRejection {
                        kind: ParseRejectionKind::UnknownMethod,
                        frame_len,
                        id: req.id,
                        method: ProjectedMethod::from_method_field(&project_method(&req.method)),
                    }),
                    meta: ReplyMeta::LocalRejection { reply: Some(wire) },
                };
            };
            prepare_allowlisted(cmd, &req, frame_len)
        }
    }
}

/// Exhaustive static `match` translating an allowlisted [`Command`] and its
/// schema-validated arguments into an [`IpcRequest`].
///
/// If arguments fail schema validation, sends `ReportParseRejection` tagged
/// with `kind: ParseError` and `method: Some(Full(cmd.name()))` so the executor
/// still evaluates `is_enabled -> rate_limit -> freeze_gate` **before**
/// reporting `InvalidArguments` (`C-7`).
fn prepare_allowlisted(cmd: Command, req: &Request, frame_len: u32) -> PreparedRequest {
    let sentinel = cmd.sends_sentinel();
    let lane = cmd.lane();
    let typed: Result<IpcRequest, ProtoError> = match cmd {
        Command::Ping => arguments::<NoArgs>(req).map(|_| IpcRequest::Ping),
        Command::Info => arguments::<NoArgs>(req).map(|_| IpcRequest::Info),
        Command::Sync => arguments::<SyncArgs>(req).map(|a| IpcRequest::Sync { id: a.id }),
        Command::SyncDelimited => {
            arguments::<SyncArgs>(req).map(|a| IpcRequest::SyncDelimited { id: a.id })
        }
        Command::GetOsInfo => arguments::<NoArgs>(req).map(|_| IpcRequest::GetOsInfo),
        Command::NetworkGetInterfaces => {
            arguments::<NoArgs>(req).map(|_| IpcRequest::NetworkGetInterfaces)
        }
        Command::GetFsInfo => arguments::<NoArgs>(req).map(|_| IpcRequest::GetFsInfo),
        Command::FsfreezeStatus => arguments::<NoArgs>(req).map(|_| IpcRequest::FsfreezeStatus),
        Command::FsfreezeFreeze => arguments::<NoArgs>(req).map(|_| IpcRequest::FsfreezeFreeze),
        Command::FsfreezeFreezeList => arguments::<FreezeListArgs>(req).map(|a| {
            let selection = match a.mountpoints {
                None => FreezeListSelection::Omitted,
                Some(list) => FreezeListSelection::Present(list),
            };
            IpcRequest::FsfreezeFreezeList(selection)
        }),
        Command::FsfreezeThaw => arguments::<NoArgs>(req).map(|_| IpcRequest::FsfreezeThaw),
        Command::Fstrim => arguments::<FstrimArgs>(req).map(|a| IpcRequest::Fstrim {
            minimum: a.minimum.unwrap_or(0),
        }),
        Command::Shutdown => arguments::<ShutdownArgs>(req).map(|a| IpcRequest::Shutdown {
            mode: a.mode.unwrap_or(ShutdownMode::Powerdown),
        }),
        Command::SuspendRam => arguments::<NoArgs>(req).map(|_| IpcRequest::SuspendRam),
    };

    match typed {
        Ok(ipc_request) => PreparedRequest {
            lane,
            ipc_request,
            meta: ReplyMeta::Command {
                cmd,
                id: req.id,
                sentinel,
            },
        },
        Err(_) => PreparedRequest {
            lane,
            ipc_request: IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::ParseError,
                frame_len,
                id: req.id,
                method: Some(ProjectedMethod::Full(cmd.name().to_owned())),
            }),
            meta: ReplyMeta::Command {
                cmd,
                id: req.id,
                sentinel,
            },
        },
    }
}

/// Formats a typed [`IpcResponse`] from the executor into QGA wire bytes
/// according to `meta`, enforcing final wire size limits without truncating.
///
/// Returns `Err(())` on a protocol mismatch (e.g., an unexpected variant for
/// the originating request).
fn format_wire_reply(meta: &ReplyMeta, resp: IpcResponse) -> Result<Option<Vec<u8>>, ()> {
    match meta {
        ReplyMeta::LocalRejection { reply } => match resp {
            IpcResponse::OkAck => Ok(reply.clone()),
            _ => Err(()),
        },
        ReplyMeta::Command { cmd, id, sentinel } => {
            let result: Result<serde_json::Value, ProtoError> = match resp {
                IpcResponse::OkSilent => {
                    return if !cmd.success_response() {
                        Ok(None)
                    } else {
                        Err(())
                    };
                }
                IpcResponse::OkEmpty if *cmd == Command::Ping => Ok(json!({})),
                IpcResponse::OkInfo(caps) if *cmd == Command::Info => {
                    let info = AgentInfo {
                        version: crate::VERSION,
                        supported_commands: caps
                            .into_iter()
                            .map(CommandCapability::to_command_info)
                            .collect(),
                    };
                    serde_json::to_value(&info)
                        .map_err(|e| ProtoError::Internal(format!("info: cannot encode: {e}")))
                }
                IpcResponse::OkI64(n) if matches!(cmd, Command::Sync | Command::SyncDelimited) => {
                    Ok(json!(n))
                }
                IpcResponse::OkFreezeStatus(state) if *cmd == Command::FsfreezeStatus => {
                    Ok(json!(state.as_str()))
                }
                IpcResponse::OkCount(n)
                    if matches!(
                        cmd,
                        Command::FsfreezeFreeze
                            | Command::FsfreezeFreezeList
                            | Command::FsfreezeThaw
                    ) =>
                {
                    Ok(json!(n))
                }
                IpcResponse::OkOsInfo(osinfo) if *cmd == Command::GetOsInfo => {
                    bounded_reply("osinfo", osinfo.as_ref(), MAX_OSINFO_REPLY_BYTES)
                }
                IpcResponse::OkInterfaces(ifaces) if *cmd == Command::NetworkGetInterfaces => {
                    let list: Vec<_> = ifaces.iter().map(InterfaceDto::to_handler).collect();
                    bounded_reply("interfaces", &list, MAX_INTERFACES_REPLY_BYTES)
                }
                IpcResponse::OkFsInfo(fsinfos) if *cmd == Command::GetFsInfo => {
                    let list: Vec<_> = fsinfos.iter().map(FsInfoDto::to_handler).collect();
                    bounded_reply("fsinfo", &list, MAX_FSINFO_REPLY_BYTES)
                }
                IpcResponse::OkFstrim(entries) if *cmd == Command::Fstrim => {
                    let trim_resp = TrimPathDto::to_trim_response(&entries);
                    bounded_fstrim_reply(&trim_resp)
                }
                IpcResponse::Err(code) => Err(code.to_proto_error()),
                _ => return Err(()),
            };
            let wire = encode(&Response::from_result(*id, result).to_json(), *sentinel);
            Ok(Some(wire))
        }
    }
}

/// One slot in the parser's per-session request queue (preserving exact
/// request order for wire replies, matching `src/channel.rs` §5.7).
enum ParserSlot {
    /// Decoded; waiting for its lane or reply budget before IPC submission.
    Waiting(PreparedRequest),
    /// Submitted to executor under `req_id`; awaiting matching `(session_gen, req_id)`.
    Pending {
        lane: Kind,
        req_id: u64,
        meta: ReplyMeta,
    },
    /// Completed; wire reply waiting behind earlier slots.
    Done(Option<Vec<u8>>),
}

/// Active lane counts across `Pending` slots (exact match with `channel.rs`).
#[derive(Default)]
struct Lanes {
    controls: usize,
    freeze: bool,
    thaw_or_ordinary: bool,
}

/// Exclusive (non-control) in-flight IPC request from a departed host session
/// that is still executing in the executor. Retained across `session_gen`
/// boundaries until its late executor reply arrives so a replacement session
/// cannot start a freeze while an earlier serial operation (e.g. `fstrim`) is
/// still running (design §5.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RetiredLane {
    session_gen: u64,
    req_id: u64,
    lane: Kind,
}

impl Lanes {
    fn of(slots: &VecDeque<ParserSlot>, retired: &[RetiredLane]) -> Self {
        let mut lanes = Lanes::default();
        for slot in slots {
            if let ParserSlot::Pending { lane, .. } = slot {
                lanes.take(*lane);
            }
        }
        for entry in retired {
            lanes.take(entry.lane);
        }
        lanes
    }

    fn take(&mut self, kind: Kind) {
        match kind {
            Kind::Control => self.controls += 1,
            Kind::Freeze => self.freeze = true,
            Kind::Thaw | Kind::Ordinary => self.thaw_or_ordinary = true,
        }
    }

    fn exclusive(&self) -> bool {
        self.freeze || self.thaw_or_ordinary
    }
}

/// Byte-level non-blocking wire reply outbox preserving exact reply order.
#[derive(Default)]
struct WireOutbox {
    replies: VecDeque<Vec<u8>>,
    written: usize,
    pending: usize,
}

impl WireOutbox {
    fn is_empty(&self) -> bool {
        self.replies.is_empty()
    }

    fn count(&self) -> usize {
        self.replies.len()
    }

    fn pending_bytes(&self) -> usize {
        self.pending
    }

    fn push(&mut self, reply: Vec<u8>) {
        self.pending += reply.len();
        self.replies.push_back(reply);
    }

    fn abandon(&mut self) {
        self.replies.clear();
        self.written = 0;
        self.pending = 0;
    }

    /// Writes as many queued reply bytes as `fd` accepts without blocking.
    fn flush(&mut self, fd: std::os::fd::BorrowedFd<'_>) -> Result<(), io::Error> {
        while let Some(front) = self.replies.front() {
            match nix::unistd::write(fd, &front[self.written..]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(n) => {
                    self.written += n;
                    self.pending -= n;
                    if self.written == front.len() {
                        self.replies.pop_front();
                        self.written = 0;
                    }
                }
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => return Ok(()),
                Err(err) => return Err(io::Error::from(err)),
            }
        }
        Ok(())
    }
}

/// Active host session attached to an open verified channel descriptor.
struct OpenSession {
    fd: OwnedFd,
    decoder: FrameDecoder,
    slots: VecDeque<ParserSlot>,
    wire_outbox: WireOutbox,
    write_failed: bool,
}

impl OpenSession {
    fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            decoder: FrameDecoder::new(),
            slots: VecDeque::new(),
            wire_outbox: WireOutbox::default(),
            write_failed: false,
        }
    }

    fn done_reply_bytes(&self) -> usize {
        self.slots
            .iter()
            .filter_map(|s| match s {
                ParserSlot::Done(Some(reply)) => Some(reply.len()),
                _ => None,
            })
            .sum()
    }

    fn input_paused(&self) -> bool {
        self.slots.len() + self.wire_outbox.count() >= MAX_QUEUED
            || self.wire_outbox.pending_bytes() + self.done_reply_bytes() >= MAX_REPLY_BYTES
    }

    /// Moves leading `Done` slots into `wire_outbox` in exact request order.
    fn promote_done(&mut self) {
        while let Some(ParserSlot::Done(_)) = self.slots.front() {
            if let Some(ParserSlot::Done(Some(reply))) = self.slots.pop_front()
                && !self.write_failed
            {
                self.wire_outbox.push(reply);
            }
        }
    }

    /// Admits waiting slots within the remaining `MAX_QUEUED` window and
    /// `MAX_REPLY_BYTES` outbox budget whose lane is free, pushing typed
    /// requests onto `ipc_outbox`.
    fn admit(
        &mut self,
        session_gen: u64,
        next_req_id: &mut u64,
        retired: &[RetiredLane],
        ipc_outbox: &mut IpcOutbox,
    ) -> Result<(), ()> {
        if self.wire_outbox.pending_bytes() >= MAX_REPLY_BYTES {
            return Ok(());
        }
        let window = MAX_QUEUED.saturating_sub(self.wire_outbox.count());
        let mut lanes = Lanes::of(&self.slots, retired);
        let mut serial_waiting = false;
        for slot in self.slots.iter_mut().take(window) {
            let ParserSlot::Waiting(prep) = slot else {
                continue;
            };
            let kind = prep.lane;
            let free = match kind {
                Kind::Control => lanes.controls < MAX_CONTROLS,
                Kind::Thaw => !lanes.thaw_or_ordinary,
                Kind::Freeze | Kind::Ordinary => !lanes.exclusive() && !serial_waiting,
            };
            if !free {
                if kind != Kind::Control {
                    serial_waiting = true;
                }
                continue;
            }
            if let ParserSlot::Waiting(prep) = std::mem::replace(slot, ParserSlot::Done(None)) {
                let req_id = *next_req_id;
                *next_req_id = next_req_id.wrapping_add(1).max(1);
                let host_id = match &prep.meta {
                    ReplyMeta::Command { id, .. } => *id,
                    ReplyMeta::LocalRejection { .. } => None,
                };
                if ipc_outbox
                    .push_request_with_id(session_gen, req_id, host_id, &prep.ipc_request)
                    .is_err()
                {
                    // Request encoding failed its own bound (e.g., an absurdly
                    // long entry past protocol cap): emit a local error rather
                    // than stalling the slot.
                    let fallback = match &prep.meta {
                        ReplyMeta::Command { id, sentinel, .. } => Some(encode(
                            &Response::error(
                                *id,
                                &ProtoError::InvalidArguments(
                                    "request exceeds IPC payload bound".to_owned(),
                                ),
                            )
                            .to_json(),
                            *sentinel,
                        )),
                        ReplyMeta::LocalRejection { reply } => reply.clone(),
                    };
                    *slot = ParserSlot::Done(fallback);
                    continue;
                }
                *slot = ParserSlot::Pending {
                    lane: kind,
                    req_id,
                    meta: prep.meta,
                };
                lanes.take(kind);
            }
        }
        Ok(())
    }

    /// Delivers a matching `ReceivedResponse` into its `Pending` slot.
    /// Returns `Err(())` on unexpected `req_id` or mismatched response variant.
    fn complete_response(&mut self, resp: ReceivedResponse) -> Result<(), ()> {
        let Some(slot) = self.slots.iter_mut().find(|s| {
            matches!(
                s,
                ParserSlot::Pending { req_id, .. } if *req_id == resp.req_id
            )
        }) else {
            // Stale or unknown req_id within the current generation: ignore
            // cleanly if it was already dropped, otherwise fail closed on
            // unexpected OkChannelFd.
            return if matches!(resp.response, IpcResponse::OkChannelFd) {
                Err(())
            } else {
                Ok(())
            };
        };
        let ParserSlot::Pending { meta, .. } = slot else {
            return Err(());
        };
        let formatted = format_wire_reply(meta, resp.response)?;
        *slot = ParserSlot::Done(formatted);
        Ok(())
    }
}

/// Channel lifecycle state inside the parser's single-threaded `ppoll` loop.
enum ChannelState {
    /// Active session on an open verified channel descriptor.
    Open(OpenSession),
    /// Open Linux `virtio_console` descriptor whose host side is disconnected;
    /// kept open to preserve `guest_connected` while draining stale input and
    /// polling readiness with bounded backoff (`HOST_WAIT_INITIAL` -> `HOST_WAIT_MAX`).
    HostWaiting {
        fd: OwnedFd,
        input: InputQueue,
        delay: Duration,
        next_probe: Instant,
    },
    /// No open channel descriptor; asking executor for a verified descriptor
    /// via `RequestChannelReopen`.
    NeedReopen { in_flight_req_id: Option<u64> },
}

/// Runs the single-threaded `ppoll(2)` parser loop over `ipc_fd` and an
/// optional initial verified channel descriptor until the executor closes
/// `ipc_fd`, reports terminal `EBUSY`, or an IPC protocol violation occurs.
pub fn run_parser_loop(ipc_fd: OwnedFd, initial_channel: Option<OwnedFd>) -> ParserExit {
    run_parser_loop_with_probe(ipc_fd, initial_channel, poll_host_state)
}

/// Testable entry point for [`run_parser_loop`] with an injectable host-state
/// probe for virtio-serial disconnect simulation.
pub(crate) fn run_parser_loop_with_probe<P>(
    ipc_fd: OwnedFd,
    initial_channel: Option<OwnedFd>,
    probe: P,
) -> ParserExit
where
    P: Fn(std::os::fd::BorrowedFd<'_>) -> HostState + Send + Sync,
{
    let mut ipc_outbox = IpcOutbox::new();
    let mut ipc_asm = StreamAssembler::new(PeerRole::Parser);
    let mut session_gen: u64 = 1;
    let mut next_req_id: u64 = 1;
    let mut retired_pending: Vec<RetiredLane> = Vec::new();
    let mut read_buf = [0u8; CHANNEL_READ_CHUNK];

    let mut ch_state = match initial_channel {
        Some(fd) => classify_fresh_fd(fd, &probe),
        None => ChannelState::NeedReopen {
            in_flight_req_id: None,
        },
    };

    loop {
        // 1. Drive state transitions before blocking in `ppoll`.
        match &mut ch_state {
            ChannelState::Open(sess) => {
                sess.promote_done();
                if sess
                    .admit(
                        session_gen,
                        &mut next_req_id,
                        &retired_pending,
                        &mut ipc_outbox,
                    )
                    .is_err()
                {
                    return ParserExit::ProtocolViolation;
                }
                sess.promote_done();
            }
            ChannelState::NeedReopen { in_flight_req_id } if in_flight_req_id.is_none() => {
                let req_id = next_req_id;
                next_req_id = next_req_id.wrapping_add(1).max(1);
                if ipc_outbox
                    .push_request(session_gen, req_id, &IpcRequest::RequestChannelReopen)
                    .is_err()
                {
                    return ParserExit::ProtocolViolation;
                }
                *in_flight_req_id = Some(req_id);
            }
            ChannelState::NeedReopen { .. } | ChannelState::HostWaiting { .. } => {}
        }

        // Flush any newly queued IPC packets non-blockingly before `ppoll`.
        match ipc_outbox.flush(ipc_fd.as_fd()) {
            Ok(FlushOutcome::Drained | FlushOutcome::WouldBlock) => {}
            Err(_) => return ParserExit::IpcClosed,
        }

        // 2. Poll IPC_FD and (when Open) channel_fd in a single `ppoll(2)`.
        let ipc_events = if ipc_outbox.is_empty() {
            PollFlags::POLLIN
        } else {
            PollFlags::POLLIN | PollFlags::POLLOUT
        };
        let timeout_spec = match &ch_state {
            ChannelState::HostWaiting { next_probe, .. } => {
                let dur = next_probe.saturating_duration_since(Instant::now());
                Some(duration_to_timespec(dur))
            }
            _ => None,
        };

        let (ipc_revents, ch_revents) = match &ch_state {
            ChannelState::Open(sess) => {
                let mut ch_events = POLLRDHUP_FLAG;
                if !sess.input_paused() {
                    ch_events |= PollFlags::POLLIN;
                }
                if !sess.wire_outbox.is_empty() && !sess.write_failed {
                    ch_events |= PollFlags::POLLOUT;
                }
                let mut fds = [
                    PollFd::new(ipc_fd.as_fd(), ipc_events),
                    PollFd::new(sess.fd.as_fd(), ch_events),
                ];
                match ppoll(&mut fds, timeout_spec, None) {
                    Ok(_) => (
                        fds[0].revents().unwrap_or(PollFlags::POLLERR),
                        Some(fds[1].revents().unwrap_or(PollFlags::POLLERR)),
                    ),
                    Err(Errno::EINTR) => continue,
                    Err(_) => return ParserExit::ProtocolViolation,
                }
            }
            ChannelState::HostWaiting { .. } | ChannelState::NeedReopen { .. } => {
                let mut fds = [PollFd::new(ipc_fd.as_fd(), ipc_events)];
                match ppoll(&mut fds, timeout_spec, None) {
                    Ok(_) => (fds[0].revents().unwrap_or(PollFlags::POLLERR), None),
                    Err(Errno::EINTR) => continue,
                    Err(_) => return ParserExit::ProtocolViolation,
                }
            }
        };

        // 3. Flush writable IPC outbox.
        if ipc_revents.contains(PollFlags::POLLOUT) {
            match ipc_outbox.flush(ipc_fd.as_fd()) {
                Ok(FlushOutcome::Drained | FlushOutcome::WouldBlock) => {}
                Err(_) => return ParserExit::IpcClosed,
            }
        }

        // 4. Drain all available IPC packets from the executor.
        if ipc_revents.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR) {
            loop {
                match recv_packet(ipc_fd.as_fd(), MAX_PACKET_BYTES) {
                    Ok(Some(pkt)) => match ipc_asm.push(pkt) {
                        Ok(Some(AssembledMessage::Response(resp))) => {
                            if let Some(exit) = handle_ipc_response(
                                resp,
                                &mut session_gen,
                                &mut ch_state,
                                &mut retired_pending,
                                &probe,
                            ) {
                                return exit;
                            }
                        }
                        Ok(Some(AssembledMessage::Request(_))) => {
                            return ParserExit::ProtocolViolation;
                        }
                        Ok(None) => {}
                        Err(_) => return ParserExit::ProtocolViolation,
                    },
                    Ok(None) => return ParserExit::IpcClosed,
                    Err(Errno::EAGAIN) => break,
                    Err(Errno::EINTR) => continue,
                    Err(_) => return ParserExit::IpcClosed,
                }
            }
        }

        // 5. Handle `HostWaiting` probe timer expiration.
        if let ChannelState::HostWaiting { next_probe, .. } = &ch_state
            && Instant::now() >= *next_probe
        {
            let prev = std::mem::replace(
                &mut ch_state,
                ChannelState::NeedReopen {
                    in_flight_req_id: None,
                },
            );
            if let ChannelState::HostWaiting {
                fd,
                mut input,
                delay,
                ..
            } = prev
            {
                match probe(fd.as_fd()) {
                    HostState::Ready => {
                        if input == InputQueue::NeedsBoundary {
                            // Ambiguous disconnect-to-ready transition: drop fd
                            // and ask executor for a fresh verified descriptor.
                            drop(fd);
                            session_gen = session_gen.wrapping_add(1).max(1);
                            ch_state = ChannelState::NeedReopen {
                                in_flight_req_id: None,
                            };
                        } else {
                            ch_state = ChannelState::Open(OpenSession::new(fd));
                        }
                    }
                    HostState::Closed => {
                        drop(fd);
                        session_gen = session_gen.wrapping_add(1).max(1);
                        ch_state = ChannelState::NeedReopen {
                            in_flight_req_id: None,
                        };
                    }
                    HostState::VirtioHostDisconnected => {
                        match drain_disconnected_input(fd.as_fd(), &probe) {
                            DrainOutcome::Drained => input = InputQueue::Clean,
                            DrainOutcome::Incomplete => input = InputQueue::NeedsBoundary,
                            DrainOutcome::Reset => {
                                drop(fd);
                                session_gen = session_gen.wrapping_add(1).max(1);
                                ch_state = ChannelState::NeedReopen {
                                    in_flight_req_id: None,
                                };
                                continue;
                            }
                        }
                        let next_delay = (delay * 2).clamp(HOST_WAIT_INITIAL, HOST_WAIT_MAX);
                        ch_state = ChannelState::HostWaiting {
                            fd,
                            input,
                            delay: next_delay,
                            next_probe: Instant::now() + next_delay,
                        };
                    }
                }
            }
            continue;
        }

        // 6. Service active channel readiness: classify hangup/error FIRST
        //    before any write or read (§5.7), then flush replies and read frames.
        if let (ChannelState::Open(sess), Some(revents)) = (&mut ch_state, ch_revents) {
            let outcome = match service_open_channel_revents(
                sess,
                revents,
                session_gen,
                &mut next_req_id,
                &retired_pending,
                &mut ipc_outbox,
                &mut read_buf,
            ) {
                Ok(outcome) => outcome,
                Err(()) => return ParserExit::ProtocolViolation,
            };

            if let ChannelEventOutcome::EndSession {
                observed_disconnect,
            } = outcome
            {
                // Flush any requests already admitted before retiring this
                // session generation.
                match ipc_outbox.flush(ipc_fd.as_fd()) {
                    Ok(FlushOutcome::Drained | FlushOutcome::WouldBlock) => {}
                    Err(_) => return ParserExit::IpcClosed,
                }
                let prev = std::mem::replace(
                    &mut ch_state,
                    ChannelState::NeedReopen {
                        in_flight_req_id: None,
                    },
                );
                if let ChannelState::Open(old_sess) = prev {
                    // Retain exclusive (non-control) in-flight lane ownership
                    // across the generation bump until the executor finishes
                    // and returns the stale-generation reply (design §5.7).
                    for slot in &old_sess.slots {
                        if let ParserSlot::Pending { lane, req_id, .. } = slot
                            && *lane != Kind::Control
                        {
                            retired_pending.push(RetiredLane {
                                session_gen,
                                req_id: *req_id,
                                lane: *lane,
                            });
                        }
                    }
                    // Increment `session_gen` on EVERY disconnect/EOF/reopen
                    // boundary so any late executor reply for the departed
                    // peer is discarded without writing to a replacement peer.
                    session_gen = session_gen.wrapping_add(1).max(1);
                    ch_state = teardown_channel(old_sess.fd, observed_disconnect, &probe);
                }
            }
        }
    }
}

/// Outcome of handling one `ppoll` readiness event on an [`OpenSession`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChannelEventOutcome {
    /// Session remains active.
    Continue,
    /// Peer hangup, EOF, or I/O error observed; tear down the active session
    /// without performing any further channel reads or writes.
    EndSession { observed_disconnect: bool },
}

/// Processes one `ppoll` readiness event on an active [`OpenSession`].
///
/// Closed/hangup readiness (`POLLHUP`, `POLLRDHUP`, `POLLERR`, `POLLNVAL`) is
/// classified **before** any channel `write(2)` or `read(2)` (design §5.7), so
/// undelivered replies are abandoned and driver-queued bytes from a departed
/// host session are routed straight to `teardown_channel` /
/// `drain_disconnected_input` instead of being executed as new commands.
fn service_open_channel_revents(
    sess: &mut OpenSession,
    revents: PollFlags,
    session_gen: u64,
    next_req_id: &mut u64,
    retired: &[RetiredLane],
    ipc_outbox: &mut IpcOutbox,
    read_buf: &mut [u8],
) -> Result<ChannelEventOutcome, ()> {
    // 6a. Classify closed/hangup readiness FIRST (§5.7).
    let revents_state = classify_channel_revents(revents);
    if revents_state != HostState::Ready {
        sess.write_failed = true;
        sess.wire_outbox.abandon();
        return Ok(ChannelEventOutcome::EndSession {
            observed_disconnect: revents_state == HostState::VirtioHostDisconnected,
        });
    }

    // 6b. Write queued replies while writable (only when peer is still Ready).
    if !sess.wire_outbox.is_empty()
        && !sess.write_failed
        && revents.contains(PollFlags::POLLOUT)
        && let Err(err) = sess.wire_outbox.flush(sess.fd.as_fd())
    {
        sess.write_failed = true;
        sess.wire_outbox.abandon();
        return Ok(ChannelEventOutcome::EndSession {
            observed_disconnect: err.kind() == io::ErrorKind::BrokenPipe,
        });
    }

    // 6c. Read host input when readable and not backpressure-paused.
    if revents.contains(PollFlags::POLLIN) && !sess.input_paused() {
        loop {
            if sess.input_paused() {
                break;
            }
            match nix::unistd::read(sess.fd.as_fd(), read_buf) {
                Ok(0) => {
                    sess.write_failed = true;
                    sess.wire_outbox.abandon();
                    return Ok(ChannelEventOutcome::EndSession {
                        observed_disconnect: true,
                    });
                }
                Ok(n) => {
                    for event in sess.decoder.push(&read_buf[..n]) {
                        sess.slots
                            .push_back(ParserSlot::Waiting(prepare_frame(event)));
                    }
                    sess.admit(session_gen, next_req_id, retired, ipc_outbox)?;
                }
                Err(Errno::EAGAIN) => break,
                Err(Errno::EINTR) => continue,
                Err(_) => {
                    sess.write_failed = true;
                    sess.wire_outbox.abandon();
                    return Ok(ChannelEventOutcome::EndSession {
                        observed_disconnect: false,
                    });
                }
            }
        }
    }

    Ok(ChannelEventOutcome::Continue)
}

/// Classifies a newly opened or newly handed-off channel descriptor.
fn classify_fresh_fd<P>(fd: OwnedFd, probe: &P) -> ChannelState
where
    P: Fn(std::os::fd::BorrowedFd<'_>) -> HostState + Send + Sync,
{
    match probe(fd.as_fd()) {
        HostState::Ready => ChannelState::Open(OpenSession::new(fd)),
        HostState::VirtioHostDisconnected => {
            let input = match drain_disconnected_input(fd.as_fd(), probe) {
                DrainOutcome::Drained => InputQueue::Clean,
                DrainOutcome::Incomplete => InputQueue::NeedsBoundary,
                DrainOutcome::Reset => {
                    drop(fd);
                    return ChannelState::NeedReopen {
                        in_flight_req_id: None,
                    };
                }
            };
            ChannelState::HostWaiting {
                fd,
                input,
                delay: HOST_WAIT_INITIAL,
                next_probe: Instant::now() + HOST_WAIT_INITIAL,
            }
        }
        HostState::Closed => {
            drop(fd);
            ChannelState::NeedReopen {
                in_flight_req_id: None,
            }
        }
    }
}

/// Transitions an ending session's descriptor either into `HostWaiting`
/// (preserving an open Linux `virtio_console` port across host disconnect) or
/// drops it and requests a verified reopen from the executor.
fn teardown_channel<P>(fd: OwnedFd, observed_disconnect: bool, probe: &P) -> ChannelState
where
    P: Fn(std::os::fd::BorrowedFd<'_>) -> HostState + Send + Sync,
{
    if observed_disconnect && probe(fd.as_fd()) == HostState::VirtioHostDisconnected {
        match drain_disconnected_input(fd.as_fd(), probe) {
            DrainOutcome::Drained => {
                return ChannelState::HostWaiting {
                    fd,
                    input: InputQueue::Clean,
                    delay: HOST_WAIT_INITIAL,
                    next_probe: Instant::now() + HOST_WAIT_INITIAL,
                };
            }
            DrainOutcome::Incomplete => {
                return ChannelState::HostWaiting {
                    fd,
                    input: InputQueue::NeedsBoundary,
                    delay: HOST_WAIT_INITIAL,
                    next_probe: Instant::now() + HOST_WAIT_INITIAL,
                };
            }
            DrainOutcome::Reset => {}
        }
    }
    drop(fd);
    ChannelState::NeedReopen {
        in_flight_req_id: None,
    }
}

/// Handles one assembled [`ReceivedResponse`] from the executor.
fn handle_ipc_response<P>(
    mut resp: ReceivedResponse,
    session_gen: &mut u64,
    ch_state: &mut ChannelState,
    retired_pending: &mut Vec<RetiredLane>,
    probe: &P,
) -> Option<ParserExit>
where
    P: Fn(std::os::fd::BorrowedFd<'_>) -> HostState + Send + Sync,
{
    // Release any retired exclusive lane owned by this completed request
    // before discarding stale-generation replies.
    retired_pending.retain(|r| !(r.session_gen == resp.session_gen && r.req_id == resp.req_id));

    // Stale response from an earlier session generation: drop any payload (and
    // reject any unexpected channel descriptor attached to a stale generation).
    if resp.session_gen != *session_gen {
        if resp.channel_fd.is_some() {
            return Some(ParserExit::ProtocolViolation);
        }
        return None;
    }

    match ch_state {
        ChannelState::NeedReopen { in_flight_req_id } if *in_flight_req_id == Some(resp.req_id) => {
            *in_flight_req_id = None;
            match resp.response {
                IpcResponse::OkChannelFd => {
                    let Some(fd) = resp.channel_fd.take() else {
                        return Some(ParserExit::ProtocolViolation);
                    };
                    if set_nonblocking(fd.as_fd()).is_err() {
                        drop(fd);
                        return None;
                    }
                    *ch_state = classify_fresh_fd(fd, probe);
                    None
                }
                IpcResponse::Err(IpcErrorCode::ChannelRetryLater) => None,
                IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy) => {
                    Some(ParserExit::ChannelTerminalBusy)
                }
                _ => Some(ParserExit::ProtocolViolation),
            }
        }
        ChannelState::Open(sess) => {
            if resp.channel_fd.is_some() {
                return Some(ParserExit::ProtocolViolation);
            }
            if sess.complete_response(resp).is_err() {
                return Some(ParserExit::ProtocolViolation);
            }
            sess.promote_done();
            None
        }
        ChannelState::HostWaiting { .. } | ChannelState::NeedReopen { .. } => {
            if resp.channel_fd.is_some() {
                return Some(ParserExit::ProtocolViolation);
            }
            // Discard any response arriving while no host session is open.
            None
        }
    }
}

fn duration_to_timespec(dur: Duration) -> TimeSpec {
    let secs = i64::try_from(dur.as_secs()).unwrap_or(i64::MAX);
    let nanos = i64::from(dur.subsec_nanos());
    TimeSpec::new(secs, nanos)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::thread;

    use super::*;
    use crate::handlers::osinfo::OsInfo;
    use crate::ipc::{
        IpcErrorCode, IpcRequest, IpcResponse, PeerRole, StreamAssembler, WireFreezeStatus,
        recv_request, send_response,
    };
    use crate::kernel::ipc::seqpacket_pair;

    fn unix_stream_pair() -> (std::os::unix::net::UnixStream, OwnedFd) {
        let (host, parser_end) = std::os::unix::net::UnixStream::pair().unwrap();
        host.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        host.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let parser_fd: OwnedFd = parser_end.into();
        set_nonblocking(parser_fd.as_fd()).unwrap();
        (host, parser_fd)
    }

    fn read_line(stream: &mut std::os::unix::net::UnixStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).unwrap();
            assert!(n > 0, "unexpected EOF reading line; partial={buf:?}");
            buf.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(buf).unwrap();
            }
        }
    }

    #[test]
    fn parser_loop_round_trips_commands_rejections_sentinel_and_silent_ops() {
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let (mut host, ch_fd) = unix_stream_pair();

        let parser_thread = thread::spawn(move || run_parser_loop(parser_sock, Some(ch_fd)));

        // Executor stand-in on the other end of `exec_sock`.
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // 1. guest-ping
        host.write_all(b"{\"execute\":\"guest-ping\",\"id\":1}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(req.session_gen, 1);
        assert_eq!(req.request, IpcRequest::Ping);
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkEmpty,
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host), "{\"return\":{},\"id\":1}\n");

        // 2. guest-sync-delimited carries 0xFF sentinel on BOTH success and error.
        host.write_all(
            b"\xff{\"execute\":\"guest-sync-delimited\",\"arguments\":{\"id\":99},\"id\":2}\n",
        )
        .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(req.request, IpcRequest::SyncDelimited { id: 99 });
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkI64(99),
            None,
        )
        .unwrap();
        let mut raw = vec![0u8; 64];
        let n = host.read(&mut raw).unwrap();
        assert_eq!(&raw[..n], b"\xff{\"return\":99,\"id\":2}\n");

        // 3. guest-fsfreeze-freeze-list preserves Omitted vs Present([]) vs Present(["/data"]).
        host.write_all(b"{\"execute\":\"guest-fsfreeze-freeze-list\",\"id\":3}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(
            req.request,
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted)
        );
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkCount(2),
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host), "{\"return\":2,\"id\":3}\n");

        host.write_all(
            b"{\"execute\":\"guest-fsfreeze-freeze-list\",\"arguments\":{\"mountpoints\":[]},\"id\":4}\n",
        )
        .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(
            req.request,
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![]))
        );
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkCount(0),
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host), "{\"return\":0,\"id\":4}\n");

        // 4. Allowlisted command with invalid arguments routes via
        //    ReportParseRejection(ParseError, Full(cmd)) so executor can return
        //    Disabled / RateLimited / Frozen before InvalidArguments (C-7).
        host.write_all(b"{\"execute\":\"guest-fstrim\",\"arguments\":{\"bogus\":1},\"id\":5}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert!(matches!(
            req.request,
            IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::ParseError,
                method: Some(ProjectedMethod::Full(ref m)),
                id: Some(5),
                ..
            }) if m == "guest-fstrim"
        ));
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::Err(IpcErrorCode::Disabled {
                command: Command::Fstrim,
            }),
            None,
        )
        .unwrap();
        let disabled_line = read_line(&mut host);
        assert!(disabled_line.contains("CommandNotFound"), "{disabled_line}");
        assert!(disabled_line.contains("disabled"), "{disabled_line}");

        // 5. Unknown method sends ReportParseRejection(UnknownMethod) and emits CommandNotFound.
        host.write_all(b"{\"execute\":\"guest-exec\",\"id\":6}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert!(matches!(
            req.request,
            IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::UnknownMethod,
                id: Some(6),
                ..
            })
        ));
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkAck,
            None,
        )
        .unwrap();
        let denied = read_line(&mut host);
        assert!(denied.contains("CommandNotFound"), "{denied}");

        // 6. guest-shutdown emits zero reply on OkSilent.
        host.write_all(b"{\"execute\":\"guest-shutdown\",\"id\":7}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(
            req.request,
            IpcRequest::Shutdown {
                mode: ShutdownMode::Powerdown
            }
        );
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkSilent,
            None,
        )
        .unwrap();
        // Follow up with a ping to prove zero bytes were written for shutdown.
        host.write_all(b"{\"execute\":\"guest-ping\",\"id\":8}\n")
            .unwrap();
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(req.request, IpcRequest::Ping);
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkEmpty,
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host), "{\"return\":{},\"id\":8}\n");

        // Close IPC -> parser exits cleanly.
        drop(exec_sock);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    }

    #[test]
    fn parser_discards_late_responses_from_previous_session_generation_after_reopen() {
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let (mut host1, ch1) = unix_stream_pair();

        let parser_thread = thread::spawn(move || run_parser_loop(parser_sock, Some(ch1)));
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // Host 1 sends a freeze with id=42 and disconnects BEFORE executor answers.
        host1
            .write_all(b"{\"execute\":\"guest-fsfreeze-freeze\",\"id\":42}\n")
            .unwrap();
        let slow_freeze = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(slow_freeze.session_gen, 1);
        assert_eq!(slow_freeze.request, IpcRequest::FsfreezeFreeze);

        // Host 1 disconnects -> parser closes ch1, increments session_gen to 2,
        // and sends RequestChannelReopen.
        drop(host1);
        let reopen = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(reopen.session_gen, 2);
        assert_eq!(reopen.request, IpcRequest::RequestChannelReopen);

        // Executor hands off verified channel 2 via SCM_RIGHTS.
        let (mut host2, ch2) = unix_stream_pair();
        send_response(
            exec_sock.as_fd(),
            reopen.session_gen,
            reopen.req_id,
            &IpcResponse::OkChannelFd,
            Some(ch2.as_fd()),
        )
        .unwrap();
        drop(ch2);

        // NOW the slow freeze reply from session_gen=1 arrives! Parser MUST
        // discard it so host 2 never sees `{"return":2,"id":42}`.
        send_response(
            exec_sock.as_fd(),
            slow_freeze.session_gen,
            slow_freeze.req_id,
            &IpcResponse::OkCount(2),
            None,
        )
        .unwrap();

        // Host 2 sends guest-fsfreeze-status reusing id=42 -> gets ONLY its own reply!
        host2
            .write_all(b"{\"execute\":\"guest-fsfreeze-status\",\"id\":42}\n")
            .unwrap();
        let status_req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(status_req.session_gen, 2);
        assert_eq!(status_req.request, IpcRequest::FsfreezeStatus);
        send_response(
            exec_sock.as_fd(),
            status_req.session_gen,
            status_req.req_id,
            &IpcResponse::OkFreezeStatus(WireFreezeStatus::Frozen),
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host2), "{\"return\":\"frozen\",\"id\":42}\n");

        drop(exec_sock);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    }

    #[test]
    fn parser_allows_thaw_and_controls_beside_in_flight_freeze_and_preserves_wire_order() {
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let (mut host, ch_fd) = unix_stream_pair();

        let parser_thread = thread::spawn(move || run_parser_loop(parser_sock, Some(ch_fd)));
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // Send freeze(1), ordinary fstrim(2), status(3), thaw(4) all at once!
        // Lane rules (§5.7): freeze(1) starts; ordinary fstrim(2) waits;
        // status(3) (Control) and thaw(4) (Thaw) overtake fstrim(2) and run
        // beside freeze(1)!
        host.write_all(
            concat!(
                "{\"execute\":\"guest-fsfreeze-freeze\",\"id\":1}\n",
                "{\"execute\":\"guest-fstrim\",\"id\":2}\n",
                "{\"execute\":\"guest-fsfreeze-status\",\"id\":3}\n",
                "{\"execute\":\"guest-fsfreeze-thaw\",\"id\":4}\n",
            )
            .as_bytes(),
        )
        .unwrap();

        let r1 = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        let r2 = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        let r3 = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(r1.request, IpcRequest::FsfreezeFreeze);
        assert_eq!(r2.request, IpcRequest::FsfreezeStatus);
        assert_eq!(r3.request, IpcRequest::FsfreezeThaw);

        // Answer thaw and status BEFORE freeze completes: replies must STILL
        // leave the wire in request order (1, 2, 3, 4)!
        send_response(
            exec_sock.as_fd(),
            r3.session_gen,
            r3.req_id,
            &IpcResponse::OkCount(1),
            None,
        )
        .unwrap();
        send_response(
            exec_sock.as_fd(),
            r2.session_gen,
            r2.req_id,
            &IpcResponse::OkFreezeStatus(WireFreezeStatus::Frozen),
            None,
        )
        .unwrap();
        send_response(
            exec_sock.as_fd(),
            r1.session_gen,
            r1.req_id,
            &IpcResponse::OkCount(1),
            None,
        )
        .unwrap();

        // Now freeze(1) and thaw(4) are done -> ordinary fstrim(2) is admitted!
        let r4 = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(r4.request, IpcRequest::Fstrim { minimum: 0 });
        send_response(
            exec_sock.as_fd(),
            r4.session_gen,
            r4.req_id,
            &IpcResponse::OkFstrim(vec![]),
            None,
        )
        .unwrap();

        // Verify strict request-order wire output: 1, 2, 3, 4!
        assert_eq!(read_line(&mut host), "{\"return\":1,\"id\":1}\n");
        assert_eq!(
            read_line(&mut host),
            "{\"return\":{\"paths\":[]},\"id\":2}\n"
        );
        assert_eq!(read_line(&mut host), "{\"return\":\"frozen\",\"id\":3}\n");
        assert_eq!(read_line(&mut host), "{\"return\":1,\"id\":4}\n");

        drop(exec_sock);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    }

    #[test]
    fn format_wire_reply_enforces_defensive_osinfo_wire_limit_without_dropping_session() {
        // An OsInfo with ~100 KiB of NUL/control bytes expands 6x under JSON
        // escaping (\u0001) to > 512 KiB -> non-fatal GenericError!
        let meta = ReplyMeta::Command {
            cmd: Command::GetOsInfo,
            id: Some(77),
            sentinel: false,
        };
        let huge = OsInfo {
            pretty_name: Some("\x01".repeat(100_000)),
            ..OsInfo::default()
        };
        let wire = format_wire_reply(&meta, IpcResponse::OkOsInfo(Box::new(huge)))
            .unwrap()
            .unwrap();
        let text = String::from_utf8(wire).unwrap();
        assert!(text.contains("GenericError"), "{text}");
        assert!(text.contains("524288"), "{text}");
        assert!(text.contains("\"id\":77"), "{text}");
    }

    #[test]
    fn format_wire_reply_covers_inventory_fstrim_and_error_variants() {
        use crate::handlers::fstrim::TrimPathOutcome;
        use crate::ipc::{IpAddressDto, IpAddressKind, WireFreezeStatus};

        let info_meta = ReplyMeta::Command {
            cmd: Command::Info,
            id: Some(1),
            sentinel: false,
        };
        let info_wire = format_wire_reply(
            &info_meta,
            IpcResponse::OkInfo(vec![CommandCapability {
                command: Command::Ping,
                enabled: true,
                success_response: true,
            }]),
        )
        .unwrap()
        .unwrap();
        let info_str = String::from_utf8(info_wire).unwrap();
        assert!(info_str.contains("\"guest-ping\""), "{info_str}");

        let ifaces_meta = ReplyMeta::Command {
            cmd: Command::NetworkGetInterfaces,
            id: Some(2),
            sentinel: false,
        };
        let ifaces_wire = format_wire_reply(
            &ifaces_meta,
            IpcResponse::OkInterfaces(vec![InterfaceDto {
                name: "eth0".to_owned(),
                hardware_address: Some("52:54:00:12:34:56".to_owned()),
                ip_addresses: vec![IpAddressDto {
                    ip_address: "10.0.0.2".to_owned(),
                    kind: IpAddressKind::Ipv4,
                    prefix: 24,
                }],
            }]),
        )
        .unwrap()
        .unwrap();
        assert!(
            String::from_utf8(ifaces_wire).unwrap().contains("\"eth0\""),
            "expected interface name"
        );

        let fsinfo_meta = ReplyMeta::Command {
            cmd: Command::GetFsInfo,
            id: Some(3),
            sentinel: false,
        };
        let fsinfo_wire = format_wire_reply(
            &fsinfo_meta,
            IpcResponse::OkFsInfo(vec![FsInfoDto {
                name: "fs-1".to_owned(),
                mountpoint: "/".to_owned(),
                fs_type: "ext4".to_owned(),
                total_bytes: Some(1024),
                used_bytes: Some(512),
            }]),
        )
        .unwrap()
        .unwrap();
        assert!(
            String::from_utf8(fsinfo_wire).unwrap().contains("\"fs-1\""),
            "expected fsinfo id"
        );

        let trim_meta = ReplyMeta::Command {
            cmd: Command::Fstrim,
            id: Some(4),
            sentinel: false,
        };
        let trim_wire = format_wire_reply(
            &trim_meta,
            IpcResponse::OkFstrim(vec![TrimPathDto {
                path: "/data".to_owned(),
                outcome: TrimPathOutcome::Trimmed {
                    trimmed: 4096,
                    minimum: 0,
                },
            }]),
        )
        .unwrap()
        .unwrap();
        assert!(
            String::from_utf8(trim_wire).unwrap().contains("4096"),
            "expected trimmed bytes"
        );

        // Mixed-outcome FstrimReplyTooLarge produces fixed non-fatal GenericError.
        let oversize_wire = format_wire_reply(
            &trim_meta,
            IpcResponse::Err(IpcErrorCode::FstrimReplyTooLarge {
                trimmed_targets: 5,
                failed_targets: 2,
                limit_bytes: 1_048_576,
            }),
        )
        .unwrap()
        .unwrap();
        let oversize_str = String::from_utf8(oversize_wire).unwrap();
        assert!(
            oversize_str.contains("trimmed 5 target(s) (2 failed)")
                && oversize_str.contains("1 MiB"),
            "{oversize_str}"
        );

        // Mismatched response variant fails closed as Err(()).
        assert!(format_wire_reply(&info_meta, IpcResponse::OkEmpty).is_err());
        assert!(
            format_wire_reply(
                &info_meta,
                IpcResponse::OkFreezeStatus(WireFreezeStatus::Thawed)
            )
            .is_err()
        );
        assert!(format_wire_reply(&info_meta, IpcResponse::OkSilent).is_err());
    }

    #[test]
    fn parser_handles_virtio_disconnect_drain_and_terminal_busy() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use crate::ipc::{recv_request, send_response};
        use crate::kernel::ipc::seqpacket_pair;

        // 1. VirtioHostDisconnected drains stale bytes without closing fd, then
        //    serves fresh commands once HostState::Ready returns.
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let (mut host, guest_fd) = unix_stream_pair();
        // Write stale bytes from a "departed host" before parser starts.
        host.write_all(b"{\"execute\":\"guest-shutdown\"}\n")
            .unwrap();

        let probe_calls = Arc::new(AtomicUsize::new(0));
        let probe_clone = Arc::clone(&probe_calls);
        let parser_thread = std::thread::spawn(move || {
            run_parser_loop_with_probe(parser_sock, Some(guest_fd), move |_| {
                let n = probe_clone.fetch_add(1, Ordering::SeqCst);
                // First 3 probes report disconnected (initial check + drain read +
                // wait-loop check), then Ready!
                if n < 3 {
                    HostState::VirtioHostDisconnected
                } else {
                    HostState::Ready
                }
            })
        });

        // Give the parser loop time to drain stale bytes and enter Ready.
        std::thread::sleep(Duration::from_millis(80));
        host.write_all(b"{\"execute\":\"guest-ping\",\"id\":55}\n")
            .unwrap();

        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        // Stale guest-shutdown was discarded; only the fresh guest-ping arrived!
        assert_eq!(req.request, IpcRequest::Ping);
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::OkEmpty,
            None,
        )
        .unwrap();
        assert_eq!(read_line(&mut host), "{\"return\":{},\"id\":55}\n");
        drop(exec_sock);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);

        // 2. No initial channel -> RequestChannelReopen -> ChannelTerminalBusy exits cleanly.
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let parser_thread = std::thread::spawn(move || run_parser_loop(parser_sock, None));
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
        let req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(req.request, IpcRequest::RequestChannelReopen);
        send_response(
            exec_sock.as_fd(),
            req.session_gen,
            req.req_id,
            &IpcResponse::Err(IpcErrorCode::ChannelTerminalBusy),
            None,
        )
        .unwrap();
        assert_eq!(
            parser_thread.join().unwrap(),
            ParserExit::ChannelTerminalBusy
        );
    }

    #[test]
    fn hangup_revents_aborts_before_reading_stale_input_or_writing_queued_replies() {
        // 1. Observed virtio hangup (`POLLIN | POLLHUP`, `!POLLOUT`): stale
        //    driver-queued input must NOT be read/submitted, and any queued
        //    undelivered reply must be abandoned without writing.
        let (mut host, guest_fd) = unix_stream_pair();
        host.set_nonblocking(true).unwrap();
        host.write_all(b"{\"execute\":\"guest-shutdown\",\"id\":1}\n")
            .unwrap();

        let mut sess = OpenSession::new(guest_fd);
        sess.wire_outbox
            .push(b"{\"return\":{},\"id\":0}\n".to_vec());
        let mut next_req_id = 1;
        let mut ipc_outbox = IpcOutbox::new();
        let mut read_buf = [0u8; 256];

        let outcome = service_open_channel_revents(
            &mut sess,
            PollFlags::POLLIN | PollFlags::POLLHUP,
            1,
            &mut next_req_id,
            &[],
            &mut ipc_outbox,
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ChannelEventOutcome::EndSession {
                observed_disconnect: true
            }
        );
        assert!(
            ipc_outbox.is_empty(),
            "stale input on POLLIN|POLLHUP must never be decoded or submitted over IPC"
        );
        assert!(
            sess.wire_outbox.is_empty(),
            "queued reply must be abandoned"
        );
        let mut probe_buf = [0u8; 64];
        assert_eq!(
            host.read(&mut probe_buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "zero bytes may be written to host once hangup is observed"
        );

        // 2. Observed writable hangup (`POLLOUT | POLLHUP`): queued reply must
        //    NOT be flushed before terminating the session.
        let (mut host2, guest_fd2) = unix_stream_pair();
        host2.set_nonblocking(true).unwrap();
        let mut sess2 = OpenSession::new(guest_fd2);
        sess2
            .wire_outbox
            .push(b"{\"return\":{},\"id\":9}\n".to_vec());
        let outcome2 = service_open_channel_revents(
            &mut sess2,
            PollFlags::POLLOUT | PollFlags::POLLHUP,
            2,
            &mut next_req_id,
            &[],
            &mut ipc_outbox,
            &mut read_buf,
        )
        .unwrap();
        assert_eq!(
            outcome2,
            ChannelEventOutcome::EndSession {
                observed_disconnect: false
            }
        );
        assert!(sess2.wire_outbox.is_empty());
        assert_eq!(
            host2.read(&mut probe_buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock,
            "queued reply must not be written on POLLOUT|POLLHUP"
        );
    }

    #[test]
    fn serial_lane_ownership_survives_channel_reopen_and_preserves_host_id() {
        let (exec_sock, parser_sock) = seqpacket_pair(false).unwrap();
        set_nonblocking(parser_sock.as_fd()).unwrap();
        let (mut host1, guest1) = unix_stream_pair();
        let (mut host2, guest2) = unix_stream_pair();

        let parser_thread = thread::spawn(move || run_parser_loop(parser_sock, Some(guest1)));
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // Session 1 starts `guest-fstrim` (Ordinary serial lane) with host id 101.
        host1
            .write_all(b"{\"execute\":\"guest-fstrim\",\"id\":101}\n")
            .unwrap();
        let trim_req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(trim_req.request, IpcRequest::Fstrim { minimum: 0 });
        assert_eq!(trim_req.host_id, Some(101));

        // Session 1 disconnects while `guest-fstrim` is STILL executing in the executor!
        drop(host1);
        let reopen_req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(reopen_req.request, IpcRequest::RequestChannelReopen);
        assert_eq!(reopen_req.host_id, None);
        send_response(
            exec_sock.as_fd(),
            reopen_req.session_gen,
            reopen_req.req_id,
            &IpcResponse::OkChannelFd,
            Some(guest2.as_fd()),
        )
        .unwrap();
        drop(guest2);

        // Session 2 sends `guest-fsfreeze-freeze` (Freeze) followed by `guest-ping`
        // (Control). `guest-ping` must run immediately, while `guest-fsfreeze-freeze`
        // MUST wait until Session 1's retired `fstrim` finishes (§5.7).
        host2
            .write_all(
                b"{\"execute\":\"guest-fsfreeze-freeze\",\"id\":202}\n{\"execute\":\"guest-ping\",\"id\":203}\n",
            )
            .unwrap();

        let next_req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(
            next_req.request,
            IpcRequest::Ping,
            "control ping must overtake freeze while retired fstrim holds the serial lane"
        );
        assert_eq!(next_req.host_id, Some(203));
        send_response(
            exec_sock.as_fd(),
            next_req.session_gen,
            next_req.req_id,
            &IpcResponse::OkEmpty,
            None,
        )
        .unwrap();

        // Confirm `guest-fsfreeze-freeze` has NOT been submitted yet.
        let mut pfd = [PollFd::new(exec_sock.as_fd(), PollFlags::POLLIN)];
        assert_eq!(
            ppoll(&mut pfd, Some(TimeSpec::new(0, 80_000_000)), None).unwrap(),
            0,
            "freeze must not start before retired fstrim completes"
        );

        // Now complete Session 1's retired `fstrim`: its late reply is discarded
        // (never written to host2) AND releases the serial lane so host2's freeze starts!
        send_response(
            exec_sock.as_fd(),
            trim_req.session_gen,
            trim_req.req_id,
            &IpcResponse::OkFstrim(vec![]),
            None,
        )
        .unwrap();

        let freeze_req = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(freeze_req.request, IpcRequest::FsfreezeFreeze);
        assert_eq!(freeze_req.host_id, Some(202));
        send_response(
            exec_sock.as_fd(),
            freeze_req.session_gen,
            freeze_req.req_id,
            &IpcResponse::OkCount(2),
            None,
        )
        .unwrap();

        // Host 2 receives ONLY its own replies in request order (202, then 203),
        // never Session 1's retired fstrim reply!
        assert_eq!(read_line(&mut host2), "{\"return\":2,\"id\":202}\n");
        assert_eq!(read_line(&mut host2), "{\"return\":{},\"id\":203}\n");

        drop(exec_sock);
        assert_eq!(parser_thread.join().unwrap(), ParserExit::IpcClosed);
    }
}
