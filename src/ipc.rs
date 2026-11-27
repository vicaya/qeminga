//! Versioned, bounded typed binary IPC protocol between the unprivileged
//! host-facing parser (`qeminga-parser`) and the privileged policy/kernel
//! executor (`qeminga`) over `AF_UNIX` `SOCK_SEQPACKET` (OQ-10 §4, #77).
//!
//! # Wire Format
//!
//! Every `SOCK_SEQPACKET` datagram carries a fixed 23-byte little-endian
//! header followed by at most [`MAX_CHUNK_PAYLOAD_BYTES`] (`32 KiB`) of
//! payload:
//!
//! ```text
//! Chunk := version(u8 = 1)
//!        | session_gen(u64 LE)
//!        | req_id(u64 LE)
//!        | opcode_or_status(u8)
//!        | flags(u8: bit 0 = MORE_CHUNKS; other bits must be 0)
//!        | chunk_seq(u16 LE: 0, 1, 2, ...)
//!        | payload_len(u16 LE <= 32768)
//!        | payload(payload_len bytes)
//! ```
//!
//! # Security Invariants
//!
//! - **Closed typed operations:** no path proxy, descriptor proxy, syscall
//!   proxy, or arbitrary error-string channel exists.
//! - **Strict descriptor ownership:** only [`ResponseStatus::OkChannelFd`]
//!   (executor → parser, `chunk_seq == 0`, `flags == 0`) may carry an
//!   `SCM_RIGHTS` descriptor — and it must carry **exactly one** `SCM_RIGHTS`
//!   descriptor with no extra/unknown control messages and no `MSG_CTRUNC`.
//!   Every other packet in either direction requires zero ancillary data.
//!   Because [`crate::kernel::ipc::RawPacket`] owns every received descriptor
//!   as [`OwnedFd`], every rejected packet closes all received descriptors
//!   immediately with zero leaks.
//! - **Explicit bounds:** per-packet cap `32 KiB`, assembled request cap
//!   `64 KiB` (matching design §5.10 with no separate 256-entry count cap on
//!   `FsfreezeFreezeList`), assembled response caps `128 KiB` (`GetOsInfo`),
//!   `256 KiB` (`NetworkGetInterfaces`), `1 MiB` (`GetFsInfo` and `Fstrim`),
//!   and at most [`MAX_CONCURRENT_STREAMS`] (`8`) in-flight multi-chunk
//!   streams per direction.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use nix::errno::Errno;

use crate::audit::{MAX_METHOD_BYTES, MethodField};
use crate::dispatch::ratelimit::CommandClass;
use crate::freeze_op::AbortCause;
use crate::handlers::Command;
use crate::handlers::fsfreeze::{
    FreezeFailure, FreezeStop, FreezeTaskStage, RecoveryReason, ThawFailure,
};
use crate::handlers::fsinfo::{
    FilesystemInfo, MAX_FSINFO_REPLY_BYTES, fsinfo_busy_error, fsinfo_timeout_error,
};
pub use crate::handlers::fstrim::TrimPathOutcome;
use crate::handlers::fstrim::{
    FstrimOversize, MAX_FSTRIM_REPLY_BYTES, TrimEntry, TrimResponse, TrimResult,
};
use crate::handlers::info::CommandInfo;
use crate::handlers::interfaces::{Interface, IpAddress, MAX_INTERFACES_REPLY_BYTES};
use crate::handlers::osinfo::{MAX_OSINFO_REPLY_BYTES, OsInfo};
use crate::handlers::shutdown::ShutdownMode;
use crate::kernel::ipc::{RawPacket, recv_packet, send_packet};
use crate::marker::MarkerError;
use crate::proto::Error as ProtoError;
use crate::state::FreezeState;

/// Reserved file descriptor number for the `SOCK_SEQPACKET` IPC socket in
/// both the executor and parser seccomp profiles (OQ-10 §3.2, §5.4).
pub const IPC_FD: i32 = 3;

/// Current binary IPC protocol version.
pub const IPC_VERSION: u8 = 1;

/// Fixed chunk header size in bytes:
/// `version(1) + session_gen(8) + req_id(8) + tag(1) + flags(1) + chunk_seq(2) + payload_len(2)`.
pub const HEADER_BYTES: usize = 23;

/// Chunk header flag bit 0: additional chunks follow for `(session_gen, req_id)`.
pub const FLAG_MORE_CHUNKS: u8 = 0x01;

/// Maximum payload bytes carried by one `SOCK_SEQPACKET` packet (`32 KiB`).
pub const MAX_CHUNK_PAYLOAD_BYTES: usize = 32 * 1024;

/// Maximum total `SOCK_SEQPACKET` packet size (`32 KiB + 23 B`).
pub const MAX_PACKET_BYTES: usize = HEADER_BYTES + MAX_CHUNK_PAYLOAD_BYTES;

/// Maximum assembled request payload bytes (`64 KiB`, at most 2 chunks).
pub const MAX_REQUEST_PAYLOAD_BYTES: usize = 64 * 1024;

/// Maximum UTF-8 byte length of a single mountpoint entry in
/// `FsfreezeFreezeList` (design §5.2).
pub const MAX_FREEZE_LIST_ENTRY_BYTES: usize = 4_096;

/// Maximum assembled IPC response payload bytes for `GetOsInfo` (`128 KiB`,
/// at most 4 chunks, covering a full `64 KiB` `os-release` plus `uname`).
pub const MAX_OSINFO_IPC_BYTES: usize = 128 * 1024;

/// Maximum serialized QGA JSON line length for `guest-get-osinfo` (`512 KiB`).
pub const MAX_OSINFO_WIRE_BYTES: usize = MAX_OSINFO_REPLY_BYTES;

/// Maximum assembled IPC response payload bytes for `NetworkGetInterfaces`
/// (`256 KiB`, at most 8 chunks).
pub const MAX_INTERFACES_IPC_BYTES: usize = MAX_INTERFACES_REPLY_BYTES;

/// Maximum assembled IPC response payload bytes for `GetFsInfo` (`1 MiB`,
/// at most 32 chunks).
pub const MAX_FSINFO_IPC_BYTES: usize = MAX_FSINFO_REPLY_BYTES;

/// Maximum assembled IPC response payload bytes for opted-in `Fstrim`
/// (`1 MiB`, at most 32 chunks).
pub const MAX_FSTRIM_IPC_BYTES: usize = MAX_FSTRIM_REPLY_BYTES;

/// Maximum concurrent in-flight multi-chunk `(session_gen, req_id)` streams
/// (matching design §5.10 session places).
pub const MAX_CONCURRENT_STREAMS: usize = 8;

/// Maximum payload size for `ReportParseRejection` (single chunk).
const MAX_PARSE_REJECTION_PAYLOAD_BYTES: usize = 256;

/// Maximum payload size for `OkInfo` (single chunk).
const MAX_INFO_PAYLOAD_BYTES: usize = 1024;

/// Maximum payload size for `Err(IpcErrorCode)` (single chunk).
const MAX_ERROR_PAYLOAD_BYTES: usize = 256;

/// Role of the receiving peer; governs allowed tags and `SCM_RIGHTS` rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRole {
    /// Privileged executor receiving typed requests from the parser.
    /// Zero control messages are ever permitted.
    Executor,
    /// Unprivileged parser receiving typed responses from the executor.
    /// Exactly one `SCM_RIGHTS` descriptor is permitted on `OkChannelFd`
    /// (`chunk_seq == 0`, `flags == 0`) and zero elsewhere.
    Parser,
}

/// Decoded 23-byte chunk header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkHeader {
    /// Protocol version (must equal [`IPC_VERSION`]).
    pub version: u8,
    /// Monotonic parser channel session generation (§5.2).
    pub session_gen: u64,
    /// Request identifier unique within `session_gen`.
    pub req_id: u64,
    /// Raw opcode (request) or status (response) discriminant.
    pub tag: u8,
    /// Chunk flags (`FLAG_MORE_CHUNKS` only).
    pub flags: u8,
    /// 0-based chunk sequence number.
    pub chunk_seq: u16,
    /// Payload byte length following this header (`<= MAX_CHUNK_PAYLOAD_BYTES`).
    pub payload_len: u16,
}

impl ChunkHeader {
    /// Encodes the 23-byte little-endian header into `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.extend_from_slice(&self.session_gen.to_le_bytes());
        out.extend_from_slice(&self.req_id.to_le_bytes());
        out.push(self.tag);
        out.push(self.flags);
        out.extend_from_slice(&self.chunk_seq.to_le_bytes());
        out.extend_from_slice(&self.payload_len.to_le_bytes());
    }

    /// Parses a 23-byte header from the prefix of `bytes`.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolViolation> {
        if bytes.len() < HEADER_BYTES {
            return Err(ProtocolViolation::PacketTooShort { len: bytes.len() });
        }
        let version = bytes[0];
        let mut gen_bytes = [0u8; 8];
        gen_bytes.copy_from_slice(&bytes[1..9]);
        let mut req_bytes = [0u8; 8];
        req_bytes.copy_from_slice(&bytes[9..17]);
        let tag = bytes[17];
        let flags = bytes[18];
        let chunk_seq = u16::from_le_bytes([bytes[19], bytes[20]]);
        let payload_len = u16::from_le_bytes([bytes[21], bytes[22]]);
        Ok(ChunkHeader {
            version,
            session_gen: u64::from_le_bytes(gen_bytes),
            req_id: u64::from_le_bytes(req_bytes),
            tag,
            flags,
            chunk_seq,
            payload_len,
        })
    }

    /// `true` when [`FLAG_MORE_CHUNKS`] is set.
    pub const fn has_more_chunks(&self) -> bool {
        (self.flags & FLAG_MORE_CHUNKS) != 0
    }
}

/// Request opcodes sent from parser to executor (OQ-10 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequestOpcode {
    /// `guest-ping`
    Ping = 1,
    /// `guest-info`
    Info = 2,
    /// `guest-sync`
    Sync = 3,
    /// `guest-sync-delimited`
    SyncDelimited = 4,
    /// `guest-fsfreeze-status`
    FsfreezeStatus = 5,
    /// `guest-fsfreeze-freeze`
    FsfreezeFreeze = 6,
    /// `guest-fsfreeze-freeze-list`
    FsfreezeFreezeList = 7,
    /// `guest-fsfreeze-thaw`
    FsfreezeThaw = 8,
    /// `guest-get-osinfo`
    GetOsInfo = 9,
    /// `guest-network-get-interfaces`
    NetworkGetInterfaces = 10,
    /// `guest-get-fsinfo`
    GetFsInfo = 11,
    /// `guest-fstrim`
    Fstrim = 12,
    /// `guest-shutdown`
    Shutdown = 13,
    /// `guest-suspend-ram`
    SuspendRam = 14,
    /// Untrusted parser observation of a rejected raw frame (§3.4).
    ReportParseRejection = 15,
    /// Request a freshly verified virtio channel descriptor via `SCM_RIGHTS`.
    RequestChannelReopen = 16,
}

impl RequestOpcode {
    /// Decodes a wire opcode byte.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Ping),
            2 => Some(Self::Info),
            3 => Some(Self::Sync),
            4 => Some(Self::SyncDelimited),
            5 => Some(Self::FsfreezeStatus),
            6 => Some(Self::FsfreezeFreeze),
            7 => Some(Self::FsfreezeFreezeList),
            8 => Some(Self::FsfreezeThaw),
            9 => Some(Self::GetOsInfo),
            10 => Some(Self::NetworkGetInterfaces),
            11 => Some(Self::GetFsInfo),
            12 => Some(Self::Fstrim),
            13 => Some(Self::Shutdown),
            14 => Some(Self::SuspendRam),
            15 => Some(Self::ReportParseRejection),
            16 => Some(Self::RequestChannelReopen),
            _ => None,
        }
    }

    /// Maximum assembled payload bytes permitted for this request opcode.
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            Self::Ping
            | Self::Info
            | Self::FsfreezeStatus
            | Self::FsfreezeFreeze
            | Self::FsfreezeThaw
            | Self::GetOsInfo
            | Self::NetworkGetInterfaces
            | Self::GetFsInfo
            | Self::SuspendRam
            | Self::RequestChannelReopen => 0,
            Self::Shutdown => 1,
            Self::Sync | Self::SyncDelimited | Self::Fstrim => 8,
            Self::ReportParseRejection => MAX_PARSE_REJECTION_PAYLOAD_BYTES,
            Self::FsfreezeFreezeList => MAX_REQUEST_PAYLOAD_BYTES,
        }
    }

    /// Whether this request opcode is allowed to span multiple chunks.
    pub const fn allows_chunking(self) -> bool {
        matches!(self, Self::FsfreezeFreezeList)
    }
}

/// Response status codes sent from executor to parser (OQ-10 §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ResponseStatus {
    /// Empty `{}` reply (`Ping`).
    OkEmpty = 0x01,
    /// Static command capability list (`Info`).
    OkInfo = 0x02,
    /// Echoed integer (`Sync`, `SyncDelimited`).
    OkI64 = 0x03,
    /// Freeze status (`FsfreezeStatus`).
    OkFreezeStatus = 0x04,
    /// Target count (`FsfreezeFreeze`, `FsfreezeFreezeList`, `FsfreezeThaw`).
    OkCount = 0x05,
    /// OS information DTO (`GetOsInfo`, chunked ≤ `128 KiB`).
    OkOsInfo = 0x06,
    /// Filtered network interfaces DTO (`NetworkGetInterfaces`, chunked ≤ `256 KiB`).
    OkInterfaces = 0x07,
    /// Visible UTF-8 filesystems DTO (`GetFsInfo`, chunked ≤ `1 MiB`).
    OkFsInfo = 0x08,
    /// Per-target trim outcomes DTO (`Fstrim`, chunked ≤ `1 MiB`).
    OkFstrim = 0x09,
    /// Success with no host reply (`Shutdown`, `SuspendRam`).
    OkSilent = 0x0A,
    /// Acknowledgement (`ReportParseRejection`).
    OkAck = 0x0B,
    /// Verified virtio channel descriptor handoff (`RequestChannelReopen`;
    /// the sole packet allowed to carry 1 `SCM_RIGHTS` descriptor).
    OkChannelFd = 0x0C,
    /// Closed typed error code (never carries arbitrary diagnostic strings).
    Err = 0x80,
}

impl ResponseStatus {
    /// Decodes a wire status byte.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0x01 => Some(Self::OkEmpty),
            0x02 => Some(Self::OkInfo),
            0x03 => Some(Self::OkI64),
            0x04 => Some(Self::OkFreezeStatus),
            0x05 => Some(Self::OkCount),
            0x06 => Some(Self::OkOsInfo),
            0x07 => Some(Self::OkInterfaces),
            0x08 => Some(Self::OkFsInfo),
            0x09 => Some(Self::OkFstrim),
            0x0A => Some(Self::OkSilent),
            0x0B => Some(Self::OkAck),
            0x0C => Some(Self::OkChannelFd),
            0x80 => Some(Self::Err),
            _ => None,
        }
    }

    /// Maximum assembled payload bytes permitted for this response status.
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            Self::OkEmpty | Self::OkSilent | Self::OkAck | Self::OkChannelFd => 0,
            Self::OkFreezeStatus => 1,
            Self::OkI64 | Self::OkCount => 8,
            Self::OkInfo => MAX_INFO_PAYLOAD_BYTES,
            Self::Err => MAX_ERROR_PAYLOAD_BYTES,
            Self::OkOsInfo => MAX_OSINFO_IPC_BYTES,
            Self::OkInterfaces => MAX_INTERFACES_IPC_BYTES,
            Self::OkFsInfo => MAX_FSINFO_IPC_BYTES,
            Self::OkFstrim => MAX_FSTRIM_IPC_BYTES,
        }
    }

    /// Whether this response status is allowed to span multiple chunks.
    pub const fn allows_chunking(self) -> bool {
        matches!(
            self,
            Self::OkOsInfo | Self::OkInterfaces | Self::OkFsInfo | Self::OkFstrim
        )
    }
}

/// Preserves the three-way distinction of `guest-fsfreeze-freeze-list`
/// `mountpoints` across IPC (OQ-10 §4.2, #63).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreezeListSelection {
    /// `mountpoints` omitted (`has_list = 0`): whole-guest or allowlist-narrowed.
    Omitted,
    /// `mountpoints` explicitly present (`has_list = 1`): empty `vec![]`
    /// selects zero targets; non-empty selects the listed mountpoints.
    Present(Vec<String>),
}

/// Untrusted parser-observed frame rejection class (§3.4, §4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ParseRejectionKind {
    /// Raw frame exceeded `MAX_FRAME_LEN` (64 KiB).
    Oversized = 0,
    /// Frame failed bounds check, JSON parse, or top-level schema validation.
    ParseError = 1,
    /// Valid request named a method outside the static allowlist.
    UnknownMethod = 2,
}

impl ParseRejectionKind {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Oversized),
            1 => Some(Self::ParseError),
            2 => Some(Self::UnknownMethod),
            _ => None,
        }
    }
}

/// Bounded method projection matching [`MethodField`] (`<= 64` byte prefix +
/// original length + optional SHA-256 digest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectedMethod {
    /// Method fit within [`MAX_METHOD_BYTES`] verbatim.
    Full(String),
    /// Method exceeded [`MAX_METHOD_BYTES`]: bounded prefix, byte length, and
    /// raw 32-byte SHA-256 digest.
    Projected {
        /// Valid UTF-8 prefix of at most [`MAX_METHOD_BYTES`] bytes.
        prefix: String,
        /// Original byte length.
        len_bytes: u32,
        /// Raw SHA-256 digest of the original method bytes.
        digest: [u8; 32],
    },
}

impl ProjectedMethod {
    /// Converts from the crate's [`MethodField`] audit projection.
    pub fn from_method_field(field: &MethodField) -> Option<Self> {
        match field {
            MethodField::Full(s) if s.len() <= MAX_METHOD_BYTES => Some(Self::Full(s.clone())),
            MethodField::Projected {
                method_prefix,
                method_len_bytes,
                method_digest,
            } if method_prefix.len() <= MAX_METHOD_BYTES && method_digest.len() == 64 => {
                let mut digest = [0u8; 32];
                for (i, slot) in digest.iter_mut().enumerate() {
                    *slot = u8::from_str_radix(&method_digest[i * 2..i * 2 + 2], 16).ok()?;
                }
                let len_bytes = u32::try_from(*method_len_bytes).unwrap_or(u32::MAX);
                Some(Self::Projected {
                    prefix: method_prefix.clone(),
                    len_bytes,
                    digest,
                })
            }
            _ => None,
        }
    }

    /// Converts back into an [`MethodField`] for guest-local audit logging.
    pub fn to_method_field(&self) -> MethodField {
        match self {
            Self::Full(s) => MethodField::Full(s.clone()),
            Self::Projected {
                prefix,
                len_bytes,
                digest,
            } => {
                let mut hex = String::with_capacity(64);
                for byte in digest {
                    hex.push_str(&format!("{byte:02x}"));
                }
                MethodField::Projected {
                    method_prefix: prefix.clone(),
                    method_len_bytes: *len_bytes as usize,
                    method_digest: hex,
                }
            }
        }
    }
}

/// Bounded untrusted parser observation payload for `ReportParseRejection`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseRejection {
    /// Category of frame rejection.
    pub kind: ParseRejectionKind,
    /// Observed frame length (capped at `u32::MAX`).
    pub frame_len: u32,
    /// Request `id`, when parsed before rejection.
    pub id: Option<i64>,
    /// Projected method name, when applicable (e.g. `UnknownMethod`).
    pub method: Option<ProjectedMethod>,
}

/// Typed request sent from parser to executor (OQ-10 §4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcRequest {
    /// `guest-ping`
    Ping,
    /// `guest-info`
    Info,
    /// `guest-sync`
    Sync {
        /// Host-supplied synchronization id.
        id: i64,
    },
    /// `guest-sync-delimited`
    SyncDelimited {
        /// Host-supplied synchronization id.
        id: i64,
    },
    /// `guest-fsfreeze-status`
    FsfreezeStatus,
    /// `guest-fsfreeze-freeze`
    FsfreezeFreeze,
    /// `guest-fsfreeze-freeze-list`
    FsfreezeFreezeList(FreezeListSelection),
    /// `guest-fsfreeze-thaw`
    FsfreezeThaw,
    /// `guest-get-osinfo`
    GetOsInfo,
    /// `guest-network-get-interfaces`
    NetworkGetInterfaces,
    /// `guest-get-fsinfo`
    GetFsInfo,
    /// `guest-fstrim`
    Fstrim {
        /// Requested minimum contiguous free range to discard, in bytes.
        minimum: u64,
    },
    /// `guest-shutdown`
    Shutdown {
        /// Requested hard shutdown mode.
        mode: ShutdownMode,
    },
    /// `guest-suspend-ram`
    SuspendRam,
    /// Untrusted parser observation of a rejected frame (§3.4).
    ReportParseRejection(ParseRejection),
    /// Requests a freshly opened and verified virtio channel descriptor.
    RequestChannelReopen,
}

impl IpcRequest {
    /// Wire opcode for this request.
    pub const fn opcode(&self) -> RequestOpcode {
        match self {
            Self::Ping => RequestOpcode::Ping,
            Self::Info => RequestOpcode::Info,
            Self::Sync { .. } => RequestOpcode::Sync,
            Self::SyncDelimited { .. } => RequestOpcode::SyncDelimited,
            Self::FsfreezeStatus => RequestOpcode::FsfreezeStatus,
            Self::FsfreezeFreeze => RequestOpcode::FsfreezeFreeze,
            Self::FsfreezeFreezeList(_) => RequestOpcode::FsfreezeFreezeList,
            Self::FsfreezeThaw => RequestOpcode::FsfreezeThaw,
            Self::GetOsInfo => RequestOpcode::GetOsInfo,
            Self::NetworkGetInterfaces => RequestOpcode::NetworkGetInterfaces,
            Self::GetFsInfo => RequestOpcode::GetFsInfo,
            Self::Fstrim { .. } => RequestOpcode::Fstrim,
            Self::Shutdown { .. } => RequestOpcode::Shutdown,
            Self::SuspendRam => RequestOpcode::SuspendRam,
            Self::ReportParseRejection(_) => RequestOpcode::ReportParseRejection,
            Self::RequestChannelReopen => RequestOpcode::RequestChannelReopen,
        }
    }
}

/// Wire freeze status reported by `guest-fsfreeze-status` (C-7: `Freezing`,
/// `Frozen`, and `Thawing` all report `Frozen`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireFreezeStatus {
    /// `"thawed"`
    Thawed = 0,
    /// `"frozen"`
    Frozen = 1,
}

impl WireFreezeStatus {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Thawed),
            1 => Some(Self::Frozen),
            _ => None,
        }
    }

    /// Converts from live [`FreezeState`].
    pub const fn from_state(state: FreezeState) -> Self {
        if state.is_frozen_for_gate() {
            Self::Frozen
        } else {
            Self::Thawed
        }
    }

    /// Lowercase QGA wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Thawed => "thawed",
            Self::Frozen => "frozen",
        }
    }
}

/// Static capability entry in `OkInfo` derived from executor's `Authority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandCapability {
    /// Allowlisted command identifier.
    pub command: Command,
    /// Whether the command is enabled by guest configuration.
    pub enabled: bool,
    /// Whether a successful call produces a wire reply.
    pub success_response: bool,
}

impl CommandCapability {
    /// Converts to QAPI `GuestAgentCommandInfo`.
    pub const fn to_command_info(self) -> CommandInfo {
        CommandInfo {
            name: self.command.name(),
            enabled: self.enabled,
            success_response: self.success_response,
        }
    }
}

/// Address family discriminant for [`IpAddressDto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpAddressKind {
    /// `"ipv4"`
    Ipv4 = 0,
    /// `"ipv6"`
    Ipv6 = 1,
}

impl IpAddressKind {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Ipv4),
            1 => Some(Self::Ipv6),
            _ => None,
        }
    }

    /// QAPI `ip-address-type` spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

/// Binary IPC DTO for one [`IpAddress`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpAddressDto {
    /// Textual IP address.
    pub ip_address: String,
    /// IPv4 or IPv6.
    pub kind: IpAddressKind,
    /// Prefix length (`0..=32` for IPv4, `0..=128` for IPv6).
    pub prefix: u8,
}

impl IpAddressDto {
    /// Converts from [`IpAddress`].
    pub fn from_handler(addr: &IpAddress) -> Option<Self> {
        let kind = match addr.ip_address_type {
            "ipv4" => IpAddressKind::Ipv4,
            "ipv6" => IpAddressKind::Ipv6,
            _ => return None,
        };
        Some(Self {
            ip_address: addr.ip_address.clone(),
            kind,
            prefix: addr.prefix,
        })
    }

    /// Converts back to [`IpAddress`].
    pub fn to_handler(&self) -> IpAddress {
        IpAddress {
            ip_address: self.ip_address.clone(),
            ip_address_type: self.kind.as_str(),
            prefix: self.prefix,
        }
    }
}

/// Binary IPC DTO for one [`Interface`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDto {
    /// Interface name.
    pub name: String,
    /// Optional lowercase colon-separated MAC.
    pub hardware_address: Option<String>,
    /// Filtered unicast addresses.
    pub ip_addresses: Vec<IpAddressDto>,
}

impl InterfaceDto {
    /// Converts from [`Interface`].
    pub fn from_handler(iface: &Interface) -> Option<Self> {
        let mut ip_addresses = Vec::with_capacity(iface.ip_addresses.len());
        for ip in &iface.ip_addresses {
            ip_addresses.push(IpAddressDto::from_handler(ip)?);
        }
        Some(Self {
            name: iface.name.clone(),
            hardware_address: iface.hardware_address.clone(),
            ip_addresses,
        })
    }

    /// Converts back to [`Interface`].
    pub fn to_handler(&self) -> Interface {
        Interface {
            name: self.name.clone(),
            hardware_address: self.hardware_address.clone(),
            ip_addresses: self
                .ip_addresses
                .iter()
                .map(IpAddressDto::to_handler)
                .collect(),
        }
    }
}

/// Binary IPC DTO for one [`FilesystemInfo`] (`disk` is always empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsInfoDto {
    /// Opaque per-superblock identifier (`fs-1`, `fs-2`, ...).
    pub name: String,
    /// Visible UTF-8 mount point.
    pub mountpoint: String,
    /// Filesystem type.
    pub fs_type: String,
    /// Optional `used-bytes`.
    pub used_bytes: Option<u64>,
    /// Optional `total-bytes`.
    pub total_bytes: Option<u64>,
}

impl FsInfoDto {
    /// Converts from [`FilesystemInfo`].
    pub fn from_handler(info: &FilesystemInfo) -> Self {
        Self {
            name: info.name.clone(),
            mountpoint: info.mountpoint.clone(),
            fs_type: info.fs_type.clone(),
            used_bytes: info.used_bytes,
            total_bytes: info.total_bytes,
        }
    }

    /// Converts back to [`FilesystemInfo`].
    pub fn to_handler(&self) -> FilesystemInfo {
        FilesystemInfo {
            name: self.name.clone(),
            mountpoint: self.mountpoint.clone(),
            fs_type: self.fs_type.clone(),
            used_bytes: self.used_bytes,
            total_bytes: self.total_bytes,
            disk: Vec::new(),
        }
    }
}

/// Binary IPC DTO for one [`TrimResult`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrimPathDto {
    /// Primary mountpoint path.
    pub path: String,
    /// Closed per-target outcome.
    pub outcome: TrimPathOutcome,
}

impl TrimPathDto {
    /// Builds an IPC DTO directly from a typed [`TrimEntry`] collected by
    /// [`crate::handlers::fstrim::trim_plan_entries`].
    pub fn from_entry(entry: &TrimEntry) -> Self {
        Self {
            path: entry.path.clone(),
            outcome: entry.outcome,
        }
    }

    /// Converts back to QAPI [`TrimResult`].
    pub fn to_handler(&self) -> TrimResult {
        self.outcome.to_trim_result(self.path.clone())
    }

    /// Converts a slice of DTOs into a [`TrimResponse`].
    pub fn to_trim_response(entries: &[Self]) -> TrimResponse {
        TrimResponse {
            paths: entries.iter().map(Self::to_handler).collect(),
        }
    }
}

/// Closed host-safe marker error class matching [`MarkerError::host_reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MarkerHostReason {
    /// `"invalid recovery marker path"`
    InvalidPath = 0,
    /// `"recovery marker directory unavailable"`
    Directory = 1,
    /// `"recovery marker already exists"`
    AlreadyPresent = 2,
    /// `"recovery marker is absent"`
    Absent = 3,
    /// `"recovery marker open failed"`
    OpenFailed = 4,
    /// `"recovery marker fsync failed"`
    FsyncFailed = 5,
    /// `"recovery marker unlink failed"`
    UnlinkFailed = 6,
    /// `"recovery marker I/O failed"`
    IoFailed = 7,
}

impl MarkerHostReason {
    /// Maps a [`MarkerError`] to its closed host-safe reason tag.
    pub fn from_marker_error(err: &MarkerError) -> Self {
        match err {
            MarkerError::InvalidPath { .. } => Self::InvalidPath,
            MarkerError::Directory { .. } => Self::Directory,
            MarkerError::AlreadyPresent { .. } => Self::AlreadyPresent,
            MarkerError::Absent { .. } => Self::Absent,
            MarkerError::Io { op: "open", .. } => Self::OpenFailed,
            MarkerError::Io { op: "fsync", .. } => Self::FsyncFailed,
            MarkerError::Io { op: "unlink", .. } => Self::UnlinkFailed,
            MarkerError::Io { .. } => Self::IoFailed,
        }
    }

    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::InvalidPath),
            1 => Some(Self::Directory),
            2 => Some(Self::AlreadyPresent),
            3 => Some(Self::Absent),
            4 => Some(Self::OpenFailed),
            5 => Some(Self::FsyncFailed),
            6 => Some(Self::UnlinkFailed),
            7 => Some(Self::IoFailed),
            _ => None,
        }
    }

    /// Fixed host-facing description matching [`MarkerError::host_reason`].
    pub const fn host_reason(self) -> &'static str {
        match self {
            Self::InvalidPath => "invalid recovery marker path",
            Self::Directory => "recovery marker directory unavailable",
            Self::AlreadyPresent => "recovery marker already exists",
            Self::Absent => "recovery marker is absent",
            Self::OpenFailed => "recovery marker open failed",
            Self::FsyncFailed => "recovery marker fsync failed",
            Self::UnlinkFailed => "recovery marker unlink failed",
            Self::IoFailed => "recovery marker I/O failed",
        }
    }
}

/// Closed host-safe freeze-stop classification matching [`FreezeStop::host_reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FreezeStopReason {
    /// `"FIFREEZE permission denied"`
    FifreezePermissionDenied = 0,
    /// `"target open failed; no FIFREEZE issued"`
    TargetOpenFailed = 1,
    /// `"target unreachable; no FIFREEZE issued"`
    TargetUnreachable = 2,
    /// `"FIFREEZE failed"`
    FifreezeFailed = 3,
    /// `"target open permission denied; no FIFREEZE issued"`
    TargetOpenPermissionDenied = 4,
    /// `"freeze ownership is ambiguous; cannot claim target"`
    OwnershipAmbiguousClaim = 5,
    /// `"cannot update freeze ownership state"`
    OwnershipError = 6,
    /// `"freeze ownership is ambiguous; cannot confirm complete recovery"`
    OwnershipAmbiguousRecovery = 7,
    /// Any other [`RecoveryReason`] returned by `OwnershipReleaseFailed`.
    ReleaseRecovery(RecoveryReason),
}

impl FreezeStopReason {
    /// Maps a [`FreezeStop`] to its closed host-safe reason tag.
    pub fn from_freeze_stop(stop: &FreezeStop) -> Self {
        match stop {
            FreezeStop::Ioctl(err) if err.is_permission() => Self::FifreezePermissionDenied,
            FreezeStop::Ioctl(err) if err.is_open_failure() => Self::TargetOpenFailed,
            FreezeStop::Ioctl(err) if err.is_wrong_filesystem() => Self::TargetUnreachable,
            FreezeStop::Ioctl(_) => Self::FifreezeFailed,
            FreezeStop::Unreachable {
                permission_denied: true,
                ..
            } => Self::TargetOpenPermissionDenied,
            FreezeStop::Unreachable {
                permission_denied: false,
                ..
            } => Self::TargetUnreachable,
            FreezeStop::OwnershipAmbiguous(_) => Self::OwnershipAmbiguousClaim,
            FreezeStop::OwnershipError(err) => match err {
                crate::ownership::OwnershipError::OpenDir { .. }
                | crate::ownership::OwnershipError::Io { .. } => Self::OwnershipError,
                crate::ownership::OwnershipError::TooManyEntries { .. }
                | crate::ownership::OwnershipError::NotOwnedBySelf { .. } => {
                    Self::OwnershipAmbiguousRecovery
                }
            },
            FreezeStop::OwnershipReleaseFailed { kind, .. } => Self::ReleaseRecovery(*kind),
        }
    }

    /// Fixed host-facing description matching [`FreezeStop::host_reason`].
    pub const fn host_reason(self) -> &'static str {
        match self {
            Self::FifreezePermissionDenied => "FIFREEZE permission denied",
            Self::TargetOpenFailed => "target open failed; no FIFREEZE issued",
            Self::TargetUnreachable => "target unreachable; no FIFREEZE issued",
            Self::FifreezeFailed => "FIFREEZE failed",
            Self::TargetOpenPermissionDenied => "target open permission denied; no FIFREEZE issued",
            Self::OwnershipAmbiguousClaim => "freeze ownership is ambiguous; cannot claim target",
            Self::OwnershipError => "cannot update freeze ownership state",
            Self::OwnershipAmbiguousRecovery => {
                "freeze ownership is ambiguous; cannot confirm complete recovery"
            }
            Self::ReleaseRecovery(kind) => kind.host_reason(),
        }
    }
}

/// Activity in flight during an aborted freeze or unsettled joining thaw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AbortActivity {
    /// No worker currently in flight.
    Idle = 0,
    /// Preparation (mount table / marker) is in flight.
    Preparing = 1,
    /// A `FIFREEZE` call is in flight.
    InFlightFifreeze = 2,
}

impl AbortActivity {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Idle),
            1 => Some(Self::Preparing),
            2 => Some(Self::InFlightFifreeze),
            _ => None,
        }
    }
}

/// State-machine transition attempted when a freeze/thaw conflicted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitionOp {
    /// `"begin freeze"`
    BeginFreeze = 0,
    /// `"claim thaw"`
    ClaimThaw = 1,
}

impl TransitionOp {
    const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::BeginFreeze),
            1 => Some(Self::ClaimThaw),
            _ => None,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::BeginFreeze => "begin freeze",
            Self::ClaimThaw => "claim thaw",
        }
    }
}

/// Closed typed error code carried inside [`IpcResponse::Err`] (OQ-10 §4.2).
///
/// Contains only closed enum discriminants and integer counts so the executor
/// never sends arbitrary diagnostic strings containing guest paths, device
/// numbers, or secrets across the IPC boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcErrorCode {
    /// Allowlisted command disabled by guest configuration (`CommandNotFound`).
    Disabled {
        /// Disabled command.
        command: Command,
    },
    /// Non-frozen-safe command rejected while filesystems are frozen.
    Frozen,
    /// Per-class token bucket exhausted.
    RateLimited {
        /// Exhausted command rate class.
        class: CommandClass,
    },
    /// Command arguments failed schema validation.
    InvalidArguments {
        /// Command whose arguments were invalid.
        command: Command,
    },
    /// Freeze state machine rejected the requested transition.
    TransitionConflict {
        /// Attempted transition.
        op: TransitionOp,
        /// Live freeze state at the time of conflict.
        current: FreezeState,
    },
    /// Freeze mount-table plan failed (`state thawed`).
    FreezePlanFailed,
    /// Creating the pre-freeze recovery marker failed (`state thawed`).
    FreezeMarkerFailed {
        /// Fixed host-safe marker error class.
        reason: MarkerHostReason,
    },
    /// Freeze failed and rolled back cleanly (`state thawed`).
    FreezeHard {
        /// Fixed host-safe freeze-stop reason.
        cause: FreezeStopReason,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// Freeze failed and rollback did not complete (`state frozen, marker retained`).
    FreezeRollbackIncomplete {
        /// Fixed host-safe freeze-stop reason.
        cause: FreezeStopReason,
        /// Fixed host-safe incomplete rollback reason.
        recovery_reason: RecoveryReason,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// Freeze rolled back but recovery marker removal failed (`state frozen, marker retained`).
    FreezeMarkerRetained {
        /// Fixed host-safe freeze-stop reason.
        cause: FreezeStopReason,
        /// Fixed host-safe marker removal error class.
        marker_reason: MarkerHostReason,
        /// Targets thawed during rollback.
        rolled_back: u64,
    },
    /// Freeze preparation task failed and marker removal also failed.
    FreezePreparationMarkerRetained {
        /// Fixed host-safe marker removal error class.
        marker_reason: MarkerHostReason,
    },
    /// A blocking freeze stage failed to join.
    FreezeTaskFailed {
        /// Stage that failed.
        stage: FreezeTaskStage,
    },
    /// Zero-work freeze could not remove its recovery marker.
    FreezeNothingFrozenMarkerRetained {
        /// Fixed host-safe marker removal error class.
        marker_reason: MarkerHostReason,
    },
    /// Freeze operation aborted by deadline or thaw request.
    FreezeAborted {
        /// Abort cause.
        cause: AbortCause,
        /// Successful `FIFREEZE` calls before abort.
        frozen: u64,
        /// Whether preparation or a `FIFREEZE` was in flight.
        activity: AbortActivity,
    },
    /// Thaw mount-table plan failed.
    ThawPlanFailed {
        /// Targets thawed before reporting the failure.
        thawed: u64,
        /// Resulting freeze state (`Thawed` or `Frozen`).
        final_state: FreezeState,
        /// Whether the recovery marker is retained on disk.
        marker_retained: bool,
    },
    /// Thaw or recovery drain incomplete.
    ThawIncomplete {
        /// Fixed host-safe recovery failure reason.
        kind: RecoveryReason,
        /// Targets thawed during this attempt.
        thawed: u64,
        /// Resulting freeze state.
        final_state: FreezeState,
        /// Whether the recovery marker is retained on disk.
        marker_retained: bool,
    },
    /// Drain completed but removing the recovery marker failed.
    ThawMarkerFailed {
        /// Fixed host-safe marker removal error class.
        reason: MarkerHostReason,
        /// Targets thawed during this attempt.
        thawed: u64,
        /// Resulting freeze state.
        final_state: FreezeState,
        /// Whether the recovery marker is retained on disk.
        marker_retained: bool,
    },
    /// Thaw blocking task failed to join.
    ThawTaskFailed {
        /// Resulting freeze state.
        final_state: FreezeState,
        /// Whether the recovery marker is retained on disk.
        marker_retained: bool,
    },
    /// Thaw joined an unsettled freeze operation (`abort accepted, recovery pending`).
    ThawAbortPending {
        /// In-flight activity of the unsettled freeze operation.
        activity: AbortActivity,
        /// Targets thawed so far.
        thawed: u64,
    },
    /// Opted-in `guest-fstrim` succeeded/ran but its serialized reply exceeded
    /// `1 MiB` (OQ-10 §4.1); session and executor state stay intact.
    FstrimReplyTooLarge {
        /// Targets whose `FITRIM` ioctl succeeded (`Ok`).
        trimmed_targets: u64,
        /// Targets that failed either before `FITRIM` or in the `FITRIM` ioctl.
        failed_targets: u64,
        /// Enforced wire bound in bytes (`1_048_576`).
        limit_bytes: u64,
    },
    /// Inventory/info reply exceeded its §5.10 wire bound; not truncated.
    ReplyTooLarge {
        /// Command whose reply exceeded the bound.
        command: Command,
        /// Measured wire line length in bytes.
        reply_bytes: u64,
        /// Enforced bound in bytes.
        limit_bytes: u64,
    },
    /// `guest-get-fsinfo` walk concurrency cap reached.
    FsinfoBusy,
    /// `guest-get-fsinfo` walk exceeded its timeout.
    FsinfoTimeout,
    /// Generic host-safe failure for a non-freeze handler (`uname`,
    /// `getifaddrs`, `fsinfo`, `fstrim`, `shutdown`, `suspend`).
    HandlerFailed {
        /// Failing command.
        command: Command,
    },
    /// `RequestChannelReopen` encountered transient failure; parser should retry.
    ChannelRetryLater,
    /// `RequestChannelReopen` observed terminal `EBUSY` (§8.4).
    ChannelTerminalBusy,
}

impl IpcErrorCode {
    /// Builds an [`IpcErrorCode`] from a [`FreezeFailure`] without retaining
    /// any guest paths, device numbers, or configured timeout durations.
    pub fn from_freeze_failure(failure: &FreezeFailure) -> Self {
        match failure {
            FreezeFailure::Plan(_) => Self::FreezePlanFailed,
            FreezeFailure::Marker(err) => Self::FreezeMarkerFailed {
                reason: MarkerHostReason::from_marker_error(err),
            },
            FreezeFailure::Hard {
                cause, rolled_back, ..
            } => Self::FreezeHard {
                cause: FreezeStopReason::from_freeze_stop(cause),
                rolled_back: *rolled_back,
            },
            FreezeFailure::RollbackIncomplete {
                cause,
                recovery_reason,
                rolled_back,
                ..
            } => Self::FreezeRollbackIncomplete {
                cause: FreezeStopReason::from_freeze_stop(cause),
                recovery_reason: *recovery_reason,
                rolled_back: *rolled_back,
            },
            FreezeFailure::MarkerRetained {
                cause,
                marker,
                rolled_back,
                ..
            } => Self::FreezeMarkerRetained {
                cause: FreezeStopReason::from_freeze_stop(cause),
                marker_reason: MarkerHostReason::from_marker_error(marker),
                rolled_back: *rolled_back,
            },
            FreezeFailure::PreparationMarkerRetained { marker, .. } => {
                Self::FreezePreparationMarkerRetained {
                    marker_reason: MarkerHostReason::from_marker_error(marker),
                }
            }
            FreezeFailure::Task { stage, .. } => Self::FreezeTaskFailed { stage: *stage },
            FreezeFailure::NothingFrozenMarkerRetained(err) => {
                Self::FreezeNothingFrozenMarkerRetained {
                    marker_reason: MarkerHostReason::from_marker_error(err),
                }
            }
            FreezeFailure::Aborted {
                cause,
                frozen,
                in_flight,
                ..
            } => {
                let activity = match in_flight.as_deref() {
                    Some(crate::freeze_op::PREPARING) => AbortActivity::Preparing,
                    Some(_) => AbortActivity::InFlightFifreeze,
                    None => AbortActivity::Idle,
                };
                Self::FreezeAborted {
                    cause: *cause,
                    frozen: *frozen,
                    activity,
                }
            }
        }
    }

    /// Builds an [`IpcErrorCode`] from a [`ThawFailure`] and its settlement
    /// metadata.
    pub fn from_thaw_failure(
        failure: &ThawFailure,
        final_state: FreezeState,
        marker_retained: bool,
    ) -> Self {
        match failure {
            ThawFailure::Plan { thawed, .. } => Self::ThawPlanFailed {
                thawed: *thawed,
                final_state,
                marker_retained,
            },
            ThawFailure::Incomplete { kind, thawed, .. } => Self::ThawIncomplete {
                kind: *kind,
                thawed: *thawed,
                final_state,
                marker_retained,
            },
            ThawFailure::Marker { err, thawed } => Self::ThawMarkerFailed {
                reason: MarkerHostReason::from_marker_error(err),
                thawed: *thawed,
                final_state,
                marker_retained,
            },
            ThawFailure::Task(_) => Self::ThawTaskFailed {
                final_state,
                marker_retained,
            },
        }
    }

    /// Formats this closed error code into the exact host-facing
    /// [`ProtoError`] (design §5.9, AC27, OQ-10 §4.1–§4.2).
    pub fn to_proto_error(self) -> ProtoError {
        let state_suffix = |final_state: FreezeState, marker_retained: bool| match (
            final_state,
            marker_retained,
        ) {
            (FreezeState::Thawed, _) => "state thawed",
            (_, true) => "state frozen, marker retained",
            (_, false) => "state frozen, marker unavailable",
        };
        match self {
            Self::Disabled { command } => ProtoError::Disabled(command.name().to_owned()),
            Self::Frozen => ProtoError::Frozen,
            Self::RateLimited { class } => ProtoError::RateLimited {
                class: class.name().to_owned(),
            },
            Self::InvalidArguments { command } => ProtoError::InvalidArguments(format!(
                "arguments do not match the schema of {}",
                command.name()
            )),
            Self::TransitionConflict { op, current } => {
                ProtoError::Internal(format!("cannot {} while {current}", op.as_str()))
            }
            Self::FreezePlanFailed => {
                ProtoError::Internal("cannot build freeze plan; state thawed".to_owned())
            }
            Self::FreezeMarkerFailed { reason } => ProtoError::Internal(format!(
                "cannot create recovery marker: {}; state thawed",
                reason.host_reason()
            )),
            Self::FreezeHard { cause, rolled_back } => ProtoError::Internal(format!(
                "freeze failed: {}; rolled back ({rolled_back} target(s) thawed); state thawed",
                cause.host_reason()
            )),
            Self::FreezeRollbackIncomplete {
                cause,
                recovery_reason,
                rolled_back,
            } => ProtoError::Internal(format!(
                "freeze failed: {}; rollback incomplete ({}, {rolled_back} target(s) thawed); state frozen, marker retained",
                cause.host_reason(),
                recovery_reason.host_reason()
            )),
            Self::FreezeMarkerRetained {
                cause,
                marker_reason,
                rolled_back,
            } => ProtoError::Internal(format!(
                "freeze failed: {}; rolled back ({rolled_back} target(s) thawed) but cannot remove recovery marker: {}; state frozen, marker retained",
                cause.host_reason(),
                marker_reason.host_reason()
            )),
            Self::FreezePreparationMarkerRetained { marker_reason } => {
                ProtoError::Internal(format!(
                    "freeze preparation failed; cannot remove recovery marker: {}; state frozen, marker retained",
                    marker_reason.host_reason()
                ))
            }
            Self::FreezeTaskFailed { stage } => ProtoError::Internal(
                match stage {
                    FreezeTaskStage::Preparation => "freeze preparation failed; state thawed",
                    FreezeTaskStage::Rollback => {
                        "freeze rollback failed; state frozen, marker retained"
                    }
                    FreezeTaskStage::MarkerRemoval => {
                        "nothing was frozen (0 target(s) frozen) and marker removal failed; state frozen, marker retained"
                    }
                }
                .to_owned(),
            ),
            Self::FreezeNothingFrozenMarkerRetained { marker_reason } => {
                ProtoError::Internal(format!(
                    "nothing was frozen (0 target(s) frozen) but cannot remove recovery marker: {}; state frozen, marker retained",
                    marker_reason.host_reason()
                ))
            }
            Self::FreezeAborted {
                cause,
                frozen,
                activity,
            } => match activity {
                AbortActivity::Preparing => ProtoError::Internal(format!(
                    "freeze aborted: {} while preparing; abort accepted, recovery pending",
                    cause.host_reason()
                )),
                AbortActivity::InFlightFifreeze => ProtoError::Internal(format!(
                    "freeze aborted: {} with a FIFREEZE in flight; {frozen} target(s) frozen so far are being thawed; state thawing, marker retained",
                    cause.host_reason()
                )),
                AbortActivity::Idle => ProtoError::Internal(format!(
                    "freeze aborted: {}; {frozen} target(s) frozen so far are being thawed; state thawing, marker retained",
                    cause.host_reason()
                )),
            },
            Self::ThawPlanFailed {
                thawed,
                final_state,
                marker_retained,
            } => ProtoError::Internal(format!(
                "cannot build thaw plan ({thawed} target(s) thawed); {}",
                state_suffix(final_state, marker_retained)
            )),
            Self::ThawIncomplete {
                kind,
                thawed,
                final_state,
                marker_retained,
            } => ProtoError::Internal(format!(
                "thaw incomplete: {} ({thawed} target(s) thawed); {}",
                kind.host_reason(),
                state_suffix(final_state, marker_retained)
            )),
            Self::ThawMarkerFailed {
                reason,
                thawed,
                final_state,
                marker_retained,
            } => ProtoError::Internal(format!(
                "drain complete ({thawed} target(s) thawed) but cannot remove recovery marker: {}; {}",
                reason.host_reason(),
                state_suffix(final_state, marker_retained)
            )),
            Self::ThawTaskFailed {
                final_state,
                marker_retained,
            } => ProtoError::Internal(format!(
                "thaw task failed; {}",
                state_suffix(final_state, marker_retained)
            )),
            Self::ThawAbortPending { activity, thawed } => ProtoError::Internal(match activity {
                AbortActivity::Preparing => {
                    "thaw requested: abort accepted, recovery pending (preparation still in flight)"
                        .to_owned()
                }
                AbortActivity::InFlightFifreeze => format!(
                    "thaw requested: abort accepted, recovery pending ({thawed} target(s) thawed so far, a FIFREEZE is still in flight)"
                ),
                AbortActivity::Idle => format!(
                    "thaw requested: abort accepted, recovery pending ({thawed} target(s) thawed so far)"
                ),
            }),
            Self::FstrimReplyTooLarge {
                trimmed_targets,
                failed_targets,
                ..
            } => ProtoError::Internal(FstrimOversize::format_host_description(
                trimmed_targets,
                failed_targets,
            )),
            Self::ReplyTooLarge {
                command,
                reply_bytes,
                limit_bytes,
            } => ProtoError::Internal(format!(
                "{}: the reply would be {reply_bytes} bytes on the wire, over the {limit_bytes} byte bound; not truncated",
                command.name()
            )),
            Self::FsinfoBusy => fsinfo_busy_error(),
            Self::FsinfoTimeout => fsinfo_timeout_error(),
            Self::HandlerFailed { command } => {
                ProtoError::Internal(format!("{} failed", command.name()))
            }
            Self::ChannelRetryLater => {
                ProtoError::Internal("channel reopen temporarily unavailable".to_owned())
            }
            Self::ChannelTerminalBusy => {
                ProtoError::Internal("channel device is already open (EBUSY)".to_owned())
            }
        }
    }
}

/// Typed response sent from executor to parser (OQ-10 §4.2).
///
/// The optional `SCM_RIGHTS` channel descriptor carried by
/// [`IpcResponse::OkChannelFd`] travels alongside the decoded response inside
/// [`ReceivedResponse`] so [`IpcResponse`] stays purely value-comparable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcResponse {
    /// Empty `{}` reply (`Ping`).
    OkEmpty,
    /// Capability list derived from executor's `Authority` (`Info`).
    OkInfo(Vec<CommandCapability>),
    /// Echoed synchronization integer (`Sync`, `SyncDelimited`).
    OkI64(i64),
    /// Freeze status (`FsfreezeStatus`).
    OkFreezeStatus(WireFreezeStatus),
    /// Superblock count (`FsfreezeFreeze`, `FsfreezeFreezeList`, `FsfreezeThaw`).
    OkCount(u64),
    /// OS information (`GetOsInfo`).
    OkOsInfo(Box<OsInfo>),
    /// Network interfaces (`NetworkGetInterfaces`).
    OkInterfaces(Vec<InterfaceDto>),
    /// Visible UTF-8 filesystems (`GetFsInfo`).
    OkFsInfo(Vec<FsInfoDto>),
    /// Per-target trim results (`Fstrim`).
    OkFstrim(Vec<TrimPathDto>),
    /// Success with suppressed host reply (`Shutdown`, `SuspendRam`).
    OkSilent,
    /// Acknowledgement (`ReportParseRejection`).
    OkAck,
    /// Verified virtio channel descriptor handoff (`RequestChannelReopen`).
    OkChannelFd,
    /// Closed typed error code.
    Err(IpcErrorCode),
}

impl IpcResponse {
    /// Wire status code for this response.
    pub const fn status(&self) -> ResponseStatus {
        match self {
            Self::OkEmpty => ResponseStatus::OkEmpty,
            Self::OkInfo(_) => ResponseStatus::OkInfo,
            Self::OkI64(_) => ResponseStatus::OkI64,
            Self::OkFreezeStatus(_) => ResponseStatus::OkFreezeStatus,
            Self::OkCount(_) => ResponseStatus::OkCount,
            Self::OkOsInfo(_) => ResponseStatus::OkOsInfo,
            Self::OkInterfaces(_) => ResponseStatus::OkInterfaces,
            Self::OkFsInfo(_) => ResponseStatus::OkFsInfo,
            Self::OkFstrim(_) => ResponseStatus::OkFstrim,
            Self::OkSilent => ResponseStatus::OkSilent,
            Self::OkAck => ResponseStatus::OkAck,
            Self::OkChannelFd => ResponseStatus::OkChannelFd,
            Self::Err(_) => ResponseStatus::Err,
        }
    }
}

/// Complete decoded request together with its session/request binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedRequest {
    /// Originating parser channel session generation.
    pub session_gen: u64,
    /// Request identifier within `session_gen`.
    pub req_id: u64,
    /// Decoded typed request.
    pub request: IpcRequest,
}

/// Complete decoded response together with its session/request binding and
/// optional verified channel descriptor (present if and only if `response ==
/// IpcResponse::OkChannelFd`).
#[derive(Debug)]
pub struct ReceivedResponse {
    /// Originating parser channel session generation.
    pub session_gen: u64,
    /// Request identifier within `session_gen`.
    pub req_id: u64,
    /// Decoded typed response.
    pub response: IpcResponse,
    /// Verified channel descriptor transferred by `OkChannelFd`.
    pub channel_fd: Option<OwnedFd>,
}

/// Errors returned when encoding an IPC message exceeds protocol bounds.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    /// Encoded payload exceeds the opcode/status's assembled byte cap.
    #[error("IPC payload length {len} exceeds bound {limit}")]
    PayloadTooLarge {
        /// Encoded payload length.
        len: usize,
        /// Allowed cap in bytes.
        limit: usize,
    },
    /// A freeze-list entry exceeds [`MAX_FREEZE_LIST_ENTRY_BYTES`].
    #[error("freeze-list entry length {len} exceeds {MAX_FREEZE_LIST_ENTRY_BYTES}")]
    FreezeListEntryTooLong {
        /// Entry length in bytes.
        len: usize,
    },
    /// A field value cannot fit in its wire integer width.
    #[error("IPC field value out of wire range: {0}")]
    ValueOutOfRange(&'static str),
    /// Attempted to attach an `SCM_RIGHTS` descriptor to an invalid response
    /// or omitted the required descriptor on `OkChannelFd`.
    #[error("SCM_RIGHTS descriptor attachment mismatch for response")]
    InvalidDescriptorAttachment,
}

/// Strict protocol violation detected before dispatch (OQ-10 §4.1).
///
/// Any violation triggers immediate `ipc_protocol_violation` logging,
/// disconnect, and parser termination without partial dispatch.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProtocolViolation {
    /// Kernel reported `MSG_TRUNC` (packet exceeded `MAX_PACKET_BYTES`).
    #[error("IPC packet truncated (MSG_TRUNC)")]
    MessageTruncated,
    /// Kernel reported `MSG_CTRUNC` (ancillary control data truncated).
    #[error("IPC ancillary data truncated (MSG_CTRUNC)")]
    ControlMessageTruncated,
    /// Packet shorter than [`HEADER_BYTES`].
    #[error("IPC packet shorter than 23-byte header ({len} bytes)")]
    PacketTooShort {
        /// Received byte length.
        len: usize,
    },
    /// Unknown protocol version byte.
    #[error("unsupported IPC protocol version {0}")]
    UnsupportedVersion(u8),
    /// Unknown request opcode or response status byte.
    #[error("unknown IPC opcode/status tag 0x{0:02x}")]
    UnknownTag(u8),
    /// Unknown flag bit set in chunk header.
    #[error("unknown IPC chunk flags 0x{0:02x}")]
    UnknownFlags(u8),
    /// Header `payload_len` exceeds [`MAX_CHUNK_PAYLOAD_BYTES`].
    #[error("IPC chunk payload_len {0} exceeds 32 KiB limit")]
    ChunkPayloadTooLarge(u16),
    /// Header `payload_len` does not match received datagram byte count.
    #[error("IPC payload_len mismatch: header={header_len}, actual={actual_len}")]
    PayloadLengthMismatch {
        /// Declared length in header.
        header_len: usize,
        /// Actual payload bytes after header.
        actual_len: usize,
    },
    /// Unexpected ancillary data or file descriptor on a packet where zero
    /// control messages are allowed.
    #[error("unexpected ancillary data or file descriptors on IPC packet")]
    UnexpectedAncillaryData,
    /// `OkChannelFd` did not carry exactly one `SCM_RIGHTS` descriptor with
    /// zero extra/unknown control messages.
    #[error("OkChannelFd must carry exactly one SCM_RIGHTS descriptor and no other cmsgs")]
    InvalidChannelHandoffAncillary,
    /// Multi-chunk flags or non-zero `chunk_seq` on a single-chunk opcode/status.
    #[error("unexpected chunking on single-chunk IPC tag 0x{0:02x}")]
    UnexpectedChunking(u8),
    /// Duplicate `chunk_seq == 0` for an already active `(session_gen, req_id)`.
    #[error("duplicate active stream for ({session_gen}, {req_id})")]
    DuplicateStream {
        /// Session generation.
        session_gen: u64,
        /// Request id.
        req_id: u64,
    },
    /// Chunk arrived out of order or without an active stream.
    #[error("out-of-order IPC chunk {got} (expected {expected})")]
    OutOfOrderChunk {
        /// Expected next sequence number.
        expected: u16,
        /// Received sequence number.
        got: u16,
    },
    /// Continuation chunk carried a different opcode/status tag than chunk 0.
    #[error("IPC continuation chunk tag 0x{got:02x} does not match stream tag 0x{expected:02x}")]
    MismatchedChunkTag {
        /// Tag from chunk 0.
        expected: u8,
        /// Tag on continuation chunk.
        got: u8,
    },
    /// More than [`MAX_CONCURRENT_STREAMS`] multi-chunk streams active at once.
    #[error("exceeded max concurrent IPC streams ({MAX_CONCURRENT_STREAMS})")]
    TooManyConcurrentStreams,
    /// Assembled payload exceeds the opcode/status's explicit byte cap.
    #[error("assembled IPC payload exceeds {limit} byte bound")]
    AssembledPayloadTooLarge {
        /// Allowed cap in bytes.
        limit: usize,
    },
    /// Stream exceeded the opcode/status's maximum chunk count (`ceil(max_bytes / 32 KiB)`).
    #[error("IPC stream exceeded max chunk count ({max_chunks})")]
    ChunkCountExceeded {
        /// Maximum chunks permitted for this opcode/status.
        max_chunks: usize,
    },
    /// Decoded payload was truncated, contained invalid UTF-8 / enum tag, or
    /// left trailing bytes unconsumed.
    #[error("malformed IPC payload: {0}")]
    MalformedPayload(&'static str),
}

/// Transport error combining OS socket errors and codec/protocol failures.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// OS socket syscall error.
    #[error("IPC socket error: {0}")]
    Errno(#[from] Errno),
    /// Outbound message exceeded codec bounds.
    #[error(transparent)]
    Encode(#[from] EncodeError),
    /// Inbound message violated the IPC protocol.
    #[error(transparent)]
    Protocol(#[from] ProtocolViolation),
}

// ---------------------------------------------------------------------------
// Wire discriminant mappings for existing crate enums
// ---------------------------------------------------------------------------

const fn command_to_u8(cmd: Command) -> u8 {
    match cmd {
        Command::Ping => 0,
        Command::Info => 1,
        Command::Sync => 2,
        Command::SyncDelimited => 3,
        Command::GetOsInfo => 4,
        Command::NetworkGetInterfaces => 5,
        Command::GetFsInfo => 6,
        Command::FsfreezeStatus => 7,
        Command::FsfreezeFreeze => 8,
        Command::FsfreezeFreezeList => 9,
        Command::FsfreezeThaw => 10,
        Command::Fstrim => 11,
        Command::Shutdown => 12,
        Command::SuspendRam => 13,
    }
}

const fn command_from_u8(raw: u8) -> Option<Command> {
    match raw {
        0 => Some(Command::Ping),
        1 => Some(Command::Info),
        2 => Some(Command::Sync),
        3 => Some(Command::SyncDelimited),
        4 => Some(Command::GetOsInfo),
        5 => Some(Command::NetworkGetInterfaces),
        6 => Some(Command::GetFsInfo),
        7 => Some(Command::FsfreezeStatus),
        8 => Some(Command::FsfreezeFreeze),
        9 => Some(Command::FsfreezeFreezeList),
        10 => Some(Command::FsfreezeThaw),
        11 => Some(Command::Fstrim),
        12 => Some(Command::Shutdown),
        13 => Some(Command::SuspendRam),
        _ => None,
    }
}

const fn rate_class_to_u8(class: CommandClass) -> u8 {
    match class {
        CommandClass::PingSync => 0,
        CommandClass::Get => 1,
        CommandClass::FsfreezeFreeze => 2,
        CommandClass::Unlimited => 3,
        CommandClass::Fstrim => 4,
        CommandClass::Shutdown => 5,
    }
}

const fn rate_class_from_u8(raw: u8) -> Option<CommandClass> {
    match raw {
        0 => Some(CommandClass::PingSync),
        1 => Some(CommandClass::Get),
        2 => Some(CommandClass::FsfreezeFreeze),
        3 => Some(CommandClass::Unlimited),
        4 => Some(CommandClass::Fstrim),
        5 => Some(CommandClass::Shutdown),
        _ => None,
    }
}

const fn shutdown_mode_to_u8(mode: ShutdownMode) -> u8 {
    match mode {
        ShutdownMode::Powerdown => 0,
        ShutdownMode::Halt => 1,
        ShutdownMode::Reboot => 2,
    }
}

const fn shutdown_mode_from_u8(raw: u8) -> Option<ShutdownMode> {
    match raw {
        0 => Some(ShutdownMode::Powerdown),
        1 => Some(ShutdownMode::Halt),
        2 => Some(ShutdownMode::Reboot),
        _ => None,
    }
}

const fn freeze_state_to_u8(state: FreezeState) -> u8 {
    match state {
        FreezeState::Thawed => 0,
        FreezeState::Freezing => 1,
        FreezeState::Frozen => 2,
        FreezeState::Thawing => 3,
    }
}

const fn freeze_state_from_u8(raw: u8) -> Option<FreezeState> {
    match raw {
        0 => Some(FreezeState::Thawed),
        1 => Some(FreezeState::Freezing),
        2 => Some(FreezeState::Frozen),
        3 => Some(FreezeState::Thawing),
        _ => None,
    }
}

const fn freeze_task_stage_to_u8(stage: FreezeTaskStage) -> u8 {
    match stage {
        FreezeTaskStage::Preparation => 0,
        FreezeTaskStage::Rollback => 1,
        FreezeTaskStage::MarkerRemoval => 2,
    }
}

const fn freeze_task_stage_from_u8(raw: u8) -> Option<FreezeTaskStage> {
    match raw {
        0 => Some(FreezeTaskStage::Preparation),
        1 => Some(FreezeTaskStage::Rollback),
        2 => Some(FreezeTaskStage::MarkerRemoval),
        _ => None,
    }
}

const fn abort_cause_to_u8(cause: AbortCause) -> u8 {
    match cause {
        AbortCause::Deadline => 0,
        AbortCause::ThawRequested => 1,
        AbortCause::WorkerLost => 2,
    }
}

const fn abort_cause_from_u8(raw: u8) -> Option<AbortCause> {
    match raw {
        0 => Some(AbortCause::Deadline),
        1 => Some(AbortCause::ThawRequested),
        2 => Some(AbortCause::WorkerLost),
        _ => None,
    }
}

const fn recovery_reason_to_u8(reason: RecoveryReason) -> u8 {
    match reason {
        RecoveryReason::TargetUnreachable => 0,
        RecoveryReason::TargetOpenFailed => 1,
        RecoveryReason::TargetOpenPermissionDenied => 2,
        RecoveryReason::PermissionDenied => 3,
        RecoveryReason::IoctlFailed => 4,
        RecoveryReason::DrainDidNotConverge => 5,
        RecoveryReason::RecoveryIncomplete => 6,
        RecoveryReason::WorkerLost => 7,
        RecoveryReason::DrainLost => 8,
        RecoveryReason::MarkerRetained => 9,
        RecoveryReason::OwnershipAmbiguous => 10,
        RecoveryReason::OwnershipError => 11,
    }
}

const fn recovery_reason_from_u8(raw: u8) -> Option<RecoveryReason> {
    match raw {
        0 => Some(RecoveryReason::TargetUnreachable),
        1 => Some(RecoveryReason::TargetOpenFailed),
        2 => Some(RecoveryReason::TargetOpenPermissionDenied),
        3 => Some(RecoveryReason::PermissionDenied),
        4 => Some(RecoveryReason::IoctlFailed),
        5 => Some(RecoveryReason::DrainDidNotConverge),
        6 => Some(RecoveryReason::RecoveryIncomplete),
        7 => Some(RecoveryReason::WorkerLost),
        8 => Some(RecoveryReason::DrainLost),
        9 => Some(RecoveryReason::MarkerRetained),
        10 => Some(RecoveryReason::OwnershipAmbiguous),
        11 => Some(RecoveryReason::OwnershipError),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Binary cursor helpers (non-recursive, zero panic, strict trailing check)
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn finish(self) -> Result<(), ProtocolViolation> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(ProtocolViolation::MalformedPayload("trailing bytes"))
        }
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], ProtocolViolation> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or(ProtocolViolation::MalformedPayload("length overflow"))?;
        if end > self.buf.len() {
            return Err(ProtocolViolation::MalformedPayload("unexpected EOF"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, ProtocolViolation> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_bool(&mut self) -> Result<bool, ProtocolViolation> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(ProtocolViolation::MalformedPayload("invalid bool")),
        }
    }

    fn read_u16(&mut self) -> Result<u16, ProtocolViolation> {
        let b = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, ProtocolViolation> {
        let b = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i32(&mut self) -> Result<i32, ProtocolViolation> {
        let b = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, ProtocolViolation> {
        let b = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_i64(&mut self) -> Result<i64, ProtocolViolation> {
        let b = self.read_bytes(8)?;
        let mut arr = [0u8; 8];
        arr.copy_from_slice(b);
        Ok(i64::from_le_bytes(arr))
    }

    fn read_str_u16(&mut self, max_len: usize) -> Result<String, ProtocolViolation> {
        let len = usize::from(self.read_u16()?);
        if len > max_len {
            return Err(ProtocolViolation::MalformedPayload("string exceeds bound"));
        }
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ProtocolViolation::MalformedPayload("invalid UTF-8"))
    }

    fn read_str_u32(&mut self, max_len: usize) -> Result<String, ProtocolViolation> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| ProtocolViolation::MalformedPayload("string length overflow"))?;
        if len > max_len {
            return Err(ProtocolViolation::MalformedPayload("string exceeds bound"));
        }
        let bytes = self.read_bytes(len)?;
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| ProtocolViolation::MalformedPayload("invalid UTF-8"))
    }

    fn read_opt_u64(&mut self) -> Result<Option<u64>, ProtocolViolation> {
        if self.read_bool()? {
            Ok(Some(self.read_u64()?))
        } else {
            Ok(None)
        }
    }

    fn read_opt_str_u32(&mut self, max_len: usize) -> Result<Option<String>, ProtocolViolation> {
        if self.read_bool()? {
            Ok(Some(self.read_str_u32(max_len)?))
        } else {
            Ok(None)
        }
    }

    fn read_freeze_stop_reason(&mut self) -> Result<FreezeStopReason, ProtocolViolation> {
        match self.read_u8()? {
            0 => Ok(FreezeStopReason::FifreezePermissionDenied),
            1 => Ok(FreezeStopReason::TargetOpenFailed),
            2 => Ok(FreezeStopReason::TargetUnreachable),
            3 => Ok(FreezeStopReason::FifreezeFailed),
            4 => Ok(FreezeStopReason::TargetOpenPermissionDenied),
            5 => Ok(FreezeStopReason::OwnershipAmbiguousClaim),
            6 => Ok(FreezeStopReason::OwnershipError),
            7 => Ok(FreezeStopReason::OwnershipAmbiguousRecovery),
            8 => Ok(FreezeStopReason::ReleaseRecovery(
                recovery_reason_from_u8(self.read_u8()?).ok_or(
                    ProtocolViolation::MalformedPayload("invalid recovery reason"),
                )?,
            )),
            _ => Err(ProtocolViolation::MalformedPayload(
                "invalid freeze stop reason",
            )),
        }
    }
}

fn write_str_u32(out: &mut Vec<u8>, s: &str) -> Result<(), EncodeError> {
    let len = u32::try_from(s.len()).map_err(|_| EncodeError::ValueOutOfRange("string u32 len"))?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Ok(())
}

fn write_opt_str_u32(out: &mut Vec<u8>, s: Option<&str>) -> Result<(), EncodeError> {
    match s {
        Some(v) => {
            out.push(1);
            write_str_u32(out, v)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

fn write_opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(n) => {
            out.push(1);
            out.extend_from_slice(&n.to_le_bytes());
        }
        None => out.push(0),
    }
}

fn write_freeze_stop_reason(out: &mut Vec<u8>, reason: FreezeStopReason) {
    match reason {
        FreezeStopReason::FifreezePermissionDenied => out.push(0),
        FreezeStopReason::TargetOpenFailed => out.push(1),
        FreezeStopReason::TargetUnreachable => out.push(2),
        FreezeStopReason::FifreezeFailed => out.push(3),
        FreezeStopReason::TargetOpenPermissionDenied => out.push(4),
        FreezeStopReason::OwnershipAmbiguousClaim => out.push(5),
        FreezeStopReason::OwnershipError => out.push(6),
        FreezeStopReason::OwnershipAmbiguousRecovery => out.push(7),
        FreezeStopReason::ReleaseRecovery(rr) => {
            out.push(8);
            out.push(recovery_reason_to_u8(rr));
        }
    }
}

// ---------------------------------------------------------------------------
// Payload encoding
// ---------------------------------------------------------------------------

fn encode_request_payload(req: &IpcRequest) -> Result<Vec<u8>, EncodeError> {
    let limit = req.opcode().max_payload_bytes();
    let mut out = Vec::new();
    match req {
        IpcRequest::Ping
        | IpcRequest::Info
        | IpcRequest::FsfreezeStatus
        | IpcRequest::FsfreezeFreeze
        | IpcRequest::FsfreezeThaw
        | IpcRequest::GetOsInfo
        | IpcRequest::NetworkGetInterfaces
        | IpcRequest::GetFsInfo
        | IpcRequest::SuspendRam
        | IpcRequest::RequestChannelReopen => {}
        IpcRequest::Sync { id } | IpcRequest::SyncDelimited { id } => {
            out.extend_from_slice(&id.to_le_bytes());
        }
        IpcRequest::Fstrim { minimum } => {
            out.extend_from_slice(&minimum.to_le_bytes());
        }
        IpcRequest::Shutdown { mode } => {
            out.push(shutdown_mode_to_u8(*mode));
        }
        IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted) => {
            out.push(0);
        }
        IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(entries)) => {
            let count = u16::try_from(entries.len())
                .map_err(|_| EncodeError::ValueOutOfRange("freeze-list count"))?;
            out.push(1);
            out.extend_from_slice(&count.to_le_bytes());
            for entry in entries {
                if entry.len() > MAX_FREEZE_LIST_ENTRY_BYTES {
                    return Err(EncodeError::FreezeListEntryTooLong { len: entry.len() });
                }
                let elen = u16::try_from(entry.len())
                    .map_err(|_| EncodeError::FreezeListEntryTooLong { len: entry.len() })?;
                if out.len() + 2 + entry.len() > limit {
                    return Err(EncodeError::PayloadTooLarge {
                        len: out.len() + 2 + entry.len(),
                        limit,
                    });
                }
                out.extend_from_slice(&elen.to_le_bytes());
                out.extend_from_slice(entry.as_bytes());
            }
        }
        IpcRequest::ReportParseRejection(rej) => {
            out.push(rej.kind as u8);
            out.extend_from_slice(&rej.frame_len.to_le_bytes());
            match rej.id {
                Some(id) => {
                    out.push(1);
                    out.extend_from_slice(&id.to_le_bytes());
                }
                None => out.push(0),
            }
            match &rej.method {
                None => out.push(0),
                Some(ProjectedMethod::Full(s)) => {
                    if s.len() > MAX_METHOD_BYTES {
                        return Err(EncodeError::ValueOutOfRange("method full length"));
                    }
                    let slen = u16::try_from(s.len())
                        .map_err(|_| EncodeError::ValueOutOfRange("method full u16"))?;
                    out.push(1);
                    out.extend_from_slice(&slen.to_le_bytes());
                    out.extend_from_slice(s.as_bytes());
                }
                Some(ProjectedMethod::Projected {
                    prefix,
                    len_bytes,
                    digest,
                }) => {
                    if prefix.len() > MAX_METHOD_BYTES {
                        return Err(EncodeError::ValueOutOfRange("method prefix length"));
                    }
                    let plen = u16::try_from(prefix.len())
                        .map_err(|_| EncodeError::ValueOutOfRange("method prefix u16"))?;
                    out.push(2);
                    out.extend_from_slice(&plen.to_le_bytes());
                    out.extend_from_slice(prefix.as_bytes());
                    out.extend_from_slice(&len_bytes.to_le_bytes());
                    out.extend_from_slice(digest);
                }
            }
        }
    }
    if out.len() > limit {
        return Err(EncodeError::PayloadTooLarge {
            len: out.len(),
            limit,
        });
    }
    Ok(out)
}

fn encode_response_payload(resp: &IpcResponse) -> Result<Vec<u8>, EncodeError> {
    let limit = resp.status().max_payload_bytes();
    let mut out = Vec::new();
    match resp {
        IpcResponse::OkEmpty
        | IpcResponse::OkSilent
        | IpcResponse::OkAck
        | IpcResponse::OkChannelFd => {}
        IpcResponse::OkInfo(caps) => {
            let count = u16::try_from(caps.len())
                .map_err(|_| EncodeError::ValueOutOfRange("info capability count"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for cap in caps {
                out.push(command_to_u8(cap.command));
                out.push(u8::from(cap.enabled));
                out.push(u8::from(cap.success_response));
            }
        }
        IpcResponse::OkI64(id) => out.extend_from_slice(&id.to_le_bytes()),
        IpcResponse::OkFreezeStatus(status) => out.push(*status as u8),
        IpcResponse::OkCount(count) => out.extend_from_slice(&count.to_le_bytes()),
        IpcResponse::OkOsInfo(info) => {
            let fields: [Option<&str>; 10] = [
                info.kernel_release.as_deref(),
                info.kernel_version.as_deref(),
                info.machine.as_deref(),
                info.id.as_deref(),
                info.name.as_deref(),
                info.pretty_name.as_deref(),
                info.version.as_deref(),
                info.version_id.as_deref(),
                info.variant.as_deref(),
                info.variant_id.as_deref(),
            ];
            let mut mask = 0u16;
            for (bit, field) in fields.iter().enumerate() {
                if field.is_some() {
                    mask |= 1u16 << bit;
                }
            }
            out.extend_from_slice(&mask.to_le_bytes());
            for field in fields.into_iter().flatten() {
                write_str_u32(&mut out, field)?;
                if out.len() > limit {
                    return Err(EncodeError::PayloadTooLarge {
                        len: out.len(),
                        limit,
                    });
                }
            }
        }
        IpcResponse::OkInterfaces(ifaces) => {
            let count = u32::try_from(ifaces.len())
                .map_err(|_| EncodeError::ValueOutOfRange("interface count"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for iface in ifaces {
                write_str_u32(&mut out, &iface.name)?;
                write_opt_str_u32(&mut out, iface.hardware_address.as_deref())?;
                let ip_count = u32::try_from(iface.ip_addresses.len())
                    .map_err(|_| EncodeError::ValueOutOfRange("ip count"))?;
                out.extend_from_slice(&ip_count.to_le_bytes());
                for ip in &iface.ip_addresses {
                    out.push(ip.kind as u8);
                    out.push(ip.prefix);
                    write_str_u32(&mut out, &ip.ip_address)?;
                    if out.len() > limit {
                        return Err(EncodeError::PayloadTooLarge {
                            len: out.len(),
                            limit,
                        });
                    }
                }
                if out.len() > limit {
                    return Err(EncodeError::PayloadTooLarge {
                        len: out.len(),
                        limit,
                    });
                }
            }
        }
        IpcResponse::OkFsInfo(entries) => {
            let count = u32::try_from(entries.len())
                .map_err(|_| EncodeError::ValueOutOfRange("fsinfo count"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for entry in entries {
                write_str_u32(&mut out, &entry.name)?;
                write_str_u32(&mut out, &entry.mountpoint)?;
                write_str_u32(&mut out, &entry.fs_type)?;
                write_opt_u64(&mut out, entry.used_bytes);
                write_opt_u64(&mut out, entry.total_bytes);
                if out.len() > limit {
                    return Err(EncodeError::PayloadTooLarge {
                        len: out.len(),
                        limit,
                    });
                }
            }
        }
        IpcResponse::OkFstrim(entries) => {
            let count = u32::try_from(entries.len())
                .map_err(|_| EncodeError::ValueOutOfRange("fstrim count"))?;
            out.extend_from_slice(&count.to_le_bytes());
            for entry in entries {
                write_str_u32(&mut out, &entry.path)?;
                match entry.outcome {
                    TrimPathOutcome::Trimmed { trimmed, minimum } => {
                        out.push(0);
                        out.extend_from_slice(&trimmed.to_le_bytes());
                        out.extend_from_slice(&minimum.to_le_bytes());
                    }
                    TrimPathOutcome::OpenPermissionDenied => out.push(1),
                    TrimPathOutcome::TargetUnreachable => out.push(2),
                    TrimPathOutcome::IoctlErrno(errno) => {
                        out.push(3);
                        out.extend_from_slice(&errno.to_le_bytes());
                    }
                }
                if out.len() > limit {
                    return Err(EncodeError::PayloadTooLarge {
                        len: out.len(),
                        limit,
                    });
                }
            }
        }
        IpcResponse::Err(code) => encode_error_code(&mut out, *code),
    }
    if out.len() > limit {
        return Err(EncodeError::PayloadTooLarge {
            len: out.len(),
            limit,
        });
    }
    Ok(out)
}

fn encode_error_code(out: &mut Vec<u8>, code: IpcErrorCode) {
    match code {
        IpcErrorCode::Disabled { command } => {
            out.push(0x01);
            out.push(command_to_u8(command));
        }
        IpcErrorCode::Frozen => out.push(0x02),
        IpcErrorCode::RateLimited { class } => {
            out.push(0x03);
            out.push(rate_class_to_u8(class));
        }
        IpcErrorCode::InvalidArguments { command } => {
            out.push(0x04);
            out.push(command_to_u8(command));
        }
        IpcErrorCode::TransitionConflict { op, current } => {
            out.push(0x05);
            out.push(op as u8);
            out.push(freeze_state_to_u8(current));
        }
        IpcErrorCode::FreezePlanFailed => out.push(0x06),
        IpcErrorCode::FreezeMarkerFailed { reason } => {
            out.push(0x07);
            out.push(reason as u8);
        }
        IpcErrorCode::FreezeHard { cause, rolled_back } => {
            out.push(0x08);
            write_freeze_stop_reason(out, cause);
            out.extend_from_slice(&rolled_back.to_le_bytes());
        }
        IpcErrorCode::FreezeRollbackIncomplete {
            cause,
            recovery_reason,
            rolled_back,
        } => {
            out.push(0x09);
            write_freeze_stop_reason(out, cause);
            out.push(recovery_reason_to_u8(recovery_reason));
            out.extend_from_slice(&rolled_back.to_le_bytes());
        }
        IpcErrorCode::FreezeMarkerRetained {
            cause,
            marker_reason,
            rolled_back,
        } => {
            out.push(0x0A);
            write_freeze_stop_reason(out, cause);
            out.push(marker_reason as u8);
            out.extend_from_slice(&rolled_back.to_le_bytes());
        }
        IpcErrorCode::FreezePreparationMarkerRetained { marker_reason } => {
            out.push(0x0B);
            out.push(marker_reason as u8);
        }
        IpcErrorCode::FreezeTaskFailed { stage } => {
            out.push(0x0C);
            out.push(freeze_task_stage_to_u8(stage));
        }
        IpcErrorCode::FreezeNothingFrozenMarkerRetained { marker_reason } => {
            out.push(0x0D);
            out.push(marker_reason as u8);
        }
        IpcErrorCode::FreezeAborted {
            cause,
            frozen,
            activity,
        } => {
            out.push(0x0E);
            out.push(abort_cause_to_u8(cause));
            out.extend_from_slice(&frozen.to_le_bytes());
            out.push(activity as u8);
        }
        IpcErrorCode::ThawPlanFailed {
            thawed,
            final_state,
            marker_retained,
        } => {
            out.push(0x0F);
            out.extend_from_slice(&thawed.to_le_bytes());
            out.push(freeze_state_to_u8(final_state));
            out.push(u8::from(marker_retained));
        }
        IpcErrorCode::ThawIncomplete {
            kind,
            thawed,
            final_state,
            marker_retained,
        } => {
            out.push(0x10);
            out.push(recovery_reason_to_u8(kind));
            out.extend_from_slice(&thawed.to_le_bytes());
            out.push(freeze_state_to_u8(final_state));
            out.push(u8::from(marker_retained));
        }
        IpcErrorCode::ThawMarkerFailed {
            reason,
            thawed,
            final_state,
            marker_retained,
        } => {
            out.push(0x11);
            out.push(reason as u8);
            out.extend_from_slice(&thawed.to_le_bytes());
            out.push(freeze_state_to_u8(final_state));
            out.push(u8::from(marker_retained));
        }
        IpcErrorCode::ThawTaskFailed {
            final_state,
            marker_retained,
        } => {
            out.push(0x12);
            out.push(freeze_state_to_u8(final_state));
            out.push(u8::from(marker_retained));
        }
        IpcErrorCode::ThawAbortPending { activity, thawed } => {
            out.push(0x13);
            out.push(activity as u8);
            out.extend_from_slice(&thawed.to_le_bytes());
        }
        IpcErrorCode::FstrimReplyTooLarge {
            trimmed_targets,
            failed_targets,
            limit_bytes,
        } => {
            out.push(0x14);
            out.extend_from_slice(&trimmed_targets.to_le_bytes());
            out.extend_from_slice(&failed_targets.to_le_bytes());
            out.extend_from_slice(&limit_bytes.to_le_bytes());
        }
        IpcErrorCode::ReplyTooLarge {
            command,
            reply_bytes,
            limit_bytes,
        } => {
            out.push(0x15);
            out.push(command_to_u8(command));
            out.extend_from_slice(&reply_bytes.to_le_bytes());
            out.extend_from_slice(&limit_bytes.to_le_bytes());
        }
        IpcErrorCode::FsinfoBusy => out.push(0x16),
        IpcErrorCode::FsinfoTimeout => out.push(0x17),
        IpcErrorCode::HandlerFailed { command } => {
            out.push(0x18);
            out.push(command_to_u8(command));
        }
        IpcErrorCode::ChannelRetryLater => out.push(0x19),
        IpcErrorCode::ChannelTerminalBusy => out.push(0x1A),
    }
}

// ---------------------------------------------------------------------------
// Payload decoding
// ---------------------------------------------------------------------------

fn decode_request_payload(
    opcode: RequestOpcode,
    payload: &[u8],
) -> Result<IpcRequest, ProtocolViolation> {
    let mut r = Reader::new(payload);
    let req = match opcode {
        RequestOpcode::Ping => IpcRequest::Ping,
        RequestOpcode::Info => IpcRequest::Info,
        RequestOpcode::Sync => IpcRequest::Sync { id: r.read_i64()? },
        RequestOpcode::SyncDelimited => IpcRequest::SyncDelimited { id: r.read_i64()? },
        RequestOpcode::FsfreezeStatus => IpcRequest::FsfreezeStatus,
        RequestOpcode::FsfreezeFreeze => IpcRequest::FsfreezeFreeze,
        RequestOpcode::FsfreezeFreezeList => match r.read_u8()? {
            0 => IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted),
            1 => {
                let count = usize::from(r.read_u16()?);
                // Minimum 2 bytes per entry (the u16 length prefix): reject
                // impossible counts before allocating any Vec capacity.
                if count.saturating_mul(2) > r.remaining() {
                    return Err(ProtocolViolation::MalformedPayload(
                        "freeze-list count exceeds remaining bytes",
                    ));
                }
                let mut entries = Vec::with_capacity(count);
                for _ in 0..count {
                    entries.push(r.read_str_u16(MAX_FREEZE_LIST_ENTRY_BYTES)?);
                }
                IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(entries))
            }
            _ => {
                return Err(ProtocolViolation::MalformedPayload(
                    "invalid freeze-list presence flag",
                ));
            }
        },
        RequestOpcode::FsfreezeThaw => IpcRequest::FsfreezeThaw,
        RequestOpcode::GetOsInfo => IpcRequest::GetOsInfo,
        RequestOpcode::NetworkGetInterfaces => IpcRequest::NetworkGetInterfaces,
        RequestOpcode::GetFsInfo => IpcRequest::GetFsInfo,
        RequestOpcode::Fstrim => IpcRequest::Fstrim {
            minimum: r.read_u64()?,
        },
        RequestOpcode::Shutdown => {
            let mode = shutdown_mode_from_u8(r.read_u8()?)
                .ok_or(ProtocolViolation::MalformedPayload("invalid shutdown mode"))?;
            IpcRequest::Shutdown { mode }
        }
        RequestOpcode::SuspendRam => IpcRequest::SuspendRam,
        RequestOpcode::ReportParseRejection => {
            let kind = ParseRejectionKind::from_u8(r.read_u8()?).ok_or(
                ProtocolViolation::MalformedPayload("invalid parse rejection kind"),
            )?;
            let frame_len = r.read_u32()?;
            let id = if r.read_bool()? {
                Some(r.read_i64()?)
            } else {
                None
            };
            let method = match r.read_u8()? {
                0 => None,
                1 => Some(ProjectedMethod::Full(r.read_str_u16(MAX_METHOD_BYTES)?)),
                2 => {
                    let prefix = r.read_str_u16(MAX_METHOD_BYTES)?;
                    let len_bytes = r.read_u32()?;
                    let raw_digest = r.read_bytes(32)?;
                    let mut digest = [0u8; 32];
                    digest.copy_from_slice(raw_digest);
                    Some(ProjectedMethod::Projected {
                        prefix,
                        len_bytes,
                        digest,
                    })
                }
                _ => {
                    return Err(ProtocolViolation::MalformedPayload(
                        "invalid projected method tag",
                    ));
                }
            };
            IpcRequest::ReportParseRejection(ParseRejection {
                kind,
                frame_len,
                id,
                method,
            })
        }
        RequestOpcode::RequestChannelReopen => IpcRequest::RequestChannelReopen,
    };
    r.finish()?;
    Ok(req)
}

fn decode_response_payload(
    status: ResponseStatus,
    payload: &[u8],
) -> Result<IpcResponse, ProtocolViolation> {
    let limit = status.max_payload_bytes();
    let mut r = Reader::new(payload);
    let resp = match status {
        ResponseStatus::OkEmpty => IpcResponse::OkEmpty,
        ResponseStatus::OkInfo => {
            let count = usize::from(r.read_u16()?);
            if count > Command::ALL.len() || count.saturating_mul(3) > r.remaining() {
                return Err(ProtocolViolation::MalformedPayload(
                    "invalid command capability count",
                ));
            }
            let mut caps = Vec::with_capacity(count);
            for _ in 0..count {
                let command = command_from_u8(r.read_u8()?)
                    .ok_or(ProtocolViolation::MalformedPayload("invalid command id"))?;
                let enabled = r.read_bool()?;
                let success_response = r.read_bool()?;
                caps.push(CommandCapability {
                    command,
                    enabled,
                    success_response,
                });
            }
            IpcResponse::OkInfo(caps)
        }
        ResponseStatus::OkI64 => IpcResponse::OkI64(r.read_i64()?),
        ResponseStatus::OkFreezeStatus => {
            let fs = WireFreezeStatus::from_u8(r.read_u8()?)
                .ok_or(ProtocolViolation::MalformedPayload("invalid freeze status"))?;
            IpcResponse::OkFreezeStatus(fs)
        }
        ResponseStatus::OkCount => IpcResponse::OkCount(r.read_u64()?),
        ResponseStatus::OkOsInfo => {
            let mask = r.read_u16()?;
            if (mask & !0x03FF) != 0 {
                return Err(ProtocolViolation::MalformedPayload(
                    "unknown osinfo presence bit",
                ));
            }
            let mut next = |bit: u16| -> Result<Option<String>, ProtocolViolation> {
                if (mask & (1u16 << bit)) != 0 {
                    Ok(Some(r.read_str_u32(limit)?))
                } else {
                    Ok(None)
                }
            };
            IpcResponse::OkOsInfo(Box::new(OsInfo {
                kernel_release: next(0)?,
                kernel_version: next(1)?,
                machine: next(2)?,
                id: next(3)?,
                name: next(4)?,
                pretty_name: next(5)?,
                version: next(6)?,
                version_id: next(7)?,
                variant: next(8)?,
                variant_id: next(9)?,
            }))
        }
        ResponseStatus::OkInterfaces => {
            let count = usize::try_from(r.read_u32()?)
                .map_err(|_| ProtocolViolation::MalformedPayload("interface count overflow"))?;
            // Minimum 9 bytes per interface: name len(4) + opt_mac(1) + ip_count(4).
            if count.saturating_mul(9) > r.remaining() {
                return Err(ProtocolViolation::MalformedPayload(
                    "interface count exceeds remaining bytes",
                ));
            }
            let mut ifaces = Vec::with_capacity(count);
            for _ in 0..count {
                let name = r.read_str_u32(limit)?;
                let hardware_address = r.read_opt_str_u32(limit)?;
                let ip_count = usize::try_from(r.read_u32()?)
                    .map_err(|_| ProtocolViolation::MalformedPayload("ip count overflow"))?;
                // Minimum 6 bytes per IP: kind(1) + prefix(1) + addr len(4).
                if ip_count.saturating_mul(6) > r.remaining() {
                    return Err(ProtocolViolation::MalformedPayload(
                        "ip count exceeds remaining bytes",
                    ));
                }
                let mut ip_addresses = Vec::with_capacity(ip_count);
                for _ in 0..ip_count {
                    let kind = IpAddressKind::from_u8(r.read_u8()?).ok_or(
                        ProtocolViolation::MalformedPayload("invalid ip address kind"),
                    )?;
                    let prefix = r.read_u8()?;
                    let max_prefix = match kind {
                        IpAddressKind::Ipv4 => 32,
                        IpAddressKind::Ipv6 => 128,
                    };
                    if prefix > max_prefix {
                        return Err(ProtocolViolation::MalformedPayload(
                            "ip prefix out of range",
                        ));
                    }
                    let ip_address = r.read_str_u32(limit)?;
                    ip_addresses.push(IpAddressDto {
                        ip_address,
                        kind,
                        prefix,
                    });
                }
                ifaces.push(InterfaceDto {
                    name,
                    hardware_address,
                    ip_addresses,
                });
            }
            IpcResponse::OkInterfaces(ifaces)
        }
        ResponseStatus::OkFsInfo => {
            let count = usize::try_from(r.read_u32()?)
                .map_err(|_| ProtocolViolation::MalformedPayload("fsinfo count overflow"))?;
            // Minimum 14 bytes per entry: 3*u32 len + 2*opt_u64 presence tags.
            if count.saturating_mul(14) > r.remaining() {
                return Err(ProtocolViolation::MalformedPayload(
                    "fsinfo count exceeds remaining bytes",
                ));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let name = r.read_str_u32(limit)?;
                let mountpoint = r.read_str_u32(limit)?;
                let fs_type = r.read_str_u32(limit)?;
                let used_bytes = r.read_opt_u64()?;
                let total_bytes = r.read_opt_u64()?;
                entries.push(FsInfoDto {
                    name,
                    mountpoint,
                    fs_type,
                    used_bytes,
                    total_bytes,
                });
            }
            IpcResponse::OkFsInfo(entries)
        }
        ResponseStatus::OkFstrim => {
            let count = usize::try_from(r.read_u32()?)
                .map_err(|_| ProtocolViolation::MalformedPayload("fstrim count overflow"))?;
            // Minimum 5 bytes per entry: path len(4) + outcome tag(1).
            if count.saturating_mul(5) > r.remaining() {
                return Err(ProtocolViolation::MalformedPayload(
                    "fstrim count exceeds remaining bytes",
                ));
            }
            let mut entries = Vec::with_capacity(count);
            for _ in 0..count {
                let path = r.read_str_u32(limit)?;
                let outcome = match r.read_u8()? {
                    0 => TrimPathOutcome::Trimmed {
                        trimmed: r.read_u64()?,
                        minimum: r.read_u64()?,
                    },
                    1 => TrimPathOutcome::OpenPermissionDenied,
                    2 => TrimPathOutcome::TargetUnreachable,
                    3 => TrimPathOutcome::IoctlErrno(r.read_i32()?),
                    _ => {
                        return Err(ProtocolViolation::MalformedPayload(
                            "invalid trim path outcome tag",
                        ));
                    }
                };
                entries.push(TrimPathDto { path, outcome });
            }
            IpcResponse::OkFstrim(entries)
        }
        ResponseStatus::OkSilent => IpcResponse::OkSilent,
        ResponseStatus::OkAck => IpcResponse::OkAck,
        ResponseStatus::OkChannelFd => IpcResponse::OkChannelFd,
        ResponseStatus::Err => IpcResponse::Err(decode_error_code(&mut r)?),
    };
    r.finish()?;
    Ok(resp)
}

fn decode_error_code(r: &mut Reader<'_>) -> Result<IpcErrorCode, ProtocolViolation> {
    let cmd = |raw: u8| {
        command_from_u8(raw).ok_or(ProtocolViolation::MalformedPayload("invalid command id"))
    };
    let state = |raw: u8| {
        freeze_state_from_u8(raw).ok_or(ProtocolViolation::MalformedPayload("invalid freeze state"))
    };
    let marker = |raw: u8| {
        MarkerHostReason::from_u8(raw)
            .ok_or(ProtocolViolation::MalformedPayload("invalid marker reason"))
    };
    let recovery = |raw: u8| {
        recovery_reason_from_u8(raw).ok_or(ProtocolViolation::MalformedPayload(
            "invalid recovery reason",
        ))
    };
    match r.read_u8()? {
        0x01 => Ok(IpcErrorCode::Disabled {
            command: cmd(r.read_u8()?)?,
        }),
        0x02 => Ok(IpcErrorCode::Frozen),
        0x03 => Ok(IpcErrorCode::RateLimited {
            class: rate_class_from_u8(r.read_u8()?)
                .ok_or(ProtocolViolation::MalformedPayload("invalid rate class"))?,
        }),
        0x04 => Ok(IpcErrorCode::InvalidArguments {
            command: cmd(r.read_u8()?)?,
        }),
        0x05 => Ok(IpcErrorCode::TransitionConflict {
            op: TransitionOp::from_u8(r.read_u8()?)
                .ok_or(ProtocolViolation::MalformedPayload("invalid transition op"))?,
            current: state(r.read_u8()?)?,
        }),
        0x06 => Ok(IpcErrorCode::FreezePlanFailed),
        0x07 => Ok(IpcErrorCode::FreezeMarkerFailed {
            reason: marker(r.read_u8()?)?,
        }),
        0x08 => Ok(IpcErrorCode::FreezeHard {
            cause: r.read_freeze_stop_reason()?,
            rolled_back: r.read_u64()?,
        }),
        0x09 => Ok(IpcErrorCode::FreezeRollbackIncomplete {
            cause: r.read_freeze_stop_reason()?,
            recovery_reason: recovery(r.read_u8()?)?,
            rolled_back: r.read_u64()?,
        }),
        0x0A => Ok(IpcErrorCode::FreezeMarkerRetained {
            cause: r.read_freeze_stop_reason()?,
            marker_reason: marker(r.read_u8()?)?,
            rolled_back: r.read_u64()?,
        }),
        0x0B => Ok(IpcErrorCode::FreezePreparationMarkerRetained {
            marker_reason: marker(r.read_u8()?)?,
        }),
        0x0C => Ok(IpcErrorCode::FreezeTaskFailed {
            stage: freeze_task_stage_from_u8(r.read_u8()?).ok_or(
                ProtocolViolation::MalformedPayload("invalid freeze task stage"),
            )?,
        }),
        0x0D => Ok(IpcErrorCode::FreezeNothingFrozenMarkerRetained {
            marker_reason: marker(r.read_u8()?)?,
        }),
        0x0E => Ok(IpcErrorCode::FreezeAborted {
            cause: abort_cause_from_u8(r.read_u8()?)
                .ok_or(ProtocolViolation::MalformedPayload("invalid abort cause"))?,
            frozen: r.read_u64()?,
            activity: AbortActivity::from_u8(r.read_u8()?).ok_or(
                ProtocolViolation::MalformedPayload("invalid abort activity"),
            )?,
        }),
        0x0F => Ok(IpcErrorCode::ThawPlanFailed {
            thawed: r.read_u64()?,
            final_state: state(r.read_u8()?)?,
            marker_retained: r.read_bool()?,
        }),
        0x10 => Ok(IpcErrorCode::ThawIncomplete {
            kind: recovery(r.read_u8()?)?,
            thawed: r.read_u64()?,
            final_state: state(r.read_u8()?)?,
            marker_retained: r.read_bool()?,
        }),
        0x11 => Ok(IpcErrorCode::ThawMarkerFailed {
            reason: marker(r.read_u8()?)?,
            thawed: r.read_u64()?,
            final_state: state(r.read_u8()?)?,
            marker_retained: r.read_bool()?,
        }),
        0x12 => Ok(IpcErrorCode::ThawTaskFailed {
            final_state: state(r.read_u8()?)?,
            marker_retained: r.read_bool()?,
        }),
        0x13 => Ok(IpcErrorCode::ThawAbortPending {
            activity: AbortActivity::from_u8(r.read_u8()?).ok_or(
                ProtocolViolation::MalformedPayload("invalid abort activity"),
            )?,
            thawed: r.read_u64()?,
        }),
        0x14 => Ok(IpcErrorCode::FstrimReplyTooLarge {
            trimmed_targets: r.read_u64()?,
            failed_targets: r.read_u64()?,
            limit_bytes: r.read_u64()?,
        }),
        0x15 => Ok(IpcErrorCode::ReplyTooLarge {
            command: cmd(r.read_u8()?)?,
            reply_bytes: r.read_u64()?,
            limit_bytes: r.read_u64()?,
        }),
        0x16 => Ok(IpcErrorCode::FsinfoBusy),
        0x17 => Ok(IpcErrorCode::FsinfoTimeout),
        0x18 => Ok(IpcErrorCode::HandlerFailed {
            command: cmd(r.read_u8()?)?,
        }),
        0x19 => Ok(IpcErrorCode::ChannelRetryLater),
        0x1A => Ok(IpcErrorCode::ChannelTerminalBusy),
        _ => Err(ProtocolViolation::MalformedPayload(
            "invalid error code tag",
        )),
    }
}

// ---------------------------------------------------------------------------
// Chunk splitting & reassembly
// ---------------------------------------------------------------------------

fn split_into_chunks(
    session_gen: u64,
    req_id: u64,
    tag: u8,
    payload: &[u8],
) -> Result<Vec<Vec<u8>>, EncodeError> {
    if payload.is_empty() {
        let mut pkt = Vec::with_capacity(HEADER_BYTES);
        ChunkHeader {
            version: IPC_VERSION,
            session_gen,
            req_id,
            tag,
            flags: 0,
            chunk_seq: 0,
            payload_len: 0,
        }
        .encode_into(&mut pkt);
        return Ok(vec![pkt]);
    }
    let total_chunks = payload.len().div_ceil(MAX_CHUNK_PAYLOAD_BYTES);
    if total_chunks > usize::from(u16::MAX) {
        return Err(EncodeError::ValueOutOfRange("chunk_seq overflow"));
    }
    let mut packets = Vec::with_capacity(total_chunks);
    for (idx, slice) in payload.chunks(MAX_CHUNK_PAYLOAD_BYTES).enumerate() {
        let more = idx + 1 < total_chunks;
        let flags = if more { FLAG_MORE_CHUNKS } else { 0 };
        let chunk_seq =
            u16::try_from(idx).map_err(|_| EncodeError::ValueOutOfRange("chunk_seq"))?;
        let payload_len =
            u16::try_from(slice.len()).map_err(|_| EncodeError::ValueOutOfRange("payload_len"))?;
        let mut pkt = Vec::with_capacity(HEADER_BYTES + slice.len());
        ChunkHeader {
            version: IPC_VERSION,
            session_gen,
            req_id,
            tag,
            flags,
            chunk_seq,
            payload_len,
        }
        .encode_into(&mut pkt);
        pkt.extend_from_slice(slice);
        packets.push(pkt);
    }
    Ok(packets)
}

/// Encodes `req` into one or more bounded `<= 32 KiB` chunk packets tagged
/// with `(session_gen, req_id)`.
pub fn encode_request_chunks(
    session_gen: u64,
    req_id: u64,
    req: &IpcRequest,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    let payload = encode_request_payload(req)?;
    split_into_chunks(session_gen, req_id, req.opcode() as u8, &payload)
}

/// Encodes `resp` into one or more bounded `<= 32 KiB` chunk packets tagged
/// with `(session_gen, req_id)`.
pub fn encode_response_chunks(
    session_gen: u64,
    req_id: u64,
    resp: &IpcResponse,
) -> Result<Vec<Vec<u8>>, EncodeError> {
    let payload = encode_response_payload(resp)?;
    split_into_chunks(session_gen, req_id, resp.status() as u8, &payload)
}

#[derive(Debug)]
struct InFlightStream {
    tag: u8,
    next_seq: u16,
    max_bytes: usize,
    buf: Vec<u8>,
}

/// Completed message popped out of [`StreamAssembler`].
#[derive(Debug)]
pub enum AssembledMessage {
    /// Complete request validated by the executor.
    Request(ReceivedRequest),
    /// Complete response validated by the parser (with optional verified
    /// channel fd strictly on `OkChannelFd`).
    Response(ReceivedResponse),
}

/// Stateful, bounded chunk reassembler and protocol validator (OQ-10 §4.1).
///
/// Validates `MSG_TRUNC`, `MSG_CTRUNC`, role-specific `SCM_RIGHTS` rules,
/// header fields, chunk order, concurrency cap ([`MAX_CONCURRENT_STREAMS`]),
/// per-opcode assembled size bounds, and strict payload decoding before
/// returning any message. Any rejected [`RawPacket`] is dropped immediately,
/// closing every received file descriptor.
#[derive(Debug)]
pub struct StreamAssembler {
    role: PeerRole,
    in_flight: BTreeMap<(u64, u64), InFlightStream>,
}

impl StreamAssembler {
    /// Creates an empty reassembler for `role`.
    pub fn new(role: PeerRole) -> Self {
        Self {
            role,
            in_flight: BTreeMap::new(),
        }
    }

    /// Number of currently active multi-chunk streams (`<= MAX_CONCURRENT_STREAMS`).
    pub fn active_streams(&self) -> usize {
        self.in_flight.len()
    }

    /// Total payload bytes currently buffered across all active streams.
    pub fn buffered_bytes(&self) -> usize {
        self.in_flight.values().map(|s| s.buf.len()).sum()
    }

    /// Drops any buffered incomplete streams belonging to sessions older than
    /// `min_session_gen`.
    pub fn drop_sessions_before(&mut self, min_session_gen: u64) {
        self.in_flight
            .retain(|&(session_gen, _), _| session_gen >= min_session_gen);
    }

    /// Validates and ingests one raw packet from `SOCK_SEQPACKET`.
    ///
    /// Returns:
    /// - `Ok(None)` when a valid intermediate chunk (`MORE_CHUNKS`) was buffered;
    /// - `Ok(Some(msg))` when a complete message finished validation and decoding;
    /// - `Err(violation)` on any protocol violation (dropping `packet` and
    ///   closing every received file descriptor immediately).
    pub fn push(
        &mut self,
        mut packet: RawPacket,
    ) -> Result<Option<AssembledMessage>, ProtocolViolation> {
        if packet.truncated {
            return Err(ProtocolViolation::MessageTruncated);
        }
        if packet.cmsg_truncated {
            return Err(ProtocolViolation::ControlMessageTruncated);
        }

        let header = ChunkHeader::decode(&packet.bytes)?;
        if header.version != IPC_VERSION {
            return Err(ProtocolViolation::UnsupportedVersion(header.version));
        }
        if (header.flags & !FLAG_MORE_CHUNKS) != 0 {
            return Err(ProtocolViolation::UnknownFlags(header.flags));
        }
        let payload_len = usize::from(header.payload_len);
        if payload_len > MAX_CHUNK_PAYLOAD_BYTES {
            return Err(ProtocolViolation::ChunkPayloadTooLarge(header.payload_len));
        }
        let actual_len = packet.bytes.len() - HEADER_BYTES;
        if actual_len != payload_len {
            return Err(ProtocolViolation::PayloadLengthMismatch {
                header_len: payload_len,
                actual_len,
            });
        }

        let (allows_chunking, max_bytes, expects_channel_fd) = match self.role {
            PeerRole::Executor => {
                let op = RequestOpcode::from_u8(header.tag)
                    .ok_or(ProtocolViolation::UnknownTag(header.tag))?;
                (op.allows_chunking(), op.max_payload_bytes(), false)
            }
            PeerRole::Parser => {
                let st = ResponseStatus::from_u8(header.tag)
                    .ok_or(ProtocolViolation::UnknownTag(header.tag))?;
                let expects_fd = st == ResponseStatus::OkChannelFd
                    && header.chunk_seq == 0
                    && !header.has_more_chunks();
                (st.allows_chunking(), st.max_payload_bytes(), expects_fd)
            }
        };

        // Strict ancillary-data & descriptor-ownership validation BEFORE any
        // buffering or dispatch; returning Err drops `packet` and closes all fds.
        let channel_fd = if expects_channel_fd {
            if packet.control_message_count != 1
                || packet.non_rights_cmsgs != 0
                || packet.fds.len() != 1
            {
                return Err(ProtocolViolation::InvalidChannelHandoffAncillary);
            }
            packet.fds.pop()
        } else {
            if packet.raw_controllen != 0
                || packet.control_message_count != 0
                || packet.non_rights_cmsgs != 0
                || !packet.fds.is_empty()
            {
                return Err(ProtocolViolation::UnexpectedAncillaryData);
            }
            None
        };

        let more = header.has_more_chunks();
        if !allows_chunking && (more || header.chunk_seq != 0) {
            return Err(ProtocolViolation::UnexpectedChunking(header.tag));
        }

        let key = (header.session_gen, header.req_id);
        let payload = &packet.bytes[HEADER_BYTES..];
        let max_chunks = max_bytes.div_ceil(MAX_CHUNK_PAYLOAD_BYTES).max(1);

        let assembled = if header.chunk_seq == 0 {
            if self.in_flight.contains_key(&key) {
                return Err(ProtocolViolation::DuplicateStream {
                    session_gen: header.session_gen,
                    req_id: header.req_id,
                });
            }
            if payload.len() > max_bytes || (more && payload.len() == max_bytes) {
                return Err(ProtocolViolation::AssembledPayloadTooLarge { limit: max_bytes });
            }
            if !more {
                payload.to_vec()
            } else {
                if payload.is_empty() {
                    return Err(ProtocolViolation::MalformedPayload(
                        "empty chunk with MORE_CHUNKS",
                    ));
                }
                if max_chunks < 2 {
                    return Err(ProtocolViolation::ChunkCountExceeded { max_chunks });
                }
                if self.in_flight.len() >= MAX_CONCURRENT_STREAMS {
                    return Err(ProtocolViolation::TooManyConcurrentStreams);
                }
                self.in_flight.insert(
                    key,
                    InFlightStream {
                        tag: header.tag,
                        next_seq: 1,
                        max_bytes,
                        buf: payload.to_vec(),
                    },
                );
                return Ok(None);
            }
        } else {
            let Some(stream) = self.in_flight.get_mut(&key) else {
                return Err(ProtocolViolation::OutOfOrderChunk {
                    expected: 0,
                    got: header.chunk_seq,
                });
            };
            if stream.tag != header.tag {
                let expected = stream.tag;
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::MismatchedChunkTag {
                    expected,
                    got: header.tag,
                });
            }
            if stream.next_seq != header.chunk_seq {
                let expected = stream.next_seq;
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::OutOfOrderChunk {
                    expected,
                    got: header.chunk_seq,
                });
            }
            if payload.is_empty() {
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::MalformedPayload(
                    "empty continuation chunk",
                ));
            }
            let Some(new_len) = stream.buf.len().checked_add(payload.len()) else {
                let limit = stream.max_bytes;
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::AssembledPayloadTooLarge { limit });
            };
            if new_len > stream.max_bytes || (more && new_len == stream.max_bytes) {
                let limit = stream.max_bytes;
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::AssembledPayloadTooLarge { limit });
            }
            if more && usize::from(header.chunk_seq).saturating_add(1) >= max_chunks {
                self.in_flight.remove(&key);
                return Err(ProtocolViolation::ChunkCountExceeded { max_chunks });
            }
            stream.buf.extend_from_slice(payload);
            stream.next_seq = stream
                .next_seq
                .checked_add(1)
                .ok_or(ProtocolViolation::ChunkCountExceeded { max_chunks })?;
            if more {
                return Ok(None);
            }
            match self.in_flight.remove(&key) {
                Some(finished) => finished.buf,
                None => {
                    return Err(ProtocolViolation::MalformedPayload(
                        "in-flight stream vanished",
                    ));
                }
            }
        };

        match self.role {
            PeerRole::Executor => {
                let op = RequestOpcode::from_u8(header.tag)
                    .ok_or(ProtocolViolation::UnknownTag(header.tag))?;
                let request = decode_request_payload(op, &assembled)?;
                Ok(Some(AssembledMessage::Request(ReceivedRequest {
                    session_gen: header.session_gen,
                    req_id: header.req_id,
                    request,
                })))
            }
            PeerRole::Parser => {
                let st = ResponseStatus::from_u8(header.tag)
                    .ok_or(ProtocolViolation::UnknownTag(header.tag))?;
                let response = decode_response_payload(st, &assembled)?;
                Ok(Some(AssembledMessage::Response(ReceivedResponse {
                    session_gen: header.session_gen,
                    req_id: header.req_id,
                    response,
                    channel_fd,
                })))
            }
        }
    }
}

/// Outcome of attempting to flush queued packets from an [`IpcOutbox`] onto a
/// (typically non-blocking) `SOCK_SEQPACKET` socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushOutcome {
    /// Every queued packet was accepted by the kernel socket buffer.
    Drained,
    /// Socket send buffer is full (`EAGAIN`/`EWOULDBLOCK`); the unsent chunk
    /// remains at the head of the outbox so a later [`IpcOutbox::flush`] call
    /// after writable readiness resumes at the exact next chunk sequence.
    WouldBlock,
}

#[derive(Debug)]
struct PendingPacket {
    bytes: Vec<u8>,
    fd: Option<OwnedFd>,
}

/// Resumable, cursor-preserving chunk writer for non-blocking `SOCK_SEQPACKET`
/// IPC sockets (OQ-10 §4.1, #77/#78).
///
/// Multi-chunk requests and responses are split once on enqueue and drained in
/// order by [`IpcOutbox::flush`]. When the kernel reports `EAGAIN`/`EWOULDBLOCK`
/// mid-stream, the unsent chunk stays at the head of the queue (together with
/// any `OkChannelFd` `OwnedFd` on chunk 0) so retrying on writable readiness
/// continues from the exact unsent `chunk_seq` rather than restarting at `0`.
#[derive(Debug, Default)]
pub struct IpcOutbox {
    queue: VecDeque<PendingPacket>,
}

impl IpcOutbox {
    /// Creates an empty outbox.
    pub fn new() -> Self {
        Self::default()
    }

    /// `true` when no chunks remain to be sent.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Number of queued `SOCK_SEQPACKET` packets not yet accepted by the kernel.
    pub fn pending_packets(&self) -> usize {
        self.queue.len()
    }

    /// Encodes and queues a complete typed request (`<= 64 KiB`, `1..=2` chunks,
    /// zero attached descriptors).
    pub fn push_request(
        &mut self,
        session_gen: u64,
        req_id: u64,
        req: &IpcRequest,
    ) -> Result<(), EncodeError> {
        let chunks = encode_request_chunks(session_gen, req_id, req)?;
        for bytes in chunks {
            self.queue.push_back(PendingPacket { bytes, fd: None });
        }
        Ok(())
    }

    /// Encodes and queues a complete typed response. `channel_fd` MUST be
    /// `Some` if and only if `resp == IpcResponse::OkChannelFd`, and is attached
    /// strictly to chunk `0` and closed as soon as chunk `0` is accepted by the
    /// kernel (or if the outbox is dropped).
    pub fn push_response(
        &mut self,
        session_gen: u64,
        req_id: u64,
        resp: &IpcResponse,
        mut channel_fd: Option<OwnedFd>,
    ) -> Result<(), EncodeError> {
        let is_handoff = matches!(resp, IpcResponse::OkChannelFd);
        if is_handoff != channel_fd.is_some() {
            return Err(EncodeError::InvalidDescriptorAttachment);
        }
        let chunks = encode_response_chunks(session_gen, req_id, resp)?;
        for (idx, bytes) in chunks.into_iter().enumerate() {
            let fd = if idx == 0 { channel_fd.take() } else { None };
            self.queue.push_back(PendingPacket { bytes, fd });
        }
        Ok(())
    }

    /// Flushes queued chunks onto `sock` until the queue drains or the socket
    /// reports `EAGAIN`/`EWOULDBLOCK`.
    pub fn flush(&mut self, sock: BorrowedFd<'_>) -> Result<FlushOutcome, Errno> {
        while let Some(front) = self.queue.front() {
            match send_packet(sock, &front.bytes, front.fd.as_ref().map(AsFd::as_fd)) {
                Ok(()) => {
                    let _ = self.queue.pop_front();
                }
                Err(Errno::EAGAIN) => return Ok(FlushOutcome::WouldBlock),
                Err(err) => return Err(err),
            }
        }
        Ok(FlushOutcome::Drained)
    }
}

/// Sends a complete typed request over a **blocking** `SOCK_SEQPACKET` socket
/// as one or more `<= 32 KiB` chunks (never attaches file descriptors).
///
/// Non-blocking callers must use [`IpcOutbox`] so `EAGAIN` mid-stream preserves
/// the chunk cursor instead of restarting at `chunk_seq == 0`.
pub fn send_request(
    sock: BorrowedFd<'_>,
    session_gen: u64,
    req_id: u64,
    req: &IpcRequest,
) -> Result<(), TransportError> {
    let chunks = encode_request_chunks(session_gen, req_id, req)?;
    for chunk in chunks {
        send_packet(sock, &chunk, None)?;
    }
    Ok(())
}

/// Sends a complete typed response over a **blocking** `SOCK_SEQPACKET` socket
/// as one or more `<= 32 KiB` chunks. `channel_fd` MUST be `Some` if and only
/// if `resp == IpcResponse::OkChannelFd`.
///
/// Non-blocking callers must use [`IpcOutbox`] so `EAGAIN` mid-stream preserves
/// the chunk cursor instead of restarting at `chunk_seq == 0`.
pub fn send_response(
    sock: BorrowedFd<'_>,
    session_gen: u64,
    req_id: u64,
    resp: &IpcResponse,
    channel_fd: Option<BorrowedFd<'_>>,
) -> Result<(), TransportError> {
    let is_handoff = matches!(resp, IpcResponse::OkChannelFd);
    if is_handoff != channel_fd.is_some() {
        return Err(TransportError::Encode(
            EncodeError::InvalidDescriptorAttachment,
        ));
    }
    let chunks = encode_response_chunks(session_gen, req_id, resp)?;
    for (idx, chunk) in chunks.iter().enumerate() {
        let fd = if idx == 0 { channel_fd } else { None };
        send_packet(sock, chunk, fd)?;
    }
    Ok(())
}

/// Receives and validates chunks until one complete [`ReceivedRequest`] is
/// assembled, returning `Ok(None)` on clean peer EOF.
pub fn recv_request(
    sock: BorrowedFd<'_>,
    assembler: &mut StreamAssembler,
) -> Result<Option<ReceivedRequest>, TransportError> {
    loop {
        let Some(pkt) = recv_packet(sock, MAX_PACKET_BYTES)? else {
            return Ok(None);
        };
        if let Some(AssembledMessage::Request(req)) = assembler.push(pkt)? {
            return Ok(Some(req));
        }
    }
}

/// Receives and validates chunks until one complete [`ReceivedResponse`] is
/// assembled, returning `Ok(None)` on clean peer EOF.
pub fn recv_response(
    sock: BorrowedFd<'_>,
    assembler: &mut StreamAssembler,
) -> Result<Option<ReceivedResponse>, TransportError> {
    loop {
        let Some(pkt) = recv_packet(sock, MAX_PACKET_BYTES)? else {
            return Ok(None);
        };
        if let Some(AssembledMessage::Response(resp)) = assembler.push(pkt)? {
            return Ok(Some(resp));
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{Read, Write};
    use std::os::fd::AsFd;

    use nix::fcntl::{FcntlArg, OFlag, fcntl};
    use nix::unistd::pipe;
    use proptest::prelude::*;

    use super::*;
    use crate::audit::project_method;
    use crate::kernel::ipc::{send_packet_fds, seqpacket_pair};

    fn nonblocking_pipe() -> (OwnedFd, OwnedFd) {
        let (r, w) = pipe().unwrap();
        let flags = OFlag::from_bits_truncate(fcntl(&r, FcntlArg::F_GETFL).unwrap());
        fcntl(&r, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();
        (r, w)
    }

    fn assert_pipe_open(read_end: &OwnedFd, context: &str) {
        let mut byte = [0u8; 1];
        assert_eq!(
            nix::unistd::read(read_end, &mut byte),
            Err(Errno::EAGAIN),
            "{context}: expected write end to remain open"
        );
    }

    fn assert_pipe_closed(read_end: &OwnedFd, context: &str) {
        let mut byte = [0u8; 1];
        assert_eq!(
            nix::unistd::read(read_end, &mut byte),
            Ok(0),
            "{context}: write end remained open (received descriptor leaked)"
        );
    }

    #[test]
    fn ipc_outbox_resumes_multi_chunk_streams_across_nonblocking_backpressure() {
        let (parser_sock, exec_sock) = seqpacket_pair(true).unwrap();

        // Build a large (~800 KiB, ~25 chunks) OkFsInfo response that exceeds
        // Linux's default AF_UNIX socket buffer so a non-blocking sender MUST
        // encounter EAGAIN mid-stream before the slow reader drains.
        let big_fs: Vec<FsInfoDto> = (0..6_500)
            .map(|i| FsInfoDto {
                name: format!("fs-{i}"),
                mountpoint: format!("/mnt/backpressure/volume_{i:04}/{}", "x".repeat(80)),
                fs_type: "ext4".to_owned(),
                used_bytes: Some(i * 4096),
                total_bytes: Some(i * 8192),
            })
            .collect();
        let big_resp = IpcResponse::OkFsInfo(big_fs);
        let expected_chunks = encode_response_chunks(9, 1, &big_resp).unwrap().len();
        assert!(
            expected_chunks >= 10,
            "need many chunks to fill socket buffer"
        );

        let mut exec_outbox = IpcOutbox::new();
        exec_outbox.push_response(9, 1, &big_resp, None).unwrap();
        assert_eq!(exec_outbox.pending_packets(), expected_chunks);

        // First flush on non-blocking socket with an un-draining receiver must
        // queue some prefix of chunks and stop mid-stream with WouldBlock.
        let first = exec_outbox.flush(exec_sock.as_fd()).unwrap();
        assert_eq!(
            first,
            FlushOutcome::WouldBlock,
            "large multi-chunk response must trigger real EAGAIN backpressure"
        );
        assert!(
            exec_outbox.pending_packets() > 0 && exec_outbox.pending_packets() < expected_chunks,
            "some chunks must have queued before WouldBlock (remaining={}, total={expected_chunks})",
            exec_outbox.pending_packets()
        );

        // Interleave slow single-packet reads with outbox flushes; the stream
        // must complete exactly once with zero duplicate/restarted chunk 0.
        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);
        let mut assembled = Vec::new();
        let mut would_block_hits = 1usize;
        for _ in 0..(expected_chunks * 4) {
            if !exec_outbox.is_empty()
                && exec_outbox.flush(exec_sock.as_fd()).unwrap() == FlushOutcome::WouldBlock
            {
                would_block_hits += 1;
            }
            match recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES) {
                Ok(Some(pkt)) => {
                    if let Some(AssembledMessage::Response(resp)) = parser_asm.push(pkt).unwrap() {
                        assembled.push(resp);
                    }
                }
                Err(Errno::EAGAIN) => {}
                other => panic!("unexpected recv_packet result: {other:?}"),
            }
            if exec_outbox.is_empty() && !assembled.is_empty() {
                break;
            }
        }
        assert!(exec_outbox.is_empty());
        assert!(would_block_hits >= 1);
        assert_eq!(assembled.len(), 1, "response must assemble exactly once");
        assert_eq!(assembled[0].session_gen, 9);
        assert_eq!(assembled[0].req_id, 1);
        assert_eq!(assembled[0].response, big_resp);
        assert_eq!(parser_asm.active_streams(), 0);

        // Connection remains completely usable in both directions, including
        // multi-chunk request + OkChannelFd SCM_RIGHTS through IpcOutbox.
        let mut parser_outbox = IpcOutbox::new();
        let big_list = IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(
            (0..600)
                .map(|i| format!("/vol/sub_{i:04}/{}", "p".repeat(50)))
                .collect(),
        ));
        parser_outbox.push_request(9, 2, &big_list).unwrap();
        assert!(parser_outbox.pending_packets() >= 2);
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
        let mut req_got = None;
        while !parser_outbox.is_empty() || req_got.is_none() {
            let _ = parser_outbox.flush(parser_sock.as_fd()).unwrap();
            match recv_packet(exec_sock.as_fd(), MAX_PACKET_BYTES) {
                Ok(Some(pkt)) => {
                    if let Some(AssembledMessage::Request(req)) = exec_asm.push(pkt).unwrap() {
                        req_got = Some(req);
                    }
                }
                Err(Errno::EAGAIN) => {}
                other => panic!("unexpected exec recv: {other:?}"),
            }
        }
        assert_eq!(req_got.unwrap().request, big_list);

        // OkChannelFd via IpcOutbox hands off and drops its OwnedFd once flushed.
        let (r_end, w_end) = nonblocking_pipe();
        exec_outbox
            .push_response(9, 3, &IpcResponse::OkChannelFd, Some(w_end))
            .unwrap();
        assert_eq!(
            exec_outbox.flush(exec_sock.as_fd()).unwrap(),
            FlushOutcome::Drained
        );
        let pkt = recv_packet(parser_sock.as_fd(), MAX_PACKET_BYTES)
            .unwrap()
            .unwrap();
        let Some(AssembledMessage::Response(handoff)) = parser_asm.push(pkt).unwrap() else {
            panic!("expected OkChannelFd");
        };
        assert_eq!(handoff.response, IpcResponse::OkChannelFd);
        assert_pipe_open(&r_end, "handoff fd owned by parser");
        drop(handoff);
        assert_pipe_closed(&r_end, "handoff fd closed after parser drop");

        // Mismatched fd attachment rejected cleanly by IpcOutbox::push_response.
        let (_, w_extra) = nonblocking_pipe();
        assert_eq!(
            exec_outbox.push_response(9, 4, &IpcResponse::OkEmpty, Some(w_extra)),
            Err(EncodeError::InvalidDescriptorAttachment)
        );
        assert_eq!(
            exec_outbox.push_response(9, 4, &IpcResponse::OkChannelFd, None),
            Err(EncodeError::InvalidDescriptorAttachment)
        );
    }

    fn raw_pkt(bytes: Vec<u8>) -> RawPacket {
        RawPacket {
            bytes,
            fds: Vec::new(),
            truncated: false,
            cmsg_truncated: false,
            control_message_count: 0,
            non_rights_cmsgs: 0,
            raw_controllen: 0,
        }
    }

    #[test]
    fn all_request_variants_round_trip_and_preserve_freeze_list_distinctions() {
        let projected =
            ProjectedMethod::from_method_field(&project_method(&"x".repeat(80))).unwrap();
        let long_list: Vec<String> = (0..400).map(|i| format!("/m/{i}")).collect();
        let cases = vec![
            IpcRequest::Ping,
            IpcRequest::Info,
            IpcRequest::Sync { id: i64::MIN },
            IpcRequest::SyncDelimited { id: i64::MAX },
            IpcRequest::FsfreezeStatus,
            IpcRequest::FsfreezeFreeze,
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted),
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![])),
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![
                "/".to_owned(),
                "/data".to_owned(),
            ])),
            // > 256 short mount names inside 64 KiB (§4.1, §6 check 6b).
            IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(long_list)),
            IpcRequest::FsfreezeThaw,
            IpcRequest::GetOsInfo,
            IpcRequest::NetworkGetInterfaces,
            IpcRequest::GetFsInfo,
            IpcRequest::Fstrim { minimum: 1_048_576 },
            IpcRequest::Shutdown {
                mode: ShutdownMode::Powerdown,
            },
            IpcRequest::Shutdown {
                mode: ShutdownMode::Halt,
            },
            IpcRequest::Shutdown {
                mode: ShutdownMode::Reboot,
            },
            IpcRequest::SuspendRam,
            IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::Oversized,
                frame_len: 70_000,
                id: None,
                method: None,
            }),
            IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::UnknownMethod,
                frame_len: 120,
                id: Some(9),
                method: Some(ProjectedMethod::Full("guest-exec".to_owned())),
            }),
            IpcRequest::ReportParseRejection(ParseRejection {
                kind: ParseRejectionKind::UnknownMethod,
                frame_len: 140,
                id: Some(-1),
                method: Some(projected),
            }),
            IpcRequest::RequestChannelReopen,
        ];

        let (parser_sock, exec_sock) = seqpacket_pair(false).unwrap();
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
        for (idx, req) in cases.into_iter().enumerate() {
            let session_gen = 7 + (idx as u64 / 3);
            let req_id = 100 + idx as u64;
            send_request(parser_sock.as_fd(), session_gen, req_id, &req).unwrap();
            let got = recv_request(exec_sock.as_fd(), &mut exec_asm)
                .unwrap()
                .unwrap();
            assert_eq!(got.session_gen, session_gen);
            assert_eq!(got.req_id, req_id);
            assert_eq!(got.request, req);
        }

        // Verify omitted vs empty vs populated encodings are distinct bytes.
        let omitted = encode_request_chunks(
            1,
            1,
            &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Omitted),
        )
        .unwrap();
        let empty = encode_request_chunks(
            1,
            1,
            &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![])),
        )
        .unwrap();
        let populated = encode_request_chunks(
            1,
            1,
            &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec!["/data".into()])),
        )
        .unwrap();
        assert_eq!(&omitted[0][HEADER_BYTES..], &[0]);
        assert_eq!(&empty[0][HEADER_BYTES..], &[1, 0, 0]);
        assert_ne!(omitted, empty);
        assert_ne!(empty, populated);
    }

    #[test]
    fn large_multi_chunk_requests_and_responses_round_trip_within_bounds() {
        let (parser_sock, exec_sock) = seqpacket_pair(false).unwrap();
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);

        // 1. Multi-chunk FsfreezeFreezeList (> 32 KiB, <= 64 KiB, > 256 entries).
        let big_list: Vec<String> = (0..500)
            .map(|i| format!("/mount/point/{:0>70}_{i}", "x"))
            .collect();
        let req = IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(big_list));
        let chunks = encode_request_chunks(1, 1, &req).unwrap();
        assert_eq!(chunks.len(), 2, "must span 2 chunks inside 64 KiB");
        send_request(parser_sock.as_fd(), 1, 1, &req).unwrap();
        let got = recv_request(exec_sock.as_fd(), &mut exec_asm)
            .unwrap()
            .unwrap();
        assert_eq!(got.request, req);

        // 2. Multi-chunk GetOsInfo with a 48 KiB PRETTY_NAME (§6 check 6c, <= 128 KiB).
        let big_os = IpcResponse::OkOsInfo(Box::new(OsInfo {
            kernel_release: Some("6.8.0-qeminga".to_owned()),
            kernel_version: Some("#1 SMP".to_owned()),
            machine: Some("x86_64".to_owned()),
            pretty_name: Some("P".repeat(48 * 1024)),
            ..OsInfo::default()
        }));
        let os_chunks = encode_response_chunks(2, 10, &big_os).unwrap();
        assert_eq!(os_chunks.len(), 2, "48 KiB osinfo must span 2 chunks");
        send_response(exec_sock.as_fd(), 2, 10, &big_os, None).unwrap();
        let got_os = recv_response(parser_sock.as_fd(), &mut parser_asm)
            .unwrap()
            .unwrap();
        assert_eq!(got_os.response, big_os);
        assert!(got_os.channel_fd.is_none());

        // 3. Multi-chunk NetworkGetInterfaces (> 32 KiB, <= 256 KiB).
        let ifaces: Vec<InterfaceDto> = (0..700)
            .map(|i| InterfaceDto {
                name: format!("eth{i}"),
                hardware_address: Some("52:54:00:12:34:56".to_owned()),
                ip_addresses: vec![IpAddressDto {
                    ip_address: format!("192.0.2.{}", i % 254 + 1),
                    kind: IpAddressKind::Ipv4,
                    prefix: 24,
                }],
            })
            .collect();
        let iface_resp = IpcResponse::OkInterfaces(ifaces);
        let iface_chunks = encode_response_chunks(2, 11, &iface_resp).unwrap();
        assert!(iface_chunks.len() >= 2 && iface_chunks.len() <= 8);
        send_response(exec_sock.as_fd(), 2, 11, &iface_resp, None).unwrap();
        assert_eq!(
            recv_response(parser_sock.as_fd(), &mut parser_asm)
                .unwrap()
                .unwrap()
                .response,
            iface_resp
        );

        // 4. Multi-chunk GetFsInfo (> 256 KiB, <= 1 MiB, §6 check 6a).
        let fs_entries: Vec<FsInfoDto> = (0..4_500)
            .map(|i| FsInfoDto {
                name: format!("fs-{}", i + 1),
                mountpoint: format!("/mnt/volume/{:0>40}_{i}", "v"),
                fs_type: "ext4".to_owned(),
                used_bytes: Some(4096 * (i as u64)),
                total_bytes: Some(8192 * (i as u64 + 1)),
            })
            .collect();
        let fs_resp = IpcResponse::OkFsInfo(fs_entries);
        let fs_chunks = encode_response_chunks(2, 12, &fs_resp).unwrap();
        assert!(
            fs_chunks.len() > 8 && fs_chunks.len() <= 32,
            "expected > 256 KiB (9..=32 chunks), got {}",
            fs_chunks.len()
        );
        // Send chunks on a helper thread because > 256 KiB exceeds default socket buffer.
        let fs_resp_send = fs_resp.clone();
        let exec_dup = exec_sock.try_clone().unwrap();
        let sender = std::thread::spawn(move || {
            send_response(exec_dup.as_fd(), 2, 12, &fs_resp_send, None).unwrap();
        });
        let got_fs = recv_response(parser_sock.as_fd(), &mut parser_asm)
            .unwrap()
            .unwrap();
        sender.join().unwrap();
        assert_eq!(got_fs.response, fs_resp);

        // 5. Multi-chunk OkFstrim with mixed outcomes + FstrimReplyTooLarge error.
        let trim_entries: Vec<TrimPathDto> = (0..2_500)
            .map(|i| TrimPathDto {
                path: format!("/data/vol_{i:04}"),
                outcome: match i % 4 {
                    0 => TrimPathOutcome::Trimmed {
                        trimmed: 4096,
                        minimum: 0,
                    },
                    1 => TrimPathOutcome::OpenPermissionDenied,
                    2 => TrimPathOutcome::TargetUnreachable,
                    _ => TrimPathOutcome::IoctlErrno(Errno::EOPNOTSUPP as i32),
                },
            })
            .collect();
        let trim_resp = IpcResponse::OkFstrim(trim_entries);
        let trim_chunks = encode_response_chunks(2, 13, &trim_resp).unwrap();
        assert!(trim_chunks.len() >= 2);
        let trim_send = trim_resp.clone();
        let exec_dup2 = exec_sock.try_clone().unwrap();
        let sender2 = std::thread::spawn(move || {
            send_response(exec_dup2.as_fd(), 2, 13, &trim_send, None).unwrap();
        });
        let got_trim = recv_response(parser_sock.as_fd(), &mut parser_asm)
            .unwrap()
            .unwrap();
        sender2.join().unwrap();
        assert_eq!(got_trim.response, trim_resp);

        let oversize = IpcResponse::Err(IpcErrorCode::FstrimReplyTooLarge {
            trimmed_targets: 210,
            failed_targets: 90,
            limit_bytes: MAX_FSTRIM_IPC_BYTES as u64,
        });
        send_response(exec_sock.as_fd(), 2, 14, &oversize, None).unwrap();
        let got_ov = recv_response(parser_sock.as_fd(), &mut parser_asm)
            .unwrap()
            .unwrap();
        assert_eq!(got_ov.response, oversize);
        if let IpcResponse::Err(code) = got_ov.response {
            assert_eq!(
                code.to_proto_error().to_string(),
                "fstrim trimmed 210 target(s) (90 failed), but reply exceeds the 1 MiB response bound"
            );
        }
    }

    #[test]
    fn channel_handoff_validates_exact_single_fd_and_closes_rejected_fds() {
        let (parser_sock, exec_sock) = seqpacket_pair(false).unwrap();
        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // 1. Valid OkChannelFd with 1 fd succeeds and transfers a working CLOEXEC fd.
        let (r_end, w_end) = pipe().unwrap();
        send_response(
            exec_sock.as_fd(),
            5,
            1,
            &IpcResponse::OkChannelFd,
            Some(r_end.as_fd()),
        )
        .unwrap();
        drop(r_end);
        let got = recv_response(parser_sock.as_fd(), &mut parser_asm)
            .unwrap()
            .unwrap();
        assert_eq!(got.response, IpcResponse::OkChannelFd);
        let fd = got.channel_fd.expect("channel fd");
        let mut w = std::fs::File::from(w_end);
        w.write_all(b"ok").unwrap();
        drop(w);
        let mut r = std::fs::File::from(fd);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"ok");
        drop(r);

        // 2. OkChannelFd with 0 fds is rejected.
        let zero_fd_pkt = encode_response_chunks(5, 2, &IpcResponse::OkChannelFd).unwrap();
        send_packet(exec_sock.as_fd(), &zero_fd_pkt[0], None).unwrap();
        let err = recv_response(parser_sock.as_fd(), &mut parser_asm).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Protocol(ProtocolViolation::InvalidChannelHandoffAncillary)
        ));

        // 3. OkChannelFd with 2 fds is rejected and closes both received fds.
        let (r1, w1) = nonblocking_pipe();
        let (r2, w2) = nonblocking_pipe();
        send_packet_fds(
            exec_sock.as_fd(),
            &zero_fd_pkt[0],
            &[w1.as_fd(), w2.as_fd()],
        )
        .unwrap();
        drop((w1, w2));
        assert_pipe_open(&r1, "2-fd OkChannelFd queued");
        assert_pipe_open(&r2, "2-fd OkChannelFd queued");
        let err = recv_response(parser_sock.as_fd(), &mut parser_asm).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Protocol(ProtocolViolation::InvalidChannelHandoffAncillary)
        ));
        assert_pipe_closed(&r1, "rejected 2-fd OkChannelFd fd 1");
        assert_pipe_closed(&r2, "rejected 2-fd OkChannelFd fd 2");

        // 4. OkChannelFd with 4 fds triggers MSG_CTRUNC and closes every fd.
        let (r1, w1) = nonblocking_pipe();
        let (r2, w2) = nonblocking_pipe();
        let (r3, w3) = nonblocking_pipe();
        let (r4, w4) = nonblocking_pipe();
        send_packet_fds(
            exec_sock.as_fd(),
            &zero_fd_pkt[0],
            &[w1.as_fd(), w2.as_fd(), w3.as_fd(), w4.as_fd()],
        )
        .unwrap();
        drop((w1, w2, w3, w4));
        let err = recv_response(parser_sock.as_fd(), &mut parser_asm).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Protocol(ProtocolViolation::ControlMessageTruncated)
        ));
        for (idx, r) in [&r1, &r2, &r3, &r4].into_iter().enumerate() {
            assert_pipe_closed(r, &format!("rejected MSG_CTRUNC OkChannelFd fd {idx}"));
        }

        // 5. Non-handoff response (OkEmpty) carrying an unexpected fd is rejected
        //    and closes the received fd.
        let (r1, w1) = nonblocking_pipe();
        let ok_pkt = encode_response_chunks(5, 3, &IpcResponse::OkEmpty).unwrap();
        send_packet(exec_sock.as_fd(), &ok_pkt[0], Some(w1.as_fd())).unwrap();
        drop(w1);
        assert_pipe_open(&r1, "unexpected non-handoff fd queued");
        let err = recv_response(parser_sock.as_fd(), &mut parser_asm).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Protocol(ProtocolViolation::UnexpectedAncillaryData)
        ));
        assert_pipe_closed(&r1, "rejected unexpected non-handoff fd");

        // 6. Parser -> executor packet carrying ANY fd is rejected and closes it.
        let (r1, w1) = nonblocking_pipe();
        let ping_pkt = encode_request_chunks(5, 4, &IpcRequest::Ping).unwrap();
        send_packet(parser_sock.as_fd(), &ping_pkt[0], Some(w1.as_fd())).unwrap();
        drop(w1);
        assert_pipe_open(&r1, "parser -> executor SCM_RIGHTS queued");
        let err = recv_request(exec_sock.as_fd(), &mut exec_asm).unwrap_err();
        assert!(matches!(
            err,
            TransportError::Protocol(ProtocolViolation::UnexpectedAncillaryData)
        ));
        assert_pipe_closed(&r1, "rejected parser -> executor SCM_RIGHTS fd");

        // 7. send_response rejects mismatched descriptor attachment on the sender side too.
        let (p1, _) = pipe().unwrap();
        assert!(matches!(
            send_response(
                exec_sock.as_fd(),
                5,
                5,
                &IpcResponse::OkEmpty,
                Some(p1.as_fd())
            ),
            Err(TransportError::Encode(
                EncodeError::InvalidDescriptorAttachment
            ))
        ));
        assert!(matches!(
            send_response(exec_sock.as_fd(), 5, 6, &IpcResponse::OkChannelFd, None),
            Err(TransportError::Encode(
                EncodeError::InvalidDescriptorAttachment
            ))
        ));
    }

    #[test]
    fn assembler_rejects_truncation_bad_headers_bad_order_concurrency_and_size_overflow() {
        let mut exec_asm = StreamAssembler::new(PeerRole::Executor);

        // MSG_TRUNC.
        let mut trunc = raw_pkt(
            encode_request_chunks(1, 1, &IpcRequest::Ping)
                .unwrap()
                .remove(0),
        );
        trunc.truncated = true;
        assert_eq!(
            exec_asm.push(trunc).unwrap_err(),
            ProtocolViolation::MessageTruncated
        );

        // Packet too short.
        assert_eq!(
            exec_asm.push(raw_pkt(vec![1; 10])).unwrap_err(),
            ProtocolViolation::PacketTooShort { len: 10 }
        );

        // Wrong version.
        let mut bad_ver = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);
        bad_ver[0] = 2;
        assert_eq!(
            exec_asm.push(raw_pkt(bad_ver)).unwrap_err(),
            ProtocolViolation::UnsupportedVersion(2)
        );

        // Unknown flags bit.
        let mut bad_flag = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);
        bad_flag[18] = 0x02;
        assert_eq!(
            exec_asm.push(raw_pkt(bad_flag)).unwrap_err(),
            ProtocolViolation::UnknownFlags(0x02)
        );

        // Unknown opcode.
        let mut bad_op = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);
        bad_op[17] = 0xFF;
        assert_eq!(
            exec_asm.push(raw_pkt(bad_op)).unwrap_err(),
            ProtocolViolation::UnknownTag(0xFF)
        );

        // Payload length mismatch (trailing byte).
        let mut bad_len = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);
        bad_len.push(0);
        assert_eq!(
            exec_asm.push(raw_pkt(bad_len)).unwrap_err(),
            ProtocolViolation::PayloadLengthMismatch {
                header_len: 0,
                actual_len: 1,
            }
        );

        // Unexpected chunking on single-chunk opcode.
        let mut chunked_ping = encode_request_chunks(1, 1, &IpcRequest::Ping)
            .unwrap()
            .remove(0);
        chunked_ping[18] = FLAG_MORE_CHUNKS;
        assert_eq!(
            exec_asm.push(raw_pkt(chunked_ping)).unwrap_err(),
            ProtocolViolation::UnexpectedChunking(RequestOpcode::Ping as u8)
        );

        // Out-of-order chunk (seq 1 before seq 0).
        let mut pkt = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 1,
            req_id: 99,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: 0,
            chunk_seq: 1,
            payload_len: 1,
        }
        .encode_into(&mut pkt);
        pkt.push(0);
        assert_eq!(
            exec_asm.push(raw_pkt(pkt)).unwrap_err(),
            ProtocolViolation::OutOfOrderChunk {
                expected: 0,
                got: 1,
            }
        );

        // Mismatched tag on continuation chunk.
        let mut c0 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 1,
            req_id: 50,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 1,
        }
        .encode_into(&mut c0);
        c0.push(1);
        assert!(exec_asm.push(raw_pkt(c0)).unwrap().is_none());

        let mut c1_wrong_tag = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 1,
            req_id: 50,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: 0,
            chunk_seq: 2,
            payload_len: 1,
        }
        .encode_into(&mut c1_wrong_tag);
        c1_wrong_tag.push(0);
        assert_eq!(
            exec_asm.push(raw_pkt(c1_wrong_tag)).unwrap_err(),
            ProtocolViolation::OutOfOrderChunk {
                expected: 1,
                got: 2,
            }
        );

        // Concurrency cap: 8 concurrent streams accepted, 9th rejected without allocating.
        let mut exec_cap = StreamAssembler::new(PeerRole::Executor);
        for req_id in 0..MAX_CONCURRENT_STREAMS as u64 {
            let mut c0 = Vec::new();
            ChunkHeader {
                version: IPC_VERSION,
                session_gen: 1,
                req_id,
                tag: RequestOpcode::FsfreezeFreezeList as u8,
                flags: FLAG_MORE_CHUNKS,
                chunk_seq: 0,
                payload_len: 3,
            }
            .encode_into(&mut c0);
            c0.extend_from_slice(&[1, 0, 0]);
            assert!(exec_cap.push(raw_pkt(c0)).unwrap().is_none());
        }
        assert_eq!(exec_cap.active_streams(), MAX_CONCURRENT_STREAMS);
        let mut c9 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 1,
            req_id: 999,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 3,
        }
        .encode_into(&mut c9);
        c9.extend_from_slice(&[1, 0, 0]);
        assert_eq!(
            exec_cap.push(raw_pkt(c9)).unwrap_err(),
            ProtocolViolation::TooManyConcurrentStreams
        );
        assert_eq!(exec_cap.active_streams(), MAX_CONCURRENT_STREAMS);
        exec_cap.drop_sessions_before(2);
        assert_eq!(exec_cap.active_streams(), 0);

        // Cumulative assembled payload > 64 KiB for FsfreezeFreezeList rejected
        // immediately on chunk 1 when MORE_CHUNKS promises further bytes past 64 KiB.
        let mut exec_size = StreamAssembler::new(PeerRole::Executor);
        let mut c0 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 1,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: MAX_CHUNK_PAYLOAD_BYTES as u16,
        }
        .encode_into(&mut c0);
        c0.resize(HEADER_BYTES + MAX_CHUNK_PAYLOAD_BYTES, 0);
        assert!(exec_size.push(raw_pkt(c0)).unwrap().is_none());

        let mut c1_overflow = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 1,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 1,
            payload_len: MAX_CHUNK_PAYLOAD_BYTES as u16,
        }
        .encode_into(&mut c1_overflow);
        c1_overflow.resize(HEADER_BYTES + MAX_CHUNK_PAYLOAD_BYTES, 0);
        assert_eq!(
            exec_size.push(raw_pkt(c1_overflow)).unwrap_err(),
            ProtocolViolation::AssembledPayloadTooLarge {
                limit: MAX_REQUEST_PAYLOAD_BYTES,
            }
        );
        assert_eq!(exec_size.active_streams(), 0);

        // Exceeding per-tag max_chunks (2 for 64 KiB FsfreezeFreezeList) with
        // small chunks is rejected immediately rather than spinning chunk_seq.
        let mut small0 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 2,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 4,
        }
        .encode_into(&mut small0);
        small0.extend_from_slice(&[1, 1, 0, 0]);
        assert!(exec_size.push(raw_pkt(small0)).unwrap().is_none());

        let mut small1 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 2,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 1,
            payload_len: 4,
        }
        .encode_into(&mut small1);
        small1.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(
            exec_size.push(raw_pkt(small1)).unwrap_err(),
            ProtocolViolation::ChunkCountExceeded { max_chunks: 2 }
        );
        assert_eq!(exec_size.active_streams(), 0);

        // Empty chunk with MORE_CHUNKS or empty continuation chunk rejected.
        let mut empty_more = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 3,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 0,
        }
        .encode_into(&mut empty_more);
        assert_eq!(
            exec_size.push(raw_pkt(empty_more)).unwrap_err(),
            ProtocolViolation::MalformedPayload("empty chunk with MORE_CHUNKS")
        );

        let mut valid_start = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 4,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 3,
        }
        .encode_into(&mut valid_start);
        valid_start.extend_from_slice(&[1, 0, 0]);
        assert!(exec_size.push(raw_pkt(valid_start)).unwrap().is_none());

        let mut empty_cont = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 2,
            req_id: 4,
            tag: RequestOpcode::FsfreezeFreezeList as u8,
            flags: 0,
            chunk_seq: 1,
            payload_len: 0,
        }
        .encode_into(&mut empty_cont);
        assert_eq!(
            exec_size.push(raw_pkt(empty_cont)).unwrap_err(),
            ProtocolViolation::MalformedPayload("empty continuation chunk")
        );
        assert_eq!(exec_size.active_streams(), 0);

        // Mismatched tag on parser multi-chunk stream (OkOsInfo -> OkFsInfo).
        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);
        let mut p0 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 3,
            req_id: 7,
            tag: ResponseStatus::OkOsInfo as u8,
            flags: FLAG_MORE_CHUNKS,
            chunk_seq: 0,
            payload_len: 2,
        }
        .encode_into(&mut p0);
        p0.extend_from_slice(&[0, 0]);
        assert!(parser_asm.push(raw_pkt(p0)).unwrap().is_none());
        let mut p1 = Vec::new();
        ChunkHeader {
            version: IPC_VERSION,
            session_gen: 3,
            req_id: 7,
            tag: ResponseStatus::OkFsInfo as u8,
            flags: 0,
            chunk_seq: 1,
            payload_len: 2,
        }
        .encode_into(&mut p1);
        p1.extend_from_slice(&[0, 0]);
        assert_eq!(
            parser_asm.push(raw_pkt(p1)).unwrap_err(),
            ProtocolViolation::MismatchedChunkTag {
                expected: ResponseStatus::OkOsInfo as u8,
                got: ResponseStatus::OkFsInfo as u8,
            }
        );
    }

    #[test]
    fn error_code_round_trip_matches_freeze_and_thaw_host_descriptions_verbatim() {
        let marker_err = MarkerError::Io {
            path: "/run/secret-tenant/frozen".into(),
            op: "unlink",
            errno: Errno::EACCES,
        };
        let freeze_cases = [
            FreezeFailure::Plan("/proc/self/mountinfo: EACCES".into()),
            FreezeFailure::Marker(marker_err.clone()),
            FreezeFailure::Hard {
                mountpoint: "/secret".into(),
                cause: FreezeStop::OwnershipAmbiguous("8-4: corrupt".into()),
                rolled_back: 2,
            },
            FreezeFailure::RollbackIncomplete {
                failed: "/secret".into(),
                cause: FreezeStop::Unreachable {
                    attempts: "/secret: ENOENT".into(),
                    permission_denied: true,
                },
                mountpoint: "/data".into(),
                recovery_reason: RecoveryReason::RecoveryIncomplete,
                reason: "8:2 failed".into(),
                rolled_back: 1,
            },
            FreezeFailure::MarkerRetained {
                failed: "/secret".into(),
                cause: FreezeStop::Ioctl(crate::kernel::KernelError::Errno(Errno::EIO)),
                marker: marker_err.clone(),
                rolled_back: 3,
            },
            FreezeFailure::PreparationMarkerRetained {
                cause: "panic".into(),
                marker: marker_err.clone(),
            },
            FreezeFailure::Task {
                stage: FreezeTaskStage::Rollback,
                detail: "join failed".into(),
            },
            FreezeFailure::NothingFrozenMarkerRetained(marker_err.clone()),
            FreezeFailure::Aborted {
                cause: AbortCause::Deadline,
                timeout_secs: 45,
                frozen: 2,
                in_flight: Some("/secret".into()),
            },
            FreezeFailure::Aborted {
                cause: AbortCause::ThawRequested,
                timeout_secs: 45,
                frozen: 0,
                in_flight: Some(crate::freeze_op::PREPARING.into()),
            },
            FreezeFailure::Aborted {
                cause: AbortCause::WorkerLost,
                timeout_secs: 45,
                frozen: 1,
                in_flight: Some("/secret".into()),
            },
        ];

        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);
        for (i, failure) in freeze_cases.iter().enumerate() {
            let code = IpcErrorCode::from_freeze_failure(failure);
            let chunks = encode_response_chunks(1, i as u64, &IpcResponse::Err(code)).unwrap();
            assert_eq!(chunks.len(), 1);
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected response");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
            assert_eq!(
                code.to_proto_error().to_string(),
                failure.host_description()
            );
        }

        let thaw_cases = [
            (
                ThawFailure::Plan {
                    detail: "/proc/self/mountinfo".into(),
                    thawed: 1,
                },
                FreezeState::Frozen,
                true,
            ),
            (
                ThawFailure::Incomplete {
                    mountpoint: "/secret".into(),
                    kind: RecoveryReason::OwnershipAmbiguous,
                    reason: "8-4".into(),
                    thawed: 0,
                },
                FreezeState::Frozen,
                false,
            ),
            (
                ThawFailure::Marker {
                    err: marker_err,
                    thawed: 2,
                },
                FreezeState::Thawed,
                true,
            ),
            (
                ThawFailure::Task("join err".into()),
                FreezeState::Frozen,
                true,
            ),
        ];

        for (i, (failure, state, retained)) in thaw_cases.iter().enumerate() {
            let code = IpcErrorCode::from_thaw_failure(failure, *state, *retained);
            let chunks = encode_response_chunks(2, i as u64, &IpcResponse::Err(code)).unwrap();
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected response");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
            assert_eq!(
                code.to_proto_error().to_string(),
                failure.host_description_with_marker(*state, *retained)
            );
        }
    }

    #[test]
    fn all_responses_error_codes_dto_conversions_and_encode_bounds_round_trip() {
        // 1. All simple + capability responses + DTO handler round-trips.
        let (parser_sock, exec_sock) = seqpacket_pair(false).unwrap();
        let mut parser_asm = StreamAssembler::new(PeerRole::Parser);

        let caps: Vec<CommandCapability> = Command::ALL
            .iter()
            .enumerate()
            .map(|(i, &command)| CommandCapability {
                command,
                enabled: i % 2 == 0,
                success_response: !matches!(command, Command::Shutdown | Command::SuspendRam),
            })
            .collect();
        for cap in &caps {
            let info = cap.to_command_info();
            assert_eq!(info.name, cap.command.name());
            assert_eq!(info.enabled, cap.enabled);
            assert_eq!(info.success_response, cap.success_response);
        }

        assert_eq!(
            WireFreezeStatus::from_state(FreezeState::Thawed).as_str(),
            "thawed"
        );
        assert_eq!(
            WireFreezeStatus::from_state(FreezeState::Freezing).as_str(),
            "frozen"
        );
        assert_eq!(
            WireFreezeStatus::from_state(FreezeState::Frozen).as_str(),
            "frozen"
        );
        assert_eq!(
            WireFreezeStatus::from_state(FreezeState::Thawing).as_str(),
            "frozen"
        );

        let iface_handler = Interface {
            name: "eth0".into(),
            hardware_address: Some("52:54:00:aa:bb:cc".into()),
            ip_addresses: vec![
                IpAddress {
                    ip_address: "192.0.2.10".into(),
                    ip_address_type: "ipv4",
                    prefix: 24,
                },
                IpAddress {
                    ip_address: "2001:db8::1".into(),
                    ip_address_type: "ipv6",
                    prefix: 64,
                },
            ],
        };
        let iface_dto = InterfaceDto::from_handler(&iface_handler).unwrap();
        assert_eq!(iface_dto.to_handler(), iface_handler);
        assert!(
            IpAddressDto::from_handler(&IpAddress {
                ip_address: "x".into(),
                ip_address_type: "unknown",
                prefix: 0,
            })
            .is_none()
        );

        let fs_handler = FilesystemInfo {
            name: "fs-1".into(),
            mountpoint: "/data".into(),
            fs_type: "ext4".into(),
            used_bytes: Some(123),
            total_bytes: Some(456),
            disk: Vec::new(),
        };
        let fs_dto = FsInfoDto::from_handler(&fs_handler);
        assert_eq!(fs_dto.to_handler(), fs_handler);

        let trim_dtos = vec![
            TrimPathDto {
                path: "/".into(),
                outcome: TrimPathOutcome::Trimmed {
                    trimmed: 8192,
                    minimum: 4096,
                },
            },
            TrimPathDto {
                path: "/secret".into(),
                outcome: TrimPathOutcome::OpenPermissionDenied,
            },
            TrimPathDto {
                path: "/gone".into(),
                outcome: TrimPathOutcome::TargetUnreachable,
            },
            TrimPathDto {
                path: "/ro".into(),
                outcome: TrimPathOutcome::IoctlErrno(Errno::EOPNOTSUPP as i32),
            },
        ];
        let trim_resp = TrimPathDto::to_trim_response(&trim_dtos);
        assert_eq!(trim_resp.paths.len(), 4);
        assert_eq!(trim_resp.paths[0].trimmed, Some(8192));
        assert!(
            trim_resp.paths[1]
                .error
                .as_deref()
                .unwrap()
                .contains("permission denied")
        );
        assert!(
            trim_resp.paths[2]
                .error
                .as_deref()
                .unwrap()
                .contains("unreachable")
        );
        assert!(trim_resp.paths[3].error.is_some());

        // ProjectedMethod round-trip for both Full and Projected.
        let full_mf = MethodField::Full("guest-nope".into());
        let pm_full = ProjectedMethod::from_method_field(&full_mf).unwrap();
        assert_eq!(pm_full.to_method_field(), full_mf);
        let proj_mf = crate::audit::project_method(&"z".repeat(MAX_METHOD_BYTES + 20));
        let pm_proj = ProjectedMethod::from_method_field(&proj_mf).unwrap();
        assert_eq!(pm_proj.to_method_field(), proj_mf);
        assert!(
            ProjectedMethod::from_method_field(&MethodField::Full(
                "a".repeat(MAX_METHOD_BYTES + 1)
            ))
            .is_none()
        );

        let simple_responses = vec![
            IpcResponse::OkEmpty,
            IpcResponse::OkInfo(caps),
            IpcResponse::OkI64(-42),
            IpcResponse::OkFreezeStatus(WireFreezeStatus::Thawed),
            IpcResponse::OkFreezeStatus(WireFreezeStatus::Frozen),
            IpcResponse::OkCount(7),
            IpcResponse::OkInterfaces(vec![iface_dto]),
            IpcResponse::OkFsInfo(vec![fs_dto]),
            IpcResponse::OkFstrim(trim_dtos),
            IpcResponse::OkSilent,
            IpcResponse::OkAck,
        ];
        for (i, resp) in simple_responses.into_iter().enumerate() {
            send_response(exec_sock.as_fd(), 10, i as u64, &resp, None).unwrap();
            let got = recv_response(parser_sock.as_fd(), &mut parser_asm)
                .unwrap()
                .unwrap();
            assert_eq!(got.response, resp);
            assert!(got.channel_fd.is_none());
        }

        // 2. Every remaining IpcErrorCode, MarkerHostReason, FreezeStopReason,
        //    RecoveryReason, TransitionOp, CommandClass, FreezeTaskStage, AbortActivity.
        let all_marker_reasons = [
            MarkerError::InvalidPath { path: "/x".into() },
            MarkerError::Directory {
                path: "/x".into(),
                errno: Errno::ENOENT,
            },
            MarkerError::AlreadyPresent { path: "/x".into() },
            MarkerError::Absent { path: "/x".into() },
            MarkerError::Io {
                path: "/x".into(),
                op: "open",
                errno: Errno::EACCES,
            },
            MarkerError::Io {
                path: "/x".into(),
                op: "fsync",
                errno: Errno::EIO,
            },
            MarkerError::Io {
                path: "/x".into(),
                op: "unlink",
                errno: Errno::EROFS,
            },
            MarkerError::Io {
                path: "/x".into(),
                op: "stat",
                errno: Errno::EIO,
            },
        ];
        for err in &all_marker_reasons {
            let r = MarkerHostReason::from_marker_error(err);
            assert_eq!(r.host_reason(), err.host_reason());
            let code = IpcErrorCode::FreezeMarkerFailed { reason: r };
            let chunks = encode_response_chunks(1, 1, &IpcResponse::Err(code)).unwrap();
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected err");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
            assert!(code.to_proto_error().to_string().contains(r.host_reason()));
        }

        let all_stops = [
            FreezeStop::Ioctl(crate::kernel::KernelError::Errno(Errno::EPERM)),
            FreezeStop::Ioctl(crate::kernel::KernelError::Open(Errno::ENOENT)),
            FreezeStop::Ioctl(crate::kernel::KernelError::WrongFilesystem {
                expected: (8, 1),
                found: (8, 2),
            }),
            FreezeStop::Ioctl(crate::kernel::KernelError::Errno(Errno::EIO)),
            FreezeStop::Unreachable {
                attempts: "/x".into(),
                permission_denied: true,
            },
            FreezeStop::Unreachable {
                attempts: "/x".into(),
                permission_denied: false,
            },
            FreezeStop::OwnershipAmbiguous("ambig".into()),
            FreezeStop::OwnershipError(crate::ownership::OwnershipError::OpenDir {
                path: "/run/o".into(),
                errno: Errno::EACCES,
            }),
            FreezeStop::OwnershipError(crate::ownership::OwnershipError::NotOwnedBySelf {
                dev: (8, 1),
            }),
            FreezeStop::OwnershipReleaseFailed {
                kind: RecoveryReason::DrainDidNotConverge,
                detail: "d".into(),
            },
        ];
        for stop in &all_stops {
            let reason = FreezeStopReason::from_freeze_stop(stop);
            assert_eq!(reason.host_reason(), stop.host_reason());
            let code = IpcErrorCode::FreezeHard {
                cause: reason,
                rolled_back: 1,
            };
            let chunks = encode_response_chunks(1, 2, &IpcResponse::Err(code)).unwrap();
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected err");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
        }

        let all_recovery = [
            RecoveryReason::TargetUnreachable,
            RecoveryReason::TargetOpenFailed,
            RecoveryReason::TargetOpenPermissionDenied,
            RecoveryReason::PermissionDenied,
            RecoveryReason::IoctlFailed,
            RecoveryReason::DrainDidNotConverge,
            RecoveryReason::RecoveryIncomplete,
            RecoveryReason::WorkerLost,
            RecoveryReason::DrainLost,
            RecoveryReason::MarkerRetained,
            RecoveryReason::OwnershipAmbiguous,
            RecoveryReason::OwnershipError,
        ];
        for kind in all_recovery {
            let code = IpcErrorCode::ThawIncomplete {
                kind,
                thawed: 0,
                final_state: FreezeState::Frozen,
                marker_retained: true,
            };
            let chunks = encode_response_chunks(1, 3, &IpcResponse::Err(code)).unwrap();
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected err");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
        }

        let extra_errors = [
            IpcErrorCode::Disabled {
                command: Command::GetFsInfo,
            },
            IpcErrorCode::Frozen,
            IpcErrorCode::RateLimited {
                class: CommandClass::PingSync,
            },
            IpcErrorCode::RateLimited {
                class: CommandClass::Get,
            },
            IpcErrorCode::RateLimited {
                class: CommandClass::FsfreezeFreeze,
            },
            IpcErrorCode::RateLimited {
                class: CommandClass::Unlimited,
            },
            IpcErrorCode::RateLimited {
                class: CommandClass::Fstrim,
            },
            IpcErrorCode::RateLimited {
                class: CommandClass::Shutdown,
            },
            IpcErrorCode::InvalidArguments {
                command: Command::Sync,
            },
            IpcErrorCode::TransitionConflict {
                op: TransitionOp::BeginFreeze,
                current: FreezeState::Freezing,
            },
            IpcErrorCode::TransitionConflict {
                op: TransitionOp::ClaimThaw,
                current: FreezeState::Thawing,
            },
            IpcErrorCode::FreezeTaskFailed {
                stage: FreezeTaskStage::Preparation,
            },
            IpcErrorCode::FreezeTaskFailed {
                stage: FreezeTaskStage::MarkerRemoval,
            },
            IpcErrorCode::FreezeAborted {
                cause: AbortCause::Deadline,
                frozen: 1,
                activity: AbortActivity::Idle,
            },
            IpcErrorCode::ThawAbortPending {
                activity: AbortActivity::Preparing,
                thawed: 0,
            },
            IpcErrorCode::ThawAbortPending {
                activity: AbortActivity::InFlightFifreeze,
                thawed: 2,
            },
            IpcErrorCode::ThawAbortPending {
                activity: AbortActivity::Idle,
                thawed: 3,
            },
            IpcErrorCode::ReplyTooLarge {
                command: Command::GetFsInfo,
                reply_bytes: 2_000_000,
                limit_bytes: MAX_FSINFO_IPC_BYTES as u64,
            },
            IpcErrorCode::FsinfoBusy,
            IpcErrorCode::FsinfoTimeout,
            IpcErrorCode::HandlerFailed {
                command: Command::Shutdown,
            },
            IpcErrorCode::ChannelRetryLater,
            IpcErrorCode::ChannelTerminalBusy,
        ];
        for (i, code) in extra_errors.into_iter().enumerate() {
            let chunks = encode_response_chunks(3, i as u64, &IpcResponse::Err(code)).unwrap();
            let Some(AssembledMessage::Response(got)) = parser_asm
                .push(raw_pkt(chunks.into_iter().next().unwrap()))
                .unwrap()
            else {
                panic!("expected err");
            };
            assert_eq!(got.response, IpcResponse::Err(code));
            assert!(!code.to_proto_error().to_string().is_empty());
        }
        assert_eq!(
            IpcErrorCode::FsinfoBusy.to_proto_error().to_string(),
            fsinfo_busy_error().to_string()
        );
        assert_eq!(
            IpcErrorCode::FsinfoTimeout.to_proto_error().to_string(),
            fsinfo_timeout_error().to_string()
        );
        let typed_entry = TrimEntry {
            path: "/data".to_owned(),
            outcome: TrimPathOutcome::IoctlErrno(Errno::EOPNOTSUPP as i32),
        };
        assert_eq!(
            TrimPathDto::from_entry(&typed_entry).to_handler(),
            typed_entry.to_result()
        );

        // 3. EncodeError guards & send_response descriptor attachment mismatch.
        assert!(matches!(
            encode_request_chunks(
                1,
                1,
                &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(vec![
                    "a".repeat(MAX_FREEZE_LIST_ENTRY_BYTES + 1)
                ])),
            ),
            Err(EncodeError::FreezeListEntryTooLong { .. })
        ));
        assert!(matches!(
            encode_request_chunks(
                1,
                1,
                &IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(
                    (0..20).map(|_| "b".repeat(4000)).collect()
                )),
            ),
            Err(EncodeError::PayloadTooLarge { .. })
        ));
        assert!(matches!(
            encode_request_chunks(
                1,
                1,
                &IpcRequest::ReportParseRejection(ParseRejection {
                    kind: ParseRejectionKind::UnknownMethod,
                    frame_len: 100,
                    id: None,
                    method: Some(ProjectedMethod::Full("c".repeat(MAX_METHOD_BYTES + 1))),
                }),
            ),
            Err(EncodeError::ValueOutOfRange(_))
        ));
        assert!(matches!(
            encode_response_chunks(
                1,
                1,
                &IpcResponse::OkOsInfo(Box::new(OsInfo {
                    pretty_name: Some("p".repeat(MAX_OSINFO_IPC_BYTES + 1)),
                    ..OsInfo::default()
                })),
            ),
            Err(EncodeError::PayloadTooLarge { .. })
        ));
        let (r_fd, _w_fd) = pipe().unwrap();
        assert!(matches!(
            send_response(exec_sock.as_fd(), 1, 1, &IpcResponse::OkChannelFd, None),
            Err(TransportError::Encode(
                EncodeError::InvalidDescriptorAttachment
            ))
        ));
        assert!(matches!(
            send_response(
                exec_sock.as_fd(),
                1,
                1,
                &IpcResponse::OkEmpty,
                Some(r_fd.as_fd()),
            ),
            Err(TransportError::Encode(
                EncodeError::InvalidDescriptorAttachment
            ))
        ));
        assert_eq!(parser_asm.buffered_bytes(), 0);
    }

    proptest! {
        #[test]
        fn decoder_never_panics_on_arbitrary_packets(
            packets in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..512), 1..16)
        ) {
            let mut exec_asm = StreamAssembler::new(PeerRole::Executor);
            let mut parser_asm = StreamAssembler::new(PeerRole::Parser);
            for raw in packets {
                let _ = exec_asm.push(raw_pkt(raw.clone()));
                let _ = parser_asm.push(raw_pkt(raw));
                prop_assert!(exec_asm.active_streams() <= MAX_CONCURRENT_STREAMS);
                prop_assert!(parser_asm.active_streams() <= MAX_CONCURRENT_STREAMS);
            }
        }

        #[test]
        fn freeze_list_round_trip_property(
            session_gen in any::<u64>(),
            req_id in any::<u64>(),
            entries in prop::collection::vec("[^\0]{0,64}", 0..40)
        ) {
            let req = IpcRequest::FsfreezeFreezeList(FreezeListSelection::Present(entries));
            let chunks = encode_request_chunks(session_gen, req_id, &req).unwrap();
            let mut asm = StreamAssembler::new(PeerRole::Executor);
            let mut decoded = None;
            for chunk in chunks {
                if let Some(msg) = asm.push(raw_pkt(chunk)).unwrap() {
                    decoded = Some(msg);
                }
            }
            match decoded {
                Some(AssembledMessage::Request(got)) => {
                    prop_assert_eq!(got.session_gen, session_gen);
                    prop_assert_eq!(got.req_id, req_id);
                    prop_assert_eq!(got.request, req);
                }
                other => prop_assert!(false, "expected Request, got {other:?}"),
            }
        }
    }
}
