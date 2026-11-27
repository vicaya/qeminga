//! Command handlers, one file per command family (design §6).
//!
//! [`SUPPORTED_COMMANDS`] is the single source of truth for the capability
//! contract advertised by `guest-info` (§3.1) and for the consistency test
//! that keeps it in step with the dispatcher's `match` arms. It is **not**
//! used for dispatch: commands are dispatched by a static `match` (§5.1).
#![forbid(unsafe_code)]

pub mod fsfreeze;
pub mod fsinfo;
pub mod fstrim;
pub mod info;
pub mod interfaces;
pub mod osinfo;
pub mod ping;
pub mod shutdown;
pub mod suspend;
pub mod sync;

/// Declares every allowlisted guest-agent command once (design §3, §5.1),
/// generating the exhaustive [`Command`] enum, [`Command::ALL`], the single
/// static wire-name `match` in [`Command::from_method`], and
/// [`Command::name`]. Adding a command here automatically puts it into the
/// `guest-info` inventory and forces an explicit choice at every exhaustive
/// policy and dispatch `match`.
macro_rules! define_commands {
    ($( #[doc = $doc:literal] $variant:ident => $wire:literal ),+ $(,)?) => {
        /// Every allowlisted guest-agent command (design §3, §5.1).
        ///
        /// Wire method names enter through one static string `match`
        /// ([`Command::from_method`]), generated from the same ordered
        /// declaration as [`Command::ALL`] and [`Command::name`]. Every
        /// policy decision — guest feature enablement, concurrency lane and
        /// freeze gate, rate-limit class, reply suppression, sync sentinel,
        /// and handler dispatch — is an exhaustive `match` on this enum with
        /// no wildcard default, so adding a command requires an explicit
        /// policy choice at compile time and cannot leave it unreachable from
        /// `guest-info`.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Command {
            $(
                #[doc = $doc]
                $variant,
            )+
        }

        impl Command {
            /// Every allowlisted command in design §3 order, each exactly once.
            pub const ALL: &[Command] = &[$(Command::$variant),+];

            /// Static allowlist `match` mapping a wire method name to its
            /// [`Command`] variant (design §5.1). There is no lookup table,
            /// registry, or plugin mechanism.
            pub fn from_method(method: &str) -> Option<Self> {
                Some(match method {
                    $( $wire => Command::$variant, )+
                    _ => return None,
                })
            }

            /// Canonical QGA wire name (design §3).
            pub const fn name(self) -> &'static str {
                match self {
                    $( Command::$variant => $wire, )+
                }
            }
        }
    };
}

define_commands! {
    /// `guest-ping`
    Ping => "guest-ping",
    /// `guest-info`
    Info => "guest-info",
    /// `guest-sync`
    Sync => "guest-sync",
    /// `guest-sync-delimited`
    SyncDelimited => "guest-sync-delimited",
    /// `guest-get-osinfo`
    GetOsInfo => "guest-get-osinfo",
    /// `guest-network-get-interfaces`
    NetworkGetInterfaces => "guest-network-get-interfaces",
    /// `guest-get-fsinfo`
    GetFsInfo => "guest-get-fsinfo",
    /// `guest-fsfreeze-status`
    FsfreezeStatus => "guest-fsfreeze-status",
    /// `guest-fsfreeze-freeze`
    FsfreezeFreeze => "guest-fsfreeze-freeze",
    /// `guest-fsfreeze-freeze-list`
    FsfreezeFreezeList => "guest-fsfreeze-freeze-list",
    /// `guest-fsfreeze-thaw`
    FsfreezeThaw => "guest-fsfreeze-thaw",
    /// `guest-fstrim`
    Fstrim => "guest-fstrim",
    /// `guest-shutdown`
    Shutdown => "guest-shutdown",
    /// `guest-suspend-ram`
    SuspendRam => "guest-suspend-ram",
}

impl Command {
    /// Whether a successful call produces a wire reply (§3.1, OQ-2).
    pub const fn success_response(self) -> bool {
        match self {
            Command::Ping
            | Command::Info
            | Command::Sync
            | Command::SyncDelimited
            | Command::GetOsInfo
            | Command::NetworkGetInterfaces
            | Command::GetFsInfo
            | Command::FsfreezeStatus
            | Command::FsfreezeFreeze
            | Command::FsfreezeFreezeList
            | Command::FsfreezeThaw
            | Command::Fstrim => true,
            Command::Shutdown | Command::SuspendRam => false,
        }
    }

    /// Whether every reply (success or error) carries the `0xFF` sync
    /// sentinel prefix (C-10).
    pub const fn sends_sentinel(self) -> bool {
        match self {
            Command::SyncDelimited => true,
            Command::Ping
            | Command::Info
            | Command::Sync
            | Command::GetOsInfo
            | Command::NetworkGetInterfaces
            | Command::GetFsInfo
            | Command::FsfreezeStatus
            | Command::FsfreezeFreeze
            | Command::FsfreezeFreezeList
            | Command::FsfreezeThaw
            | Command::Fstrim
            | Command::Shutdown
            | Command::SuspendRam => false,
        }
    }

    /// `CommandSpec` advertised by `guest-info`.
    pub const fn spec(self) -> CommandSpec {
        CommandSpec {
            name: self.name(),
            success_response: self.success_response(),
        }
    }

    /// Whether guest-derived `authority` enables this command (§5.9, §8.1).
    ///
    /// Shared by request dispatch and `guest-info` capability reporting.
    /// Exhaustive with no wildcard default: every command must explicitly
    /// declare either the core snapshot/control baseline or the guest
    /// switch that governs it. Temporary `Frozen` state is orthogonal and
    /// enforced separately by the live freeze gate (§3.1, §5.3).
    pub const fn is_enabled(self, authority: &crate::config::Authority) -> bool {
        match self {
            Command::Ping
            | Command::Info
            | Command::Sync
            | Command::SyncDelimited
            | Command::FsfreezeStatus
            | Command::FsfreezeFreeze
            | Command::FsfreezeFreezeList
            | Command::FsfreezeThaw => true,
            Command::GetOsInfo | Command::NetworkGetInterfaces | Command::GetFsInfo => {
                authority.information
            }
            Command::Fstrim => authority.trim,
            Command::Shutdown => authority.reboot,
            Command::SuspendRam => authority.suspend,
        }
    }

    /// The session lane for this command (§5.7).
    pub const fn lane(self) -> crate::channel::Kind {
        use crate::channel::Kind;
        match self {
            Command::FsfreezeThaw => Kind::Thaw,
            Command::FsfreezeFreeze | Command::FsfreezeFreezeList => Kind::Freeze,
            Command::Ping
            | Command::Info
            | Command::Sync
            | Command::SyncDelimited
            | Command::FsfreezeStatus => Kind::Control,
            Command::GetOsInfo
            | Command::NetworkGetInterfaces
            | Command::GetFsInfo
            | Command::Fstrim
            | Command::Shutdown
            | Command::SuspendRam => Kind::Ordinary,
        }
    }

    /// `true` for the six commands accepted while filesystems are frozen
    /// (§5.3): status, thaw, ping, sync, sync-delimited, info — derived
    /// exhaustively from [`Command::lane`] so concurrency lane and freeze
    /// gate always agree.
    pub const fn is_frozen_safe(self) -> bool {
        use crate::channel::Kind;
        match self.lane() {
            Kind::Control | Kind::Thaw => true,
            Kind::Freeze | Kind::Ordinary => false,
        }
    }

    /// The rate-limit class of this command (§5.3, C-9).
    pub const fn rate_class(self) -> crate::dispatch::ratelimit::CommandClass {
        use crate::dispatch::ratelimit::CommandClass;
        match self {
            Command::Ping | Command::Sync | Command::SyncDelimited | Command::Info => {
                CommandClass::PingSync
            }
            Command::GetOsInfo | Command::GetFsInfo | Command::NetworkGetInterfaces => {
                CommandClass::Get
            }
            Command::FsfreezeFreeze | Command::FsfreezeFreezeList => CommandClass::FsfreezeFreeze,
            Command::FsfreezeStatus | Command::FsfreezeThaw => CommandClass::Unlimited,
            Command::Fstrim => CommandClass::Fstrim,
            Command::Shutdown | Command::SuspendRam => CommandClass::Shutdown,
        }
    }
}

/// A command in the allowlist as advertised by `guest-info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    /// The wire name.
    pub name: &'static str,
    /// `false` for `guest-shutdown` and `guest-suspend-ram`, which never
    /// send a success reply (the host watches for the VM exit or the QMP
    /// `SUSPEND` event instead); errors are still reported.
    pub success_response: bool,
}

const fn build_supported_commands() -> [CommandSpec; Command::ALL.len()] {
    let mut specs = [Command::ALL[0].spec(); Command::ALL.len()];
    let mut i = 1;
    while i < Command::ALL.len() {
        specs[i] = Command::ALL[i].spec();
        i += 1;
    }
    specs
}

const SUPPORTED_COMMAND_ARRAY: [CommandSpec; Command::ALL.len()] = build_supported_commands();

/// Every allowlisted command (design §3), each exactly once.
pub const SUPPORTED_COMMANDS: &[CommandSpec] = &SUPPORTED_COMMAND_ARRAY;

/// Looks up a command's spec by name.
pub fn spec(name: &str) -> Option<&'static CommandSpec> {
    SUPPORTED_COMMANDS.iter().find(|spec| spec.name == name)
}

/// Measures the worst-case QGA reply line length in bytes for `value`
/// (including [`MAX_RESPONSE_ENVELOPE_BYTES`](crate::proto::MAX_RESPONSE_ENVELOPE_BYTES))
/// without allocating a buffer of that size.
pub(crate) fn serialized_reply_line_bytes<T: serde::Serialize>(
    what: &str,
    value: &T,
) -> Result<(usize, usize), crate::proto::Error> {
    let mut counter = Counting(0);
    serde_json::to_writer(&mut counter, value)
        .map_err(|err| crate::proto::Error::Internal(format!("{what}: cannot encode: {err}")))?;
    Ok((counter.0, counter.0 + crate::proto::MAX_RESPONSE_ENVELOPE_BYTES))
}

/// Serialises an information reply and refuses one whose line on the
/// wire would exceed `bound` bytes with an explicit error instead of
/// truncating it (§5.10, #43 §6): a controller validating coverage must
/// never mistake a partial list for the whole, and a single reply is
/// what the session keeps whole past its backpressure threshold (§5.7),
/// so its size is bounded here. The line is the value plus the response
/// envelope the dispatcher adds (`{"return":…,"id":…}` and the newline),
/// so the value is measured against the bound less the longest envelope
/// ([`MAX_RESPONSE_ENVELOPE_BYTES`](crate::proto::MAX_RESPONSE_ENVELOPE_BYTES)).
/// The length is counted through a writer that stores nothing, so a
/// reply over the bound costs no buffer of its size, and the value is
/// converted to the reply tree directly rather than parsed back from
/// its bytes.
pub fn bounded_reply<T: serde::Serialize>(
    what: &str,
    value: &T,
    bound: usize,
) -> Result<serde_json::Value, crate::proto::Error> {
    let (value_bytes, line) = serialized_reply_line_bytes(what, value)?;
    if line > bound {
        return Err(crate::proto::Error::Internal(format!(
            "{what}: the reply would be {line} bytes on the wire ({value_bytes} of value), over the {bound} byte bound; not truncated"
        )));
    }
    serde_json::to_value(value)
        .map_err(|err| crate::proto::Error::Internal(format!("{what}: cannot encode: {err}")))
}

/// Counts the bytes written through it and keeps none of them: the
/// length of an encoding without a buffer of that length.
struct Counting(usize);

impl std::io::Write for Counting {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Argument type for commands that take no arguments; rejects any key.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{MAX_RESPONSE_ENVELOPE_BYTES, Response};

    #[test]
    fn the_reply_bound_covers_the_whole_line_envelope_included() {
        // A value that fills the bound with the longest envelope is
        // answered and the line the dispatcher sends is exactly the
        // bound; one byte more of value is refused, naming the size on
        // the wire.
        const BOUND: usize = 1024;
        let value_of = |n: usize| "x".repeat(n - 2);
        let fits = value_of(BOUND - MAX_RESPONSE_ENVELOPE_BYTES);
        let reply = bounded_reply("test", &fits, BOUND).unwrap();
        let mut line = Response::Success {
            ret: reply,
            id: Some(i64::MIN),
        }
        .to_json();
        line.push(b'\n');
        assert_eq!(line.len(), BOUND);
        let over = value_of(BOUND - MAX_RESPONSE_ENVELOPE_BYTES + 1);
        let text = bounded_reply("test", &over, BOUND).unwrap_err().to_string();
        assert!(
            text.contains(&format!("{} bytes on the wire", BOUND + 1))
                && text.contains("over the 1024 byte bound")
                && text.contains("not truncated"),
            "{text}"
        );
    }

    #[test]
    fn command_enum_round_trips_and_matches_supported_commands() {
        assert_eq!(Command::ALL.len(), 14);
        assert_eq!(SUPPORTED_COMMANDS.len(), Command::ALL.len());
        for (&cmd, spec_entry) in Command::ALL.iter().zip(SUPPORTED_COMMANDS.iter()) {
            assert_eq!(Command::from_method(cmd.name()), Some(cmd));
            assert_eq!(spec_entry, &cmd.spec());
            assert_eq!(spec(cmd.name()), Some(spec_entry));
            assert_eq!(
                cmd.sends_sentinel(),
                matches!(cmd, Command::SyncDelimited),
                "{cmd:?}"
            );
        }
        assert_eq!(Command::from_method("guest-exec"), None);
        assert_eq!(spec("guest-exec"), None);
    }

    #[test]
    fn command_is_enabled_follows_guest_authority_exhaustively() {
        use crate::config::Authority;
        let dp = Authority::data_protection();
        for cmd in Command::ALL {
            let core = matches!(
                cmd,
                Command::Ping
                    | Command::Info
                    | Command::Sync
                    | Command::SyncDelimited
                    | Command::FsfreezeStatus
                    | Command::FsfreezeFreeze
                    | Command::FsfreezeFreezeList
                    | Command::FsfreezeThaw
            );
            assert_eq!(cmd.is_enabled(&dp), core, "data-protection {cmd:?}");
            assert!(cmd.is_enabled(&Authority::full()), "full {cmd:?}");
        }
        assert!(Command::GetOsInfo.is_enabled(&Authority {
            information: true,
            ..dp
        }));
        assert!(Command::NetworkGetInterfaces.is_enabled(&Authority {
            information: true,
            ..dp
        }));
        assert!(Command::GetFsInfo.is_enabled(&Authority {
            information: true,
            ..dp
        }));
        assert!(Command::Fstrim.is_enabled(&Authority { trim: true, ..dp }));
        assert!(Command::Shutdown.is_enabled(&Authority { reboot: true, ..dp }));
        assert!(Command::SuspendRam.is_enabled(&Authority {
            suspend: true,
            ..dp
        }));
    }
}
