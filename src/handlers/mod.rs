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

/// Every allowlisted command (design §3), each exactly once.
pub const SUPPORTED_COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "guest-ping",
        success_response: true,
    },
    CommandSpec {
        name: "guest-info",
        success_response: true,
    },
    CommandSpec {
        name: "guest-sync",
        success_response: true,
    },
    CommandSpec {
        name: "guest-sync-delimited",
        success_response: true,
    },
    CommandSpec {
        name: "guest-get-osinfo",
        success_response: true,
    },
    CommandSpec {
        name: "guest-network-get-interfaces",
        success_response: true,
    },
    CommandSpec {
        name: "guest-get-fsinfo",
        success_response: true,
    },
    CommandSpec {
        name: "guest-fsfreeze-status",
        success_response: true,
    },
    CommandSpec {
        name: "guest-fsfreeze-freeze",
        success_response: true,
    },
    CommandSpec {
        name: "guest-fsfreeze-freeze-list",
        success_response: true,
    },
    CommandSpec {
        name: "guest-fsfreeze-thaw",
        success_response: true,
    },
    CommandSpec {
        name: "guest-fstrim",
        success_response: true,
    },
    CommandSpec {
        name: "guest-shutdown",
        success_response: false,
    },
    CommandSpec {
        name: "guest-suspend-ram",
        success_response: false,
    },
];

/// Looks up a command's spec by name.
pub fn spec(name: &str) -> Option<&'static CommandSpec> {
    SUPPORTED_COMMANDS.iter().find(|spec| spec.name == name)
}

/// Serialises an information reply and refuses one larger than `bound`
/// bytes with an explicit error instead of truncating it (§5.10, #43 §6):
/// a controller validating coverage must never mistake a partial list
/// for the whole, and a single reply is what the session keeps whole
/// past its backpressure threshold (§5.7), so its size is bounded here.
pub fn bounded_reply<T: serde::Serialize>(
    what: &str,
    value: &T,
    bound: usize,
) -> Result<serde_json::Value, crate::proto::Error> {
    let bytes = serde_json::to_vec(value)
        .map_err(|err| crate::proto::Error::Internal(format!("{what}: cannot encode: {err}")))?;
    if bytes.len() > bound {
        return Err(crate::proto::Error::Internal(format!(
            "{what}: the reply would be {} bytes, over the {bound} byte bound; not truncated",
            bytes.len()
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|err| crate::proto::Error::Internal(format!("{what}: cannot encode: {err}")))
}

/// Argument type for commands that take no arguments; rejects any key.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}
