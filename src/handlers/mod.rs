//! Command handlers, one file per command family (design §6).
//!
//! [`SUPPORTED_COMMANDS`] is the single source of truth for the capability
//! contract advertised by `guest-info` (§3.1) and for the consistency test
//! that keeps it in step with the dispatcher's `match` arms. It is **not**
//! used for dispatch: commands are dispatched by a static `match` (§5.1).
#![forbid(unsafe_code)]

pub mod fsinfo;
pub mod info;
pub mod interfaces;
pub mod osinfo;
pub mod ping;
pub mod sync;

/// A command in the allowlist as advertised by `guest-info`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandSpec {
    /// The wire name.
    pub name: &'static str,
    /// `false` only for `guest-shutdown`, which never sends a success reply.
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
        success_response: true,
    },
];

/// Looks up a command's spec by name.
pub fn spec(name: &str) -> Option<&'static CommandSpec> {
    SUPPORTED_COMMANDS.iter().find(|spec| spec.name == name)
}

/// Argument type for commands that take no arguments; rejects any key.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}
