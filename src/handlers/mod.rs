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
    let encode = |err: serde_json::Error| {
        crate::proto::Error::Internal(format!("{what}: cannot encode: {err}"))
    };
    let mut counter = Counting(0);
    serde_json::to_writer(&mut counter, value).map_err(encode)?;
    let line = counter.0 + crate::proto::MAX_RESPONSE_ENVELOPE_BYTES;
    if line > bound {
        return Err(crate::proto::Error::Internal(format!(
            "{what}: the reply would be {line} bytes on the wire ({} of value), over the {bound} byte bound; not truncated",
            counter.0
        )));
    }
    serde_json::to_value(value).map_err(encode)
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
}
