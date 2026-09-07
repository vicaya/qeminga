//! `guest-suspend-ram` (design §3, §8.1; D1; OQ-2): opt-in suspend to RAM.
//!
//! Two switches must both be on (§8.1): the `suspend_ram` Cargo feature
//! and `[features] suspend_ram = true`. The dispatcher's runtime gate
//! answers `CommandNotFound` (`command guest-suspend-ram has been
//! disabled`) when either is off, so [`handle`] only exists in builds
//! with the feature. It checks that `/sys/power/state` lists `mem` and
//! then writes `mem` to it. Like upstream (`success-response: false`,
//! OQ-2) a successful suspend sends no reply: the host learns of it from
//! the QMP `SUSPEND` event and of the resume from `WAKEUP`, and a reply
//! written after the resume would be unexpected. Errors are still
//! reported.
//!
//! The [`SuspendOps`] trait and the production [`SysPower`] are compiled
//! unconditionally so the `Context` shape does not depend on the feature.
#![forbid(unsafe_code)]

use std::path::Path;

use crate::proto::Error;

/// The sysfs power interface.
pub trait SuspendOps: Send + Sync {
    /// The contents of `/sys/power/state` (space-separated states).
    fn supported_states(&self) -> Result<String, Error>;
    /// Writes `state` to `/sys/power/state`; returns after resume.
    fn enter(&self, state: &str) -> Result<(), Error>;
}

/// Production implementation over `/sys/power/state`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SysPower;

/// The sysfs file [`SysPower`] uses.
pub const POWER_STATE_PATH: &str = "/sys/power/state";

impl SuspendOps for SysPower {
    fn supported_states(&self) -> Result<String, Error> {
        std::fs::read_to_string(Path::new(POWER_STATE_PATH))
            .map_err(|err| Error::Internal(format!("cannot read {POWER_STATE_PATH}: {err}")))
    }

    fn enter(&self, state: &str) -> Result<(), Error> {
        std::fs::write(Path::new(POWER_STATE_PATH), state)
            .map_err(|err| Error::Internal(format!("cannot write {POWER_STATE_PATH}: {err}")))
    }
}

/// The state written for suspend to RAM.
pub const MEM: &str = "mem";

/// `true` when `states` (the file contents) lists `mem`.
pub fn supports_mem(states: &str) -> bool {
    states.split_ascii_whitespace().any(|s| s == MEM)
}

/// `guest-suspend-ram` handler (feature `suspend_ram` only).
#[cfg(feature = "suspend_ram")]
pub async fn handle(
    ctx: &crate::dispatch::Context,
    req: &crate::proto::Request,
) -> Result<serde_json::Value, Error> {
    let crate::handlers::NoArgs {} = crate::proto::arguments(req)?;
    let ops: std::sync::Arc<dyn SuspendOps> = std::sync::Arc::clone(&ctx.suspend);
    tokio::task::spawn_blocking(move || {
        let states = ops.supported_states()?;
        if !supports_mem(&states) {
            return Err(Error::Internal(
                "suspend to RAM is not supported by this kernel".to_owned(),
            ));
        }
        ops.enter(MEM)
    })
    .await
    .map_err(|err| Error::Internal(format!("suspend task failed: {err}")))??;
    Ok(serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Router;
    use crate::config::Config;
    use crate::dispatch::{Context, Dispatcher};
    use crate::framing::DecodeEvent;
    use crate::kernel::fake::FakeKernel;
    use crate::state::{FreezeState, FreezeStateMachine};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct FakeSuspend {
        states: String,
        written: Mutex<Vec<String>>,
    }

    impl SuspendOps for FakeSuspend {
        fn supported_states(&self) -> Result<String, Error> {
            Ok(self.states.clone())
        }
        fn enter(&self, state: &str) -> Result<(), Error> {
            self.written.lock().unwrap().push(state.to_owned());
            Ok(())
        }
    }

    fn rig(state: FreezeState, config: &str, states: &str) -> (Arc<Context>, Arc<FakeSuspend>) {
        let suspend = Arc::new(FakeSuspend {
            states: states.to_owned(),
            written: Mutex::new(Vec::new()),
        });
        let ctx = Context::new(
            Arc::new(Config::parse(config).unwrap()),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
        )
        .with_kernel(Arc::new(FakeKernel::new()))
        .with_suspend(suspend.clone());
        (Arc::new(ctx), suspend)
    }

    /// The dispatcher's reply to one frame, if it produced one.
    async fn send_opt(ctx: &Arc<Context>, json: &str) -> Option<String> {
        Dispatcher::new(ctx.clone())
            .handle(DecodeEvent::Frame {
                bytes: json.as_bytes().to_vec(),
                sentinel: false,
            })
            .await
            .map(|reply| String::from_utf8(reply).unwrap())
    }

    async fn send(ctx: &Arc<Context>, json: &str) -> String {
        send_opt(ctx, json).await.expect("a reply")
    }

    const DISABLED: &str = "{\"error\":{\"class\":\"CommandNotFound\",\"desc\":\"command guest-suspend-ram has been disabled\"}}\n";

    #[test]
    fn supports_mem_parses_the_state_list() {
        assert!(supports_mem("freeze mem disk\n"));
        assert!(supports_mem("mem"));
        assert!(!supports_mem("freeze disk\n"));
        assert!(!supports_mem("memory"));
        assert!(!supports_mem(""));
    }

    #[cfg(not(feature = "suspend_ram"))]
    #[tokio::test]
    async fn feature_absent_returns_command_not_found_disabled() {
        let (ctx, suspend) = rig(
            FreezeState::Thawed,
            "[features]\nsuspend_ram = true\n",
            "freeze mem disk\n",
        );
        assert_eq!(
            send(&ctx, r#"{"execute":"guest-suspend-ram"}"#).await,
            DISABLED
        );
        assert!(suspend.written.lock().unwrap().is_empty());
        assert_eq!(ctx.handler_calls(), 0);
    }

    #[cfg(feature = "suspend_ram")]
    #[tokio::test]
    async fn runtime_off_returns_command_not_found_disabled() {
        let (ctx, suspend) = rig(FreezeState::Thawed, "", "freeze mem disk\n");
        assert_eq!(
            send(&ctx, r#"{"execute":"guest-suspend-ram"}"#).await,
            DISABLED
        );
        let (ctx2, _) = rig(
            FreezeState::Thawed,
            "[features]\nsuspend_ram = false\n",
            "freeze mem disk\n",
        );
        assert_eq!(
            send(&ctx2, r#"{"execute":"guest-suspend-ram"}"#).await,
            DISABLED
        );
        assert!(suspend.written.lock().unwrap().is_empty());
        assert_eq!(ctx.handler_calls(), 0);
    }

    #[cfg(feature = "suspend_ram")]
    #[tokio::test]
    async fn writes_mem_to_sys_power_state_when_supported() {
        let (ctx, suspend) = rig(
            FreezeState::Thawed,
            "[features]\nsuspend_ram = true\n",
            "freeze mem disk\n",
        );
        let reply = send_opt(&ctx, r#"{"execute":"guest-suspend-ram","id":4}"#).await;
        assert_eq!(
            reply, None,
            "no success reply after resume (success-response: false, OQ-2)"
        );
        assert_eq!(*suspend.written.lock().unwrap(), ["mem"]);
        assert_eq!(ctx.handler_calls(), 1, "the handler did run");
        // Arguments are rejected.
        let reply = send(
            &ctx,
            r#"{"execute":"guest-suspend-ram","arguments":{"x":1}}"#,
        )
        .await;
        assert!(reply.contains("GenericError"));
        assert_eq!(suspend.written.lock().unwrap().len(), 1);
    }

    #[cfg(feature = "suspend_ram")]
    #[tokio::test]
    async fn unsupported_state_file_is_generic_error() {
        let (ctx, suspend) = rig(
            FreezeState::Thawed,
            "[features]\nsuspend_ram = true\n",
            "freeze disk\n",
        );
        let reply = send(&ctx, r#"{"execute":"guest-suspend-ram"}"#).await;
        assert!(
            reply.starts_with("{\"error\":{\"class\":\"GenericError\""),
            "{reply}"
        );
        assert!(reply.contains("not supported"), "{reply}");
        assert!(
            suspend.written.lock().unwrap().is_empty(),
            "nothing written"
        );
    }

    #[tokio::test]
    async fn suspend_is_rejected_while_frozen() {
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let (ctx, suspend) = rig(state, "[features]\nsuspend_ram = true\n", "mem\n");
            let reply = send(&ctx, r#"{"execute":"guest-suspend-ram"}"#).await;
            if cfg!(feature = "suspend_ram") {
                assert_eq!(
                    reply,
                    "{\"error\":{\"class\":\"GenericError\",\"desc\":\"filesystems are frozen; retry after thaw\"}}\n",
                    "{state}"
                );
            } else {
                // The runtime gate precedes the freeze gate (C-7).
                assert_eq!(reply, DISABLED, "{state}");
            }
            assert!(suspend.written.lock().unwrap().is_empty());
            assert_eq!(ctx.handler_calls(), 0);
        }
    }

    #[test]
    fn sys_power_reads_the_real_file_or_reports_an_error() {
        // Never writes; only exercises the read path, which may or may not
        // exist in the test environment. Either way the result has the
        // documented shape.
        match SysPower.supported_states() {
            Ok(states) => {
                assert!(
                    states.split_whitespace().all(|s| !s.is_empty()),
                    "space-separated state names: {states:?}"
                );
                // Empty inside a container that cannot suspend; a
                // newline-terminated list on a real guest.
                assert!(states.is_empty() || states.ends_with('\n'), "{states:?}");
            }
            Err(err) => {
                assert!(matches!(err, Error::Internal(_)), "{err:?}");
                assert!(
                    err.to_string().contains("cannot read /sys/power/state"),
                    "{err}"
                );
            }
        }
    }
}
