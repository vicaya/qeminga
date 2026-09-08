//! `guest-shutdown` (design §3 `mode`, no success reply; §4.1 `reboot`
//! syscall; §5.3 2/min; AC12; C-11; OQ-1).
//!
//! `mode` ∈ `{"halt", "powerdown", "reboot"}`, default `"powerdown"`. The
//! handler flushes stderr, calls `sync(2)` and then `reboot(2)` on the
//! blocking pool. On success the kernel never returns, and the dispatcher
//! suppresses the reply anyway (`success-response: false`); errors are
//! still reported.
//!
//! These are *hard* shutdown semantics: `reboot(2)` is an immediate
//! kernel action. No service is stopped, no unit is given a chance to
//! shut down, and no filesystem is unmounted; the `sync(2)` is the only
//! flush. Upstream's `guest-shutdown` asks the service manager for an
//! orderly shutdown instead. That path needs `CAP_KILL` (or D-Bus) and
//! is a design change recorded as OQ-1; the mode → syscall mapping lives
//! in one function so it stays a local change.
#![forbid(unsafe_code)]

use std::io::Write;
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::kernel::{KernelOps, RebootCommand};
use crate::proto::{Error, Request, arguments};

/// The `mode` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShutdownMode {
    /// Halt the machine.
    Halt,
    /// Power it off (default).
    Powerdown,
    /// Reboot it.
    Reboot,
}

/// Arguments of `guest-shutdown`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShutdownArgs {
    /// Defaults to [`ShutdownMode::Powerdown`].
    #[serde(default)]
    pub mode: Option<ShutdownMode>,
}

/// The kernel command for a mode (OQ-1 lives here and in
/// `kernel::shutdown::reboot_mode`).
pub const fn reboot_command(mode: ShutdownMode) -> RebootCommand {
    match mode {
        ShutdownMode::Halt => RebootCommand::Halt,
        ShutdownMode::Powerdown => RebootCommand::PowerOff,
        ShutdownMode::Reboot => RebootCommand::Restart,
    }
}

/// `guest-shutdown` handler.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let args: ShutdownArgs = arguments(req)?;
    let cmd = reboot_command(args.mode.unwrap_or(ShutdownMode::Powerdown));
    let kernel: Arc<dyn KernelOps> = Arc::clone(&ctx.kernel);
    // The audit record for this command was already emitted by the
    // dispatcher; make sure it has left the process before the kernel
    // stops scheduling us.
    let _ = std::io::stderr().flush();
    tokio::task::spawn_blocking(move || {
        kernel.sync();
        kernel.reboot(cmd)
    })
    .await
    .map_err(|err| Error::Internal(format!("shutdown task failed: {err}")))?
    .map_err(|err| Error::Internal(format!("shutdown failed: {err}")))?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{self, Router};
    use crate::config::Config;
    use crate::dispatch::Dispatcher;
    use crate::framing::DecodeEvent;
    use crate::kernel::fake::{Call, FakeKernel};
    use crate::proto::{ErrorClass, parse_request};
    use crate::state::{FreezeState, FreezeStateMachine};
    use nix::errno::Errno;
    use std::sync::Mutex;
    use tracing::Level;
    use tracing::instrument::WithSubscriber;

    #[derive(Clone, Default)]
    struct SharedSink(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn rig(state: FreezeState) -> (Arc<Context>, Arc<FakeKernel>, SharedSink) {
        let kernel = Arc::new(FakeKernel::new());
        let sink = SharedSink::default();
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(sink.clone())),
            crate::marker::Marker::for_tests(),
        )
        .with_kernel(kernel.clone());
        (Arc::new(ctx), kernel, sink)
    }

    fn req(json: &str) -> Request {
        parse_request(json.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn default_mode_is_powerdown() {
        let (ctx, kernel, _) = rig(FreezeState::Thawed);
        handle(&ctx, &req(r#"{"execute":"guest-shutdown"}"#))
            .await
            .unwrap();
        assert_eq!(
            kernel.calls(),
            vec![Call::Sync, Call::Reboot(RebootCommand::PowerOff)]
        );
        for (mode, cmd) in [
            ("halt", RebootCommand::Halt),
            ("reboot", RebootCommand::Restart),
            ("powerdown", RebootCommand::PowerOff),
        ] {
            let (ctx, kernel, _) = rig(FreezeState::Thawed);
            let json = format!(r#"{{"execute":"guest-shutdown","arguments":{{"mode":"{mode}"}}}}"#);
            handle(&ctx, &req(&json)).await.unwrap();
            assert_eq!(
                kernel.calls(),
                vec![Call::Sync, Call::Reboot(cmd)],
                "{mode}"
            );
        }
        assert_eq!(reboot_command(ShutdownMode::Halt), RebootCommand::Halt);
    }

    #[tokio::test]
    async fn invalid_mode_is_generic_error_and_no_reboot_call() {
        let (ctx, kernel, _) = rig(FreezeState::Thawed);
        for args in [
            r#"{"mode":"suspend"}"#,
            r#"{"mode":"Halt"}"#,
            r#"{"mode":1}"#,
            r#"{"mode":"halt","force":true}"#,
        ] {
            let json = format!(r#"{{"execute":"guest-shutdown","arguments":{args}}}"#);
            let err = handle(&ctx, &req(&json)).await.unwrap_err();
            assert!(matches!(err, Error::InvalidArguments(_)), "{args}: {err:?}");
            assert_eq!(err.class(), ErrorClass::GenericError);
        }
        assert!(kernel.calls().is_empty(), "no sync, no reboot");
        // `null` means default.
        handle(
            &ctx,
            &req(r#"{"execute":"guest-shutdown","arguments":{"mode":null}}"#),
        )
        .await
        .unwrap();
        assert_eq!(kernel.calls().len(), 2);
    }

    #[tokio::test]
    async fn sync_is_called_before_reboot() {
        let (ctx, kernel, _) = rig(FreezeState::Thawed);
        handle(
            &ctx,
            &req(r#"{"execute":"guest-shutdown","arguments":{"mode":"reboot"}}"#),
        )
        .await
        .unwrap();
        assert_eq!(
            kernel.calls(),
            vec![Call::Sync, Call::Reboot(RebootCommand::Restart)]
        );
    }

    #[tokio::test]
    async fn success_produces_no_response_and_audit_record_is_emitted_before_reboot() {
        let (ctx, kernel, sink) = rig(FreezeState::Thawed);
        // The kernel hook runs at the moment of `reboot`; the audit record
        // for this command must already be in the sink.
        let sink2 = sink.clone();
        let seen = Arc::new(Mutex::new(None));
        let seen2 = seen.clone();
        kernel.set_hook(Box::new(move |call| {
            if let Call::Reboot(_) = call {
                let text = String::from_utf8(sink2.0.lock().unwrap().clone()).unwrap();
                *seen2.lock().unwrap() = Some(text);
            }
        }));
        let dispatcher = Dispatcher::new(ctx.clone());
        let reply = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-shutdown","id":9}"#.to_vec(),
                sentinel: false,
            })
            .with_subscriber(audit::subscriber(Level::TRACE, ctx.audit.clone()))
            .await;
        assert!(reply.is_none(), "AC12: no success reply");
        let text = seen.lock().unwrap().clone().expect("reboot was called");
        let record: Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
        assert_eq!(record["event"], audit::EVENT_COMMAND_RECEIVED);
        assert_eq!(record["method"], "guest-shutdown");
        assert_eq!(record["id"], 9);
        assert_eq!(record["disposition"], "allowed");
    }

    #[tokio::test]
    async fn reboot_failure_is_reported_as_generic_error() {
        let (ctx, kernel, _) = rig(FreezeState::Thawed);
        kernel.script_reboot_error(Errno::EPERM);
        let err = handle(&ctx, &req(r#"{"execute":"guest-shutdown"}"#))
            .await
            .unwrap_err();
        assert_eq!(err.class(), ErrorClass::GenericError);
        assert!(err.to_string().contains("EPERM"), "{err}");
        assert_eq!(kernel.calls().len(), 2, "sync then the failed reboot");
        // Through the dispatcher the error *is* sent (only success is silent).
        let dispatcher = Dispatcher::new(ctx.clone());
        let reply = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-shutdown","id":1}"#.to_vec(),
                sentinel: false,
            })
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&reply[..reply.len() - 1]).unwrap();
        assert_eq!(value["error"]["class"], "GenericError");
        assert_eq!(value["id"], 1);
    }

    #[tokio::test]
    async fn shutdown_is_rejected_while_frozen() {
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let (ctx, kernel, _) = rig(state);
            let dispatcher = Dispatcher::new(ctx.clone());
            let reply = dispatcher
                .handle(DecodeEvent::Frame {
                    bytes: br#"{"execute":"guest-shutdown"}"#.to_vec(),
                    sentinel: false,
                })
                .await
                .unwrap();
            assert_eq!(
                reply,
                b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"filesystems are frozen; retry after thaw\"}}\n",
                "{state}"
            );
            assert!(kernel.calls().is_empty(), "{state}: no sync, no reboot");
        }
    }
}
