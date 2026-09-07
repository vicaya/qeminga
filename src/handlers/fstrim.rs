//! `guest-fstrim` (design §3, §5.3; D2; §8.1 runtime-only switch; C-13).
//!
//! Issues `FITRIM` over every filesystem in the freeze plan (same plan as
//! freeze, forward mount order) with the requested minimum extent
//! (default 0). Per-mountpoint failures are reported inline in that
//! path's `error` field, upstream style, rather than failing the whole
//! command. The runtime switch (`[features] fstrim`) is enforced by the
//! dispatcher before this handler runs; so is the freeze gate.
#![forbid(unsafe_code)]

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::freeze_plan::FreezePlan;
use crate::kernel::KernelOps;
use crate::mountinfo::MountSource;
use crate::proto::{Error, Request, arguments};

/// Arguments of `guest-fstrim`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstrimArgs {
    /// Minimum contiguous free range to discard, in bytes (default 0).
    #[serde(default)]
    pub minimum: Option<u64>,
}

/// One `GuestFilesystemTrimResult` (C-5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrimResult {
    /// The mount point.
    pub path: String,
    /// Bytes trimmed; absent on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trimmed: Option<u64>,
    /// The minimum extent the kernel applied (the request rounded up to
    /// the block size and the discard granularity, as `FITRIM` writes it
    /// back); absent on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum: Option<u64>,
    /// Why this mount point could not be trimmed; absent on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The `GuestFilesystemTrimResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrimResponse {
    /// One entry per plan target, in mount order.
    pub paths: Vec<TrimResult>,
}

/// Trims every target of `plan` with `minimum`.
pub fn trim_plan(kernel: &dyn KernelOps, plan: &FreezePlan, minimum: u64) -> TrimResponse {
    TrimResponse {
        paths: plan
            .thaw_order()
            .map(|target| {
                // The ioctl gets the byte-exact path; the reply is lossy.
                let mountpoint = target.mountpoint.as_path();
                let path = mountpoint.to_string_lossy().into_owned();
                match kernel.fitrim(mountpoint, minimum) {
                    Ok(trimmed) => TrimResult {
                        path,
                        trimmed: Some(trimmed.bytes),
                        minimum: Some(trimmed.minimum),
                        error: None,
                    },
                    Err(err) => {
                        tracing::warn!(event = "fstrim_failed", mountpoint = %mountpoint.display(), errno = %err, "trim failed");
                        TrimResult {
                            path,
                            trimmed: None,
                            minimum: None,
                            error: Some(err.to_string()),
                        }
                    }
                }
            })
            .collect(),
    }
}

/// `guest-fstrim` handler.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let args: FstrimArgs = arguments(req)?;
    let minimum = args.minimum.unwrap_or(0);
    let kernel: Arc<dyn KernelOps> = Arc::clone(&ctx.kernel);
    let mounts: Arc<dyn MountSource> = Arc::clone(&ctx.mounts);
    let dispatch = tracing::dispatcher::get_default(Clone::clone);
    let response = tokio::task::spawn_blocking(move || {
        tracing::dispatcher::with_default(&dispatch, || {
            let plan = FreezePlan::build(&mounts.mounts()?);
            Ok::<_, Error>(trim_plan(kernel.as_ref(), &plan, minimum))
        })
    })
    .await
    .map_err(|err| Error::Internal(format!("fstrim task failed: {err}")))??;
    Ok(json!(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Router;
    use crate::config::Config;
    use crate::dispatch::Dispatcher;
    use crate::framing::DecodeEvent;
    use crate::kernel::fake::{Call, FakeKernel};
    use crate::mountinfo::StaticMounts;
    use crate::proto::parse_request;
    use crate::state::{FreezeState, FreezeStateMachine};
    use nix::errno::Errno;
    use std::path::Path;

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/mountinfo")
                .join(name),
        )
        .unwrap()
    }

    fn rig(state: FreezeState, config: Config) -> (Arc<Context>, Arc<FakeKernel>) {
        let kernel = Arc::new(FakeKernel::new());
        let ctx = Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(fixture("nested.txt"))));
        (Arc::new(ctx), kernel)
    }

    fn req(json: &str) -> Request {
        parse_request(json.as_bytes()).unwrap()
    }

    #[tokio::test]
    async fn fstrim_trims_each_plan_target_in_forward_order_with_minimum() {
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        kernel.script_trim("/", Ok(4096));
        kernel.script_trim("/home", Ok(8192));
        let value = handle(
            &ctx,
            &req(r#"{"execute":"guest-fstrim","arguments":{"minimum":1048576}}"#),
        )
        .await
        .unwrap();
        assert_eq!(
            kernel.calls(),
            vec![
                Call::Fitrim("/".into(), 1_048_576),
                Call::Fitrim("/home".into(), 1_048_576),
                Call::Fitrim("/home/data".into(), 1_048_576),
                Call::Fitrim("/home/data/deep".into(), 1_048_576),
            ]
        );
        let paths = value["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 4);
        assert_eq!(
            paths[0],
            json!({"path": "/", "trimmed": 4096, "minimum": 1_048_576})
        );
        assert_eq!(paths[1]["trimmed"], 8192);
        assert_eq!(paths[2]["trimmed"], 0);
        assert!(paths[0].get("error").is_none());
    }

    #[tokio::test]
    async fn fstrim_reports_the_effective_minimum_not_the_requested_one() {
        // The kernel rounds the requested minimum up to its block size and
        // the device's discard granularity and writes it back; the reply's
        // `minimum` is that effective value (C-5), per mount point.
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        kernel.script_trim_rounded("/", 4096, 2_097_152);
        kernel.script_trim("/home", Ok(8192));
        let value = handle(
            &ctx,
            &req(r#"{"execute":"guest-fstrim","arguments":{"minimum":1048576}}"#),
        )
        .await
        .unwrap();
        let paths = value["paths"].as_array().unwrap();
        assert_eq!(
            paths[0],
            json!({"path": "/", "trimmed": 4096, "minimum": 2_097_152}),
            "rounded up by the kernel"
        );
        assert_eq!(
            paths[1],
            json!({"path": "/home", "trimmed": 8192, "minimum": 1_048_576}),
            "accepted as requested"
        );
    }

    #[tokio::test]
    async fn fstrim_default_minimum_is_zero() {
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        let value = handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
            .await
            .unwrap();
        assert!(
            kernel
                .calls()
                .iter()
                .all(|c| matches!(c, Call::Fitrim(_, 0)))
        );
        assert_eq!(value["paths"][0]["minimum"], 0);
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        handle(&ctx, &req(r#"{"execute":"guest-fstrim","arguments":{}}"#))
            .await
            .unwrap();
        assert!(
            kernel
                .calls()
                .iter()
                .all(|c| matches!(c, Call::Fitrim(_, 0)))
        );
    }

    #[tokio::test]
    async fn fstrim_rejects_negative_or_non_integer_minimum() {
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        for args in [
            r#"{"minimum":-1}"#,
            r#"{"minimum":1.5}"#,
            r#"{"minimum":"4096"}"#,
            r#"{"minimum":null,"x":1}"#,
            r#"{"min":1}"#,
        ] {
            let json = format!(r#"{{"execute":"guest-fstrim","arguments":{args}}}"#);
            let err = handle(&ctx, &req(&json)).await.unwrap_err();
            assert!(matches!(err, Error::InvalidArguments(_)), "{args}: {err:?}");
        }
        assert!(kernel.calls().is_empty());
        // `null` is the default.
        handle(
            &ctx,
            &req(r#"{"execute":"guest-fstrim","arguments":{"minimum":null}}"#),
        )
        .await
        .unwrap();
        assert!(!kernel.calls().is_empty());
    }

    #[tokio::test]
    async fn per_path_error_is_reported_inline_not_as_command_failure() {
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        kernel.script_trim("/home", Err(Errno::EOPNOTSUPP));
        kernel.script_trim("/home/data", Err(Errno::EIO));
        kernel.script_trim("/", Ok(1));
        let value = handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
            .await
            .unwrap();
        let paths = value["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 4, "every target is reported");
        assert_eq!(paths[0]["trimmed"], 1);
        assert_eq!(paths[1]["path"], "/home");
        assert!(paths[1]["error"].as_str().unwrap().contains("EOPNOTSUPP"));
        assert!(paths[1].get("trimmed").is_none());
        assert!(paths[1].get("minimum").is_none());
        assert!(paths[2]["error"].as_str().unwrap().contains("EIO"));
        assert_eq!(paths[3]["trimmed"], 0);
        // A failure on one path never stops the others.
        assert_eq!(kernel.calls().len(), 4);
    }

    #[tokio::test]
    async fn fstrim_disabled_at_runtime_is_command_not_found() {
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let (ctx, kernel) = rig(FreezeState::Thawed, config);
        let dispatcher = Dispatcher::new(ctx.clone());
        let reply = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-fstrim"}"#.to_vec(),
                sentinel: false,
            })
            .await
            .unwrap();
        assert_eq!(
            reply,
            b"{\"error\":{\"class\":\"CommandNotFound\",\"desc\":\"command guest-fstrim has been disabled\"}}\n"
        );
        assert!(kernel.calls().is_empty());
        assert_eq!(ctx.handler_calls(), 0);
        // Enabled (default): the handler runs and trims.
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        let dispatcher = Dispatcher::new(ctx.clone());
        let reply = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-fstrim","id":3}"#.to_vec(),
                sentinel: false,
            })
            .await
            .unwrap();
        let value: Value = serde_json::from_slice(&reply[..reply.len() - 1]).unwrap();
        assert_eq!(value["id"], 3);
        assert_eq!(value["return"]["paths"].as_array().unwrap().len(), 4);
        assert_eq!(kernel.calls().len(), 4);
    }

    #[tokio::test]
    async fn fstrim_is_rejected_while_frozen() {
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let (ctx, kernel) = rig(state, Config::default());
            let dispatcher = Dispatcher::new(ctx.clone());
            let reply = dispatcher
                .handle(DecodeEvent::Frame {
                    bytes: br#"{"execute":"guest-fstrim"}"#.to_vec(),
                    sentinel: false,
                })
                .await
                .unwrap();
            assert_eq!(
                reply,
                b"{\"error\":{\"class\":\"GenericError\",\"desc\":\"filesystems are frozen; retry after thaw\"}}\n",
                "{state}"
            );
            assert!(kernel.calls().is_empty(), "{state}: no ioctl");
        }
    }

    #[tokio::test]
    async fn empty_plan_yields_empty_paths() {
        let kernel = Arc::new(FakeKernel::new());
        let ctx = Context::new(
            Arc::new(Config::default()),
            Arc::new(FreezeStateMachine::new()),
            Router::new(Box::new(std::io::sink())),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(
            "1 0 0:1 / / rw - tmpfs tmpfs rw\n".to_owned(),
        )));
        let value = handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
            .await
            .unwrap();
        assert_eq!(value, json!({"paths": []}));
        assert!(kernel.calls().is_empty());
    }
}
