//! `guest-fstrim` (design §3, §5.3; D2; §8.1 runtime-only switch; C-13).
//!
//! Issues `FITRIM` over every filesystem in the freeze plan (same plan as
//! freeze, forward mount order) with the requested minimum extent
//! (default 0). Per-mountpoint failures are reported inline in that
//! path's `error` field, upstream style, rather than failing the whole
//! command. The runtime switch (`[features] fstrim`) is enforced by the
//! dispatcher before this handler runs; so is the freeze gate.
#![forbid(unsafe_code)]

use std::borrow::Cow;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::dispatch::Context;
use crate::freeze_plan::FreezePlan;
use crate::handlers::fsfreeze::open_target;
use crate::kernel::KernelOps;
use crate::mountinfo::MountSource;
use crate::proto::{Error, Request, arguments};

/// Bound on the encoded `guest-fstrim` wire reply (1 MiB; OQ-10 §4.1, #77).
///
/// Because `FITRIM` kernel discards may already have completed when the reply
/// is assembled, exceeding this bound returns a non-fatal `GenericError`
/// carrying exact successful-ioctl (`trimmed_targets`) and failed-target
/// (`failed_targets`) counts rather than truncating paths or dropping the
/// session.
pub const MAX_FSTRIM_REPLY_BYTES: usize = 1024 * 1024;

/// Maximum UTF-8 bytes emitted per field (`mountpoint`, `error`) in a single
/// guest-local `fstrim_failed` audit record so a target with thousands of
/// bind aliases or a very long path can never produce an unbounded log line
/// (#77).
pub const MAX_FSTRIM_LOG_FIELD_BYTES: usize = 1024;

/// Summary returned when a valid `guest-fstrim` result exceeds
/// [`MAX_FSTRIM_REPLY_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FstrimOversize {
    /// Targets whose `FITRIM` ioctl succeeded (`Ok`).
    pub trimmed_targets: u64,
    /// Targets that failed either before `FITRIM` (unreachable / permission
    /// denied open, where no `FITRIM` was issued) or in the `FITRIM` ioctl.
    pub failed_targets: u64,
    /// Measured QGA reply line length (including worst-case JSON envelope).
    pub reply_bytes: usize,
    /// Enforced wire response bound in bytes.
    pub limit_bytes: usize,
}

impl FstrimOversize {
    /// Fixed host-safe error description (OQ-10 §4.1).
    pub fn format_host_description(trimmed_targets: u64, failed_targets: u64) -> String {
        format!(
            "fstrim trimmed {trimmed_targets} target(s) ({failed_targets} failed), but reply exceeds the 1 MiB response bound"
        )
    }

    /// Fixed host-safe error description (OQ-10 §4.1).
    pub fn host_description(&self) -> String {
        Self::format_host_description(self.trimmed_targets, self.failed_targets)
    }
}

/// Bounds a guest-local `fstrim_failed` diagnostic field so the emitted string
/// is at most `max_bytes` UTF-8 bytes, including the truncation suffix.
fn bound_log_field(value: &str, max_bytes: usize) -> Cow<'_, str> {
    if value.len() <= max_bytes {
        return Cow::Borrowed(value);
    }
    let suffix = format!("... (truncated, {} bytes total)", value.len());
    if suffix.len() >= max_bytes {
        let mut cut = max_bytes;
        while cut > 0 && !value.is_char_boundary(cut) {
            cut -= 1;
        }
        return Cow::Owned(value[..cut].to_owned());
    }
    let mut cut = max_bytes - suffix.len();
    while cut > 0 && !value.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = String::with_capacity(cut + suffix.len());
    out.push_str(&value[..cut]);
    out.push_str(&suffix);
    Cow::Owned(out)
}

/// Arguments of `guest-fstrim`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FstrimArgs {
    /// Minimum contiguous free range to discard, in bytes (default 0).
    #[serde(default)]
    pub minimum: Option<u64>,
}

/// Closed per-path outcome collected by [`trim_plan_entries`] and shared by
/// both the QGA JSON encoder and the binary IPC encoder (OQ-10 §4.2, #77).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrimPathOutcome {
    /// `FITRIM` succeeded with `trimmed` bytes and effective `minimum`.
    Trimmed {
        /// Discarded byte count.
        trimmed: u64,
        /// Effective minimum extent applied by the kernel.
        minimum: u64,
    },
    /// Opening the target failed with `EPERM`/`EACCES`; no `FITRIM` issued.
    OpenPermissionDenied,
    /// No mount point opened on the planned superblock; no `FITRIM` issued.
    TargetUnreachable,
    /// `FITRIM` ioctl returned a kernel errno.
    IoctlErrno(i32),
}

impl TrimPathOutcome {
    /// Formats this typed outcome as the host-facing QAPI [`TrimResult`] for
    /// `path`.
    pub fn to_trim_result(self, path: String) -> TrimResult {
        match self {
            Self::Trimmed { trimmed, minimum } => TrimResult {
                path,
                trimmed: Some(trimmed),
                minimum: Some(minimum),
                error: None,
            },
            Self::OpenPermissionDenied => TrimResult {
                path,
                trimmed: None,
                minimum: None,
                error: Some("target open permission denied; no FITRIM issued".to_owned()),
            },
            Self::TargetUnreachable => TrimResult {
                path,
                trimmed: None,
                minimum: None,
                error: Some("target unreachable; no FITRIM issued".to_owned()),
            },
            Self::IoctlErrno(raw) => TrimResult {
                path,
                trimmed: None,
                minimum: None,
                error: Some(nix::errno::Errno::from_raw(raw).to_string()),
            },
        }
    }
}

/// Typed per-mountpoint trim result retaining the closed [`TrimPathOutcome`]
/// before host-wire rendering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrimEntry {
    /// Primary mount point path.
    pub path: String,
    /// Closed per-target outcome.
    pub outcome: TrimPathOutcome,
}

impl TrimEntry {
    /// Converts this typed entry into the QAPI [`TrimResult`].
    pub fn to_result(&self) -> TrimResult {
        self.outcome.to_trim_result(self.path.clone())
    }
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

/// Trims every target of `plan` with `minimum`, returning typed
/// [`TrimEntry`] records so both the QGA JSON encoder and the binary IPC
/// encoder share the exact same collection and error classification.
pub fn trim_plan_entries(
    kernel: &dyn KernelOps,
    plan: &FreezePlan,
    minimum: u64,
) -> Vec<TrimEntry> {
    plan.thaw_order()
        .map(|target| {
            // The ioctl gets the verified handle; the reply is lossy.
            let mountpoint = target.mountpoint.as_path();
            let path = mountpoint.to_string_lossy().into_owned();
            let (outcome, failure_detail) = match open_target(kernel, target) {
                Ok(mount) => match kernel.fitrim(&mount, minimum) {
                    Ok(trimmed) => (
                        TrimPathOutcome::Trimmed {
                            trimmed: trimmed.bytes,
                            minimum: trimmed.minimum,
                        },
                        None,
                    ),
                    Err(err) => (
                        TrimPathOutcome::IoctlErrno(
                            err.errno()
                                .map_or(nix::errno::Errno::EIO as i32, |e| e as i32),
                        ),
                        Some(err.to_string()),
                    ),
                },
                Err(err) => {
                    let outcome = if err.permission_denied {
                        TrimPathOutcome::OpenPermissionDenied
                    } else {
                        TrimPathOutcome::TargetUnreachable
                    };
                    let detail = format!(
                        "no mount point leads to {}:{} ({}); no FITRIM issued",
                        target.dev.0, target.dev.1, err.detail
                    );
                    (outcome, Some(detail))
                }
            };
            if let Some(detail) = failure_detail {
                let logged_mp = bound_log_field(&path, MAX_FSTRIM_LOG_FIELD_BYTES);
                let logged_err = bound_log_field(&detail, MAX_FSTRIM_LOG_FIELD_BYTES);
                tracing::warn!(
                    event = "fstrim_failed",
                    mountpoint = %logged_mp,
                    error = %logged_err,
                    "trim failed"
                );
            }
            TrimEntry { path, outcome }
        })
        .collect()
}

/// Trims every target of `plan` with `minimum`. Each target is opened on
/// its planned device through the first of its mount points that still
/// leads there (as freeze and thaw do); a target none of them opens on
/// reports that inline, like a failed ioctl.
pub fn trim_plan(kernel: &dyn KernelOps, plan: &FreezePlan, minimum: u64) -> TrimResponse {
    TrimResponse {
        paths: trim_plan_entries(kernel, plan, minimum)
            .into_iter()
            .map(|entry| entry.outcome.to_trim_result(entry.path))
            .collect(),
    }
}

/// Checks whether `response` fits within [`MAX_FSTRIM_REPLY_BYTES`] on the
/// wire without allocating a serialized buffer. Returns the wire line length
/// on success, or [`FstrimOversize`] carrying exact `trimmed_targets`
/// (successful `FITRIM` ioctls only) and `failed_targets` counts.
pub fn check_fstrim_reply_bounds(
    response: &TrimResponse,
) -> Result<usize, Result<FstrimOversize, Error>> {
    let (_, line) = match crate::handlers::serialized_reply_line_bytes("fstrim", response) {
        Ok(measured) => measured,
        Err(err) => return Err(Err(err)),
    };
    if line > MAX_FSTRIM_REPLY_BYTES {
        let trimmed_targets = response
            .paths
            .iter()
            .filter(|entry| entry.trimmed.is_some())
            .count() as u64;
        let failed_targets = response
            .paths
            .iter()
            .filter(|entry| entry.error.is_some())
            .count() as u64;
        return Err(Ok(FstrimOversize {
            trimmed_targets,
            failed_targets,
            reply_bytes: line,
            limit_bytes: MAX_FSTRIM_REPLY_BYTES,
        }));
    }
    Ok(line)
}

/// Converts `response` into a QGA JSON value if it fits within
/// [`MAX_FSTRIM_REPLY_BYTES`]; otherwise emits one fixed-size
/// `fstrim_reply_too_large` summary record and returns the non-fatal
/// mixed-outcome `GenericError` (OQ-10 §4.1, #77).
pub fn bounded_fstrim_reply(response: &TrimResponse) -> Result<Value, Error> {
    match check_fstrim_reply_bounds(response) {
        Ok(_) => serde_json::to_value(response)
            .map_err(|err| Error::Internal(format!("fstrim: cannot encode: {err}"))),
        Err(Ok(oversize)) => {
            tracing::warn!(
                event = "fstrim_reply_too_large",
                trimmed_targets = oversize.trimmed_targets,
                failed_targets = oversize.failed_targets,
                reply_bytes = oversize.reply_bytes as u64,
                limit_bytes = oversize.limit_bytes as u64,
                "fstrim reply exceeds 1 MiB bound; returning summary counts only"
            );
            Err(Error::Internal(oversize.host_description()))
        }
        Err(Err(err)) => Err(err),
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
    bounded_fstrim_reply(&response)
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
    use serde_json::json;
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
        rig_with(state, config, "nested.txt")
    }

    fn rig_with(
        state: FreezeState,
        config: Config,
        mountinfo: &str,
    ) -> (Arc<Context>, Arc<FakeKernel>) {
        let kernel = Arc::new(FakeKernel::new());
        let ctx = Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
            crate::marker::Marker::for_tests(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(fixture(mountinfo))));
        (Arc::new(ctx), kernel)
    }

    /// The `Fitrim` calls only (each is preceded by the `Open` of its
    /// target).
    fn trims(kernel: &FakeKernel) -> Vec<Call> {
        kernel
            .calls()
            .into_iter()
            .filter(|c| matches!(c, Call::Fitrim(..)))
            .collect()
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
            trims(&kernel),
            vec![
                Call::Fitrim("/".into(), 1_048_576),
                Call::Fitrim("/home".into(), 1_048_576),
                Call::Fitrim("/home/data".into(), 1_048_576),
                Call::Fitrim("/home/data/deep".into(), 1_048_576),
            ]
        );
        assert_eq!(
            kernel.calls()[0],
            Call::Open("/".into(), (8, 1)),
            "each target is opened on its planned device before its ioctl"
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
            trims(&kernel)
                .iter()
                .all(|c| matches!(c, Call::Fitrim(_, 0)))
        );
        assert_eq!(value["paths"][0]["minimum"], 0);
        let (ctx, kernel) = rig(FreezeState::Thawed, Config::default());
        handle(&ctx, &req(r#"{"execute":"guest-fstrim","arguments":{}}"#))
            .await
            .unwrap();
        assert!(
            trims(&kernel)
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
        assert_eq!(trims(&kernel).len(), 4);
    }

    #[tokio::test]
    async fn a_hidden_target_is_trimmed_through_an_alias_and_an_unreachable_one_reports_it() {
        // bind_mounts.txt: / (8:1; /var/www, /mnt/rootbind) and /data
        // (8:2; /srv/exports). With `information = false` and `fstrim = true`,
        // /data leads elsewhere so 8:2 is trimmed through /srv/exports and
        // still reported as /data; no pathname of 8:1 opens on it, which
        // reports a fixed open-failure reason on the wire while keeping
        // alternate aliases and device numbers in guest-local logs (PR #57).
        #[derive(Clone, Default)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let cfg = Config::parse("[features]\ninformation = false\nfstrim = true\n").unwrap();
        let (ctx, kernel) = rig_with(FreezeState::Thawed, cfg.clone(), "bind_mounts.txt");
        kernel.script_mount_device("/data", (8, 9));
        kernel.script_mount_device("/", (8, 7));
        for path in ["/var/www", "/mnt/rootbind"] {
            kernel.script_open_error(path, Errno::ENOENT);
        }
        kernel.script_trim("/srv/exports", Ok(77));
        let sink = Sink::default();
        let router = Router::new(Box::new(sink.clone()));
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::WARN,
            router.clone(),
        ));
        let value = {
            use tracing::instrument::WithSubscriber;
            handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
                .with_subscriber(dispatch)
                .await
                .unwrap()
        };
        assert!(
            router.settle(std::time::Duration::from_secs(1)),
            "audit writer did not settle"
        );
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();

        let paths = value["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0]["path"], "/");
        let error = paths[0]["error"].as_str().unwrap();
        assert_eq!(error, "target unreachable; no FITRIM issued");
        for forbidden in ["/var/www", "/mnt/rootbind", "8:1", "8:7", "ENOENT"] {
            assert!(
                !error.contains(forbidden),
                "trim wire error disclosed {forbidden:?}: {error:?}"
            );
        }
        assert!(
            logs.contains("/var/www")
                && logs.contains("/mnt/rootbind")
                && logs.contains("8:1")
                && logs.contains("8:7"),
            "guest-local log must retain alias and device diagnostics: {logs}"
        );
        assert_eq!(paths[1]["path"], "/data");
        assert_eq!(paths[1]["trimmed"], 77);
        assert_eq!(trims(&kernel), vec![Call::Fitrim("/srv/exports".into(), 0)]);
        assert!(
            kernel.calls().contains(&Call::Open("/data".into(), (8, 2))),
            "the first pathname was tried and refused"
        );

        // When every mount point fails with EACCES/EPERM, emit the fixed
        // permission-denied open reason without aliases.
        let (ctx, kernel) = rig_with(FreezeState::Thawed, cfg, "bind_mounts.txt");
        for path in ["/", "/var/www", "/mnt/rootbind"] {
            kernel.script_open_error(path, Errno::EACCES);
        }
        let value = handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
            .await
            .unwrap();
        let error = value["paths"][0]["error"].as_str().unwrap();
        assert_eq!(error, "target open permission denied; no FITRIM issued");
        for forbidden in ["/var/www", "/mnt/rootbind", "8:1", "EACCES"] {
            assert!(
                !error.contains(forbidden),
                "trim wire error disclosed {forbidden:?}: {error:?}"
            );
        }
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
        assert_eq!(trims(&kernel).len(), 4);
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
            crate::marker::Marker::for_tests(),
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

    #[tokio::test]
    async fn oversized_fstrim_reply_reports_exact_mixed_counts_logs_bounded_summary_and_keeps_dispatcher_usable()
     {
        use tracing::instrument::WithSubscriber;

        #[derive(Clone, Default)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // Build a synthetic mount table with ~360 distinct superblocks whose
        // ~3200-byte paths push the serialized `guest-fstrim` JSON reply past
        // the 1 MiB bound while mixing:
        //   - successful FITRIM ioctls (trimmed_targets),
        //   - unreachable opens where no FITRIM ran (failed_targets),
        //   - failed FITRIM ioctls (failed_targets).
        let mut table = String::from("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
        let kernel = Arc::new(FakeKernel::new());
        kernel.script_trim("/", Ok(4096));
        let mut expected_trimmed = 1u64;
        let mut expected_failed = 0u64;
        let long_seg = "a".repeat(3100);
        for i in 2u32..365 {
            let path = format!("/m/{long_seg}_{i}");
            table.push_str(&format!("{i} 1 8:{i} / {path} rw - ext4 /dev/sd{i} rw\n"));
            if i % 5 == 0 {
                kernel.script_open_error(&path, Errno::ENOENT);
                expected_failed += 1;
            } else if i % 7 == 0 {
                kernel.script_trim(&path, Err(Errno::EOPNOTSUPP));
                expected_failed += 1;
            } else {
                kernel.script_trim(&path, Ok(1024));
                expected_trimmed += 1;
            }
        }

        let sink = Sink::default();
        let router = Router::new(Box::new(sink.clone()));
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                router.clone(),
                crate::marker::Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table))),
        );
        let dispatcher = Dispatcher::new(ctx.clone());
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::WARN,
            router.clone(),
        ));

        let reply = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-fstrim","id":42}"#.to_vec(),
                sentinel: false,
            })
            .with_subscriber(dispatch.clone())
            .await
            .unwrap();
        let parsed: Value = serde_json::from_slice(&reply[..reply.len() - 1]).unwrap();
        assert_eq!(parsed["id"], 42);
        assert_eq!(parsed["error"]["class"], "GenericError");
        assert_eq!(
            parsed["error"]["desc"],
            format!(
                "fstrim trimmed {expected_trimmed} target(s) ({expected_failed} failed), but reply exceeds the 1 MiB response bound"
            )
        );

        // Connection / dispatcher stays completely usable for subsequent commands.
        let ping = dispatcher
            .handle(DecodeEvent::Frame {
                bytes: br#"{"execute":"guest-ping","id":43}"#.to_vec(),
                sentinel: false,
            })
            .await
            .unwrap();
        assert_eq!(ping, b"{\"return\":{},\"id\":43}\n");

        assert!(router.settle(std::time::Duration::from_secs(1)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.contains("\"event\":\"fstrim_reply_too_large\""),
            "expected fixed-size fstrim_reply_too_large summary record: {logs}"
        );
        // Every individual `fstrim_failed` audit record must stay strictly
        // bounded on every field (`mountpoint`, `error`) including any
        // truncation suffix, even though mountpoint paths are > 3 KiB each.
        for line in logs.lines() {
            if line.contains("\"event\":\"fstrim_failed\"") {
                let rec: Value = serde_json::from_str(line).unwrap();
                let mp = rec["mountpoint"].as_str().unwrap();
                let err = rec["error"].as_str().unwrap();
                assert!(
                    mp.len() <= MAX_FSTRIM_LOG_FIELD_BYTES,
                    "fstrim_failed mountpoint exceeded {MAX_FSTRIM_LOG_FIELD_BYTES} bytes (got {})",
                    mp.len()
                );
                assert!(
                    err.len() <= MAX_FSTRIM_LOG_FIELD_BYTES,
                    "fstrim_failed error exceeded {MAX_FSTRIM_LOG_FIELD_BYTES} bytes (got {})",
                    err.len()
                );
                assert!(
                    line.len() <= 4096,
                    "fstrim_failed record exceeded bound ({} bytes): {}",
                    line.len(),
                    &line[..line.len().min(200)]
                );
            }
        }
    }

    #[tokio::test]
    async fn fstrim_failed_record_is_bounded_even_with_many_unreachable_aliases() {
        use tracing::instrument::WithSubscriber;

        #[derive(Clone, Default)]
        struct Sink(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // One superblock (8:2) with 120 unreachable bind aliases would produce
        // a multi-kilobyte `err.detail` string if logged unbounded.
        let mut table = String::from("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n");
        let kernel = Arc::new(FakeKernel::new());
        let seg = "alias_segment_".repeat(5);
        for i in 0..120u32 {
            let mp = format!("/{seg}_{i}");
            table.push_str(&format!("{} 1 8:2 / {mp} rw - ext4 /dev/sdb1 rw\n", i + 2));
            kernel.script_open_error(&mp, Errno::ENOENT);
        }

        let sink = Sink::default();
        let router = Router::new(Box::new(sink.clone()));
        let ctx = Arc::new(
            Context::new(
                Arc::new(Config::default()),
                Arc::new(FreezeStateMachine::starting_in(FreezeState::Thawed)),
                router.clone(),
                crate::marker::Marker::for_tests(),
            )
            .with_kernel(kernel)
            .with_mounts(Arc::new(StaticMounts(table))),
        );
        let dispatch = tracing::Dispatch::new(crate::audit::subscriber(
            tracing::Level::WARN,
            router.clone(),
        ));
        let value = handle(&ctx, &req(r#"{"execute":"guest-fstrim"}"#))
            .with_subscriber(dispatch)
            .await
            .unwrap();
        assert_eq!(
            value["paths"][1]["error"],
            "target unreachable; no FITRIM issued"
        );
        assert!(router.settle(std::time::Duration::from_secs(1)));
        let logs = String::from_utf8(sink.0.lock().unwrap().clone()).unwrap();
        let failed_lines: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("\"event\":\"fstrim_failed\""))
            .collect();
        assert_eq!(failed_lines.len(), 1, "{logs}");
        let rec: Value = serde_json::from_str(failed_lines[0]).unwrap();
        let mp = rec["mountpoint"].as_str().unwrap();
        let err = rec["error"].as_str().unwrap();
        assert!(
            mp.len() <= MAX_FSTRIM_LOG_FIELD_BYTES,
            "mountpoint field exceeded {MAX_FSTRIM_LOG_FIELD_BYTES} bytes (got {})",
            mp.len()
        );
        assert!(
            err.len() <= MAX_FSTRIM_LOG_FIELD_BYTES,
            "error field exceeded {MAX_FSTRIM_LOG_FIELD_BYTES} bytes (got {})",
            err.len()
        );
        assert!(
            err.ends_with("bytes total)"),
            "truncated error field should keep its truncation suffix: {err}"
        );
        assert!(
            failed_lines[0].len() <= 4096,
            "fstrim_failed record with 120 aliases must stay bounded (got {} bytes)",
            failed_lines[0].len()
        );
    }

    #[test]
    fn bound_log_field_counts_truncation_suffix_and_preserves_utf8_boundaries() {
        let exact = "x".repeat(MAX_FSTRIM_LOG_FIELD_BYTES);
        let kept = bound_log_field(&exact, MAX_FSTRIM_LOG_FIELD_BYTES);
        assert_eq!(kept.as_ref(), exact);
        assert_eq!(kept.len(), MAX_FSTRIM_LOG_FIELD_BYTES);

        let over_ascii = "a".repeat(MAX_FSTRIM_LOG_FIELD_BYTES + 1);
        let bounded = bound_log_field(&over_ascii, MAX_FSTRIM_LOG_FIELD_BYTES);
        assert!(
            bounded.len() <= MAX_FSTRIM_LOG_FIELD_BYTES,
            "emitted field {} exceeded limit {MAX_FSTRIM_LOG_FIELD_BYTES}",
            bounded.len()
        );
        assert!(bounded.ends_with("... (truncated, 1025 bytes total)"));

        // 4-byte UTF-8 characters crossing the post-suffix budget boundary.
        let over_utf8 = "🦀".repeat(400);
        let bounded_utf8 = bound_log_field(&over_utf8, MAX_FSTRIM_LOG_FIELD_BYTES);
        assert!(bounded_utf8.len() <= MAX_FSTRIM_LOG_FIELD_BYTES);
        assert!(bounded_utf8.ends_with("... (truncated, 1600 bytes total)"));
        assert!(bounded_utf8.starts_with('🦀'));

        // Tiny limit smaller than the suffix still never exceeds max_bytes.
        let tiny = bound_log_field("🦀🦀🦀", 7);
        assert!(tiny.len() <= 7);
        assert_eq!(tiny.as_ref(), "🦀");
    }

    #[test]
    fn trim_plan_entries_retain_typed_outcomes_and_match_qga_formatting() {
        let table = "\
1 0 8:1 / / rw - ext4 /dev/sda1 rw
2 1 8:2 / /a rw - ext4 /dev/sdb1 rw
3 1 8:3 / /b rw - ext4 /dev/sdc1 rw
4 1 8:4 / /c rw - ext4 /dev/sdd1 rw
";
        let plan = FreezePlan::build(&crate::mountinfo::parse_mountinfo(table));
        let kernel = FakeKernel::new();
        kernel.script_trim("/", Ok(4096));
        kernel.script_open_error("/a", Errno::EACCES);
        kernel.script_open_error("/b", Errno::ENOENT);
        kernel.script_trim("/c", Err(Errno::EOPNOTSUPP));

        let entries = trim_plan_entries(&kernel, &plan, 512);
        assert_eq!(
            entries,
            vec![
                TrimEntry {
                    path: "/".to_owned(),
                    outcome: TrimPathOutcome::Trimmed {
                        trimmed: 4096,
                        minimum: 512,
                    },
                },
                TrimEntry {
                    path: "/a".to_owned(),
                    outcome: TrimPathOutcome::OpenPermissionDenied,
                },
                TrimEntry {
                    path: "/b".to_owned(),
                    outcome: TrimPathOutcome::TargetUnreachable,
                },
                TrimEntry {
                    path: "/c".to_owned(),
                    outcome: TrimPathOutcome::IoctlErrno(Errno::EOPNOTSUPP as i32),
                },
            ]
        );
        let rendered = TrimResponse {
            paths: entries.iter().map(TrimEntry::to_result).collect(),
        };
        assert_eq!(rendered, trim_plan(&kernel, &plan, 512));
    }
}
