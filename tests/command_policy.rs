//! Independent command-policy verification against the public dispatcher,
//! `guest-info`, and queued session execution (#64, design §3.1, §5.1, §5.3,
//! §5.7, §5.9).
//!
//! Uses a hand-written expected command list (independent of `Command::ALL`
//! and `SUPPORTED_COMMANDS`) across the shipped CVM and general-VM profiles
//! plus mixed feature opt-ins, in both `Thawed` and `Frozen` states, and
//! through queued requests behind an in-flight freeze. Run with default
//! features (`!suspend_ram`) and with `--all-features` (`suspend_ram`).
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qeminga::audit::{self, Router};
use qeminga::channel::{self, run_session_until};
use qeminga::config::Config;
use qeminga::dispatch::{Context, Dispatcher, reason};
use qeminga::framing::{DecodeEvent, FrameDecoder};
use qeminga::freeze_op::ManualClock;
use qeminga::handlers::Command;
use qeminga::handlers::info::agent_info;
use qeminga::handlers::suspend::SuspendOps;
use qeminga::kernel::fake::FakeKernel;
use qeminga::marker::Marker;
use qeminga::mountinfo::StaticMounts;
use qeminga::proto::Error;
use qeminga::state::{FreezeState, FreezeStateMachine};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::Level;
use tracing::instrument::WithSubscriber;

/// Independent expected specification for each of the 14 commands in design §3.
#[derive(Clone, Copy)]
struct Expected {
    name: &'static str,
    success_response: bool,
    frozen_safe: bool,
    sentinel: bool,
    payload: &'static str,
}

const EXPECTED_COMMANDS: &[Expected] = &[
    Expected {
        name: "guest-ping",
        success_response: true,
        frozen_safe: true,
        sentinel: false,
        payload: r#"{"execute":"guest-ping"}"#,
    },
    Expected {
        name: "guest-info",
        success_response: true,
        frozen_safe: true,
        sentinel: false,
        payload: r#"{"execute":"guest-info"}"#,
    },
    Expected {
        name: "guest-sync",
        success_response: true,
        frozen_safe: true,
        sentinel: false,
        payload: r#"{"execute":"guest-sync","arguments":{"id":1}}"#,
    },
    Expected {
        name: "guest-sync-delimited",
        success_response: true,
        frozen_safe: true,
        sentinel: true,
        payload: r#"{"execute":"guest-sync-delimited","arguments":{"id":2}}"#,
    },
    Expected {
        name: "guest-get-osinfo",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-get-osinfo"}"#,
    },
    Expected {
        name: "guest-network-get-interfaces",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-network-get-interfaces"}"#,
    },
    Expected {
        name: "guest-get-fsinfo",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-get-fsinfo"}"#,
    },
    Expected {
        name: "guest-fsfreeze-status",
        success_response: true,
        frozen_safe: true,
        sentinel: false,
        payload: r#"{"execute":"guest-fsfreeze-status"}"#,
    },
    Expected {
        name: "guest-fsfreeze-freeze",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-fsfreeze-freeze"}"#,
    },
    Expected {
        name: "guest-fsfreeze-freeze-list",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/"]}}"#,
    },
    Expected {
        name: "guest-fsfreeze-thaw",
        success_response: true,
        frozen_safe: true,
        sentinel: false,
        payload: r#"{"execute":"guest-fsfreeze-thaw"}"#,
    },
    Expected {
        name: "guest-fstrim",
        success_response: true,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-fstrim"}"#,
    },
    Expected {
        name: "guest-shutdown",
        success_response: false,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-shutdown"}"#,
    },
    Expected {
        name: "guest-suspend-ram",
        success_response: false,
        frozen_safe: false,
        sentinel: false,
        payload: r#"{"execute":"guest-suspend-ram"}"#,
    },
];

/// Independent denied/unknown methods that must never enter `guest-info` or
/// invoke any handler.
const PROHIBITED_UNKNOWN: &[&str] = &[
    "guest-exec",
    "guest-file-open",
    "guest-set-user-password",
    "guest-ssh-add-authorized-keys",
    "guest-get-users",
    "guest-network-get-route",
    "guest-suspend-disk",
    "guest-unknown-method",
];

fn expected_enabled(name: &str, config: &Config) -> bool {
    match name {
        "guest-ping"
        | "guest-info"
        | "guest-sync"
        | "guest-sync-delimited"
        | "guest-fsfreeze-status"
        | "guest-fsfreeze-freeze"
        | "guest-fsfreeze-freeze-list"
        | "guest-fsfreeze-thaw" => true,
        "guest-get-osinfo" | "guest-network-get-interfaces" | "guest-get-fsinfo" => {
            config.features.information
        }
        "guest-fstrim" => config.features.fstrim,
        "guest-shutdown" => config.features.shutdown,
        "guest-suspend-ram" => cfg!(feature = "suspend_ram") && config.features.suspend_ram,
        other => panic!("unexpected command in test matrix: {other}"),
    }
}

#[derive(Clone, Default)]
struct SharedSink(Arc<Mutex<Vec<u8>>>);

impl SharedSink {
    fn records(&self) -> Vec<Value> {
        let bytes = self.0.lock().unwrap().clone();
        String::from_utf8(bytes)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Value>(l).unwrap())
            .filter(|v| v["event"] == audit::EVENT_COMMAND_RECEIVED)
            .collect()
    }
}

impl Write for SharedSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct FakeSuspend;

impl SuspendOps for FakeSuspend {
    fn supported_states(&self) -> Result<String, Error> {
        Ok("freeze mem disk".to_owned())
    }
    fn enter(&self, _state: &str) -> Result<(), Error> {
        Ok(())
    }
}

fn read_repo(rel: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)).unwrap()
}

fn build_context(
    config: Config,
    state: FreezeState,
) -> (Arc<Context>, SharedSink, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    let mounts = read_repo("tests/fixtures/mountinfo/simple.txt");
    let ctx = Arc::new(
        Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            router,
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(Arc::new(FakeKernel::new()))
        .with_mounts(Arc::new(StaticMounts(mounts)))
        .with_suspend(Arc::new(FakeSuspend)),
    );
    (ctx, sink, dir)
}

async fn dispatch_one(dispatcher: &Dispatcher, payload: &str) -> Option<Vec<u8>> {
    let router = dispatcher.context().audit.clone();
    dispatcher
        .handle(DecodeEvent::Frame {
            bytes: payload.as_bytes().to_vec(),
            sentinel: false,
        })
        .with_subscriber(audit::subscriber(Level::TRACE, router))
        .await
}

fn decode_reply(raw: &[u8], expect_sentinel: bool) -> Value {
    assert_eq!(raw.last(), Some(&b'\n'));
    let body = if expect_sentinel {
        assert_eq!(raw.first(), Some(&0xFF), "missing 0xFF sentinel");
        &raw[1..raw.len() - 1]
    } else {
        assert_ne!(raw.first(), Some(&0xFF), "unexpected 0xFF sentinel");
        &raw[..raw.len() - 1]
    };
    serde_json::from_slice(body).unwrap()
}

fn profile_matrix() -> Vec<(&'static str, Config)> {
    vec![
        (
            "cvm-data-protection",
            Config::parse(&read_repo("packaging/config-data-protection.toml")).unwrap(),
        ),
        (
            "general-vm-lifecycle",
            Config::parse(&read_repo("packaging/config.toml")).unwrap(),
        ),
        (
            "mixed-info-and-suspend",
            Config::parse(
                "[features]\ninformation = true\nshutdown = false\nfstrim = false\nsuspend_ram = true\n",
            )
            .unwrap(),
        ),
        (
            "mixed-trim-and-shutdown",
            Config::parse(
                "[features]\ninformation = false\nshutdown = true\nfstrim = true\nsuspend_ram = false\n",
            )
            .unwrap(),
        ),
        (
            "mixed-suspend-only",
            Config::parse(
                "[features]\ninformation = false\nshutdown = false\nfstrim = false\nsuspend_ram = true\n",
            )
            .unwrap(),
        ),
        (
            "all-enabled",
            Config::parse(
                "[features]\ninformation = true\nshutdown = true\nfstrim = true\nsuspend_ram = true\n",
            )
            .unwrap(),
        ),
    ]
}

#[tokio::test]
async fn unified_policy_matches_independent_matrix_across_profiles_and_freeze_states() {
    for (profile_name, config) in profile_matrix() {
        let authority = config.authority();
        let advertised = agent_info(&config);

        // 1. `guest-info` and `Command::is_enabled` agree with the independent
        //    expected command list, and omit every prohibited/unknown command.
        assert_eq!(
            advertised.supported_commands.len(),
            EXPECTED_COMMANDS.len(),
            "{profile_name}"
        );
        for (entry, expected) in advertised
            .supported_commands
            .iter()
            .zip(EXPECTED_COMMANDS.iter())
        {
            let want_enabled = expected_enabled(expected.name, &config);
            assert_eq!(entry.name, expected.name, "{profile_name}");
            assert_eq!(
                entry.success_response, expected.success_response,
                "{profile_name} {}",
                expected.name
            );
            assert_eq!(
                entry.enabled, want_enabled,
                "{profile_name} {} guest-info mismatch",
                expected.name
            );
            let cmd = Command::from_method(expected.name).unwrap();
            assert_eq!(
                cmd.is_enabled(&authority),
                want_enabled,
                "{profile_name} {} Command::is_enabled mismatch",
                expected.name
            );
        }
        for unknown in PROHIBITED_UNKNOWN {
            assert!(Command::from_method(unknown).is_none(), "{unknown}");
            assert!(
                !advertised
                    .supported_commands
                    .iter()
                    .any(|c| c.name == *unknown),
                "{profile_name} must not advertise {unknown}"
            );
        }

        // 2. Public dispatcher in Thawed and Frozen states:
        //    - Every prohibited (disabled or unknown) command makes zero handler
        //      calls and answers CommandNotFound with exact QAPI description.
        //    - Disabled beats Frozen gate (error precedence, C-7).
        //    - `guest-info` still advertises the configured policy while Frozen
        //      (distinction between configured command vs freeze-gated command).
        for state in [FreezeState::Thawed, FreezeState::Frozen] {
            // Check prohibited methods first on a clean context to prove zero
            // handler invocations.
            let (ctx, sink, _dir) = build_context(config.clone(), state);
            let dispatcher = Dispatcher::new(Arc::clone(&ctx));
            let mut expected_audits = 0usize;

            for unknown in PROHIBITED_UNKNOWN {
                let raw = dispatch_one(&dispatcher, &format!(r#"{{"execute":"{unknown}"}}"#))
                    .await
                    .unwrap();
                let reply = decode_reply(&raw, false);
                assert_eq!(
                    reply["error"]["class"], "CommandNotFound",
                    "{profile_name} {state} {unknown}"
                );
                assert_eq!(
                    reply["error"]["desc"],
                    format!("The command {unknown} has not been found"),
                    "{profile_name} {state} {unknown}"
                );
                expected_audits += 1;
            }

            for expected in EXPECTED_COMMANDS {
                if expected_enabled(expected.name, &config) {
                    continue;
                }
                let raw = dispatch_one(&dispatcher, expected.payload).await.unwrap();
                let reply = decode_reply(&raw, expected.sentinel);
                assert_eq!(
                    reply["error"]["class"], "CommandNotFound",
                    "{profile_name} {state} {}",
                    expected.name
                );
                assert_eq!(
                    reply["error"]["desc"],
                    format!("command {} has been disabled", expected.name),
                    "{profile_name} {state} {}",
                    expected.name
                );
                expected_audits += 1;
            }

            assert_eq!(
                ctx.handler_calls(),
                0,
                "{profile_name} {state}: prohibited methods must invoke zero handlers"
            );
            assert!(ctx.audit.settle(Duration::from_secs(5)));
            let records = sink.records();
            assert_eq!(records.len(), expected_audits, "{profile_name} {state}");
            for rec in &records {
                assert_eq!(rec["disposition"], "denied");
                assert_eq!(rec["freeze_state_before"], state.as_str());
            }

            // Verify enabled commands obey freeze gate when Frozen while
            // `guest-info` preserves configured enablement.
            let (ctx, _sink, _dir) = build_context(config.clone(), state);
            let dispatcher = Dispatcher::new(Arc::clone(&ctx));
            let raw_info = dispatch_one(&dispatcher, r#"{"execute":"guest-info"}"#)
                .await
                .unwrap();
            let wire_info = decode_reply(&raw_info, false);
            for (wire_entry, expected) in wire_info["return"]["supported_commands"]
                .as_array()
                .unwrap()
                .iter()
                .zip(EXPECTED_COMMANDS.iter())
            {
                assert_eq!(
                    wire_entry["enabled"],
                    expected_enabled(expected.name, &config),
                    "{profile_name} {state} guest-info must reflect configured policy, not freeze gate"
                );
            }

            for expected in EXPECTED_COMMANDS {
                if !expected_enabled(expected.name, &config) {
                    continue;
                }
                // Fresh context per enabled command so freeze/thaw transitions
                // don't disturb later checks.
                let (cmd_ctx, _s, _d) = build_context(config.clone(), state);
                let cmd_disp = Dispatcher::new(Arc::clone(&cmd_ctx));
                let raw = dispatch_one(&cmd_disp, expected.payload).await;
                if state != FreezeState::Thawed && !expected.frozen_safe {
                    let reply = decode_reply(raw.as_ref().unwrap(), expected.sentinel);
                    assert_eq!(
                        reply["error"]["class"], "GenericError",
                        "{profile_name} {state} {}",
                        expected.name
                    );
                    assert_eq!(
                        reply["error"]["desc"], "filesystems are frozen; retry after thaw",
                        "{profile_name} {state} {}",
                        expected.name
                    );
                    assert_eq!(
                        cmd_ctx.handler_calls(),
                        0,
                        "{profile_name} {state} {} barred by freeze gate must not invoke handler",
                        expected.name
                    );
                } else {
                    assert_eq!(
                        cmd_ctx.handler_calls(),
                        1,
                        "{profile_name} {state} {} should invoke handler",
                        expected.name
                    );
                    if expected.success_response {
                        let reply = decode_reply(raw.as_ref().unwrap(), expected.sentinel);
                        assert!(
                            reply.get("return").is_some(),
                            "{profile_name} {state} {}: {reply}",
                            expected.name
                        );
                    } else {
                        assert!(
                            raw.is_none(),
                            "{profile_name} {state} {} must suppress success reply",
                            expected.name
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_requests_apply_live_gates_at_admission_with_zero_prohibited_handler_calls() {
    // Queue multiple prohibited commands AND a configured non-frozen-safe
    // command (`guest-fstrim`) behind an in-flight freeze under a mixed
    // profile where `fstrim = true` and `information = false`, `shutdown = false`,
    // `suspend_ram = false`.
    //
    // While the freeze is blocked inside `FIFREEZE`:
    // - The queued serial commands wait in the session queue without running.
    // - Once the freeze completes and publishes `Frozen`, the lane admits each
    //   queued serial command one by one and evaluates gates LIVE:
    //   - disabled `guest-get-osinfo`, `guest-shutdown`, `guest-suspend-ram`
    //     get `CommandNotFound` ("has been disabled") — disabled beats frozen,
    //     zero handler calls.
    //   - unknown `guest-exec` gets `CommandNotFound` ("not been found") — zero
    //     handler calls.
    //   - enabled `guest-fstrim` (queued while Thawed!) sees the LIVE `Frozen`
    //     state on admission and gets `GenericError` ("filesystems are frozen;
    //     retry after thaw") with `freeze_state_before = "frozen"` and zero
    //     handler calls.
    let config = Config::parse(
        "[features]\ninformation = false\nshutdown = false\nfstrim = true\nsuspend_ram = false\n",
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(FakeKernel::new());
    let gate = kernel.script_freeze_gate("/home");
    let _release = gate.release_on_drop();

    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    let clock = ManualClock::new();
    let ctx = Arc::new(
        Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel.clone())
        .with_mounts(Arc::new(StaticMounts(read_repo(
            "tests/fixtures/mountinfo/simple.txt",
        ))))
        .with_freeze_clock(Arc::new(clock))
        .with_freeze_operation_timeout(Duration::from_secs(30)),
    );

    let (mut peer, ours) = tokio::io::duplex(16 * 1024);
    let (reader, writer) = tokio::io::split(ours);
    let (_cancel_tx, mut cancel_rx) = channel::cancel_pair();
    let dispatcher = Dispatcher::new(Arc::clone(&ctx));
    let sub = audit::subscriber(Level::TRACE, router);
    let session = tokio::spawn(
        async move {
            let mut decoder = FrameDecoder::new();
            run_session_until(reader, writer, &dispatcher, &mut decoder, &mut cancel_rx).await
        }
        .with_subscriber(sub),
    );

    // Send the freeze first, wait until its worker is blocked inside FIFREEZE.
    peer.write_all(b"{\"execute\":\"guest-fsfreeze-freeze\",\"id\":1}\n")
        .await
        .unwrap();
    let start = std::time::Instant::now();
    while gate.waiting() == 0 {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for freeze gate"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(ctx.handler_calls(), 1, "only the freeze handler is running");

    // Queue 5 serial requests behind the blocked freeze (total 6 <= MAX_QUEUED=8).
    let queued = concat!(
        "{\"execute\":\"guest-get-osinfo\",\"id\":2}\n",
        "{\"execute\":\"guest-shutdown\",\"id\":3}\n",
        "{\"execute\":\"guest-suspend-ram\",\"id\":4}\n",
        "{\"execute\":\"guest-exec\",\"id\":5}\n",
        "{\"execute\":\"guest-fstrim\",\"id\":6}\n",
    );
    peer.write_all(queued.as_bytes()).await.unwrap();
    peer.flush().await.unwrap();
    // Give the session loop a chance to read and queue every frame.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        ctx.handler_calls(),
        1,
        "queued serial commands must not execute before admission"
    );

    // Release the freeze so it finishes and transitions to Frozen, then wait
    // for all 6 replies (freeze + 5 queued serial commands) before thawing so
    // the thaw lane cannot overtake `guest-fstrim`.
    gate.release();

    async fn read_reply(peer: &mut tokio::io::DuplexStream) -> Value {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(10), peer.read(&mut byte))
                .await
                .expect("reply within 10 s")
                .unwrap();
            assert_eq!(n, 1, "peer closed early");
            if byte[0] == b'\n' {
                let body = line.strip_prefix(&[0xFF]).unwrap_or(&line);
                return serde_json::from_slice(body).unwrap();
            }
            line.push(byte[0]);
        }
    }

    let mut replies = Vec::new();
    for _ in 0..6 {
        replies.push(read_reply(&mut peer).await);
    }

    peer.write_all(b"{\"execute\":\"guest-fsfreeze-thaw\",\"id\":7}\n")
        .await
        .unwrap();
    replies.push(read_reply(&mut peer).await);
    peer.shutdown().await.unwrap();
    let _report = session.await.unwrap();

    assert_eq!(replies.len(), 7, "{replies:?}");

    assert_eq!(replies[0]["id"], 1);
    assert_eq!(replies[0]["return"], 2);

    // Queued disabled commands: CommandNotFound ("has been disabled") beats Frozen gate.
    for (idx, (id, name)) in [
        (2, "guest-get-osinfo"),
        (3, "guest-shutdown"),
        (4, "guest-suspend-ram"),
    ]
    .into_iter()
    .enumerate()
    {
        let r = &replies[idx + 1];
        assert_eq!(r["id"], id, "{r}");
        assert_eq!(r["error"]["class"], "CommandNotFound", "{r}");
        assert_eq!(
            r["error"]["desc"],
            format!("command {name} has been disabled")
        );
    }

    // Queued unknown command: CommandNotFound ("not been found").
    assert_eq!(replies[4]["id"], 5);
    assert_eq!(replies[4]["error"]["class"], "CommandNotFound");
    assert_eq!(
        replies[4]["error"]["desc"],
        "The command guest-exec has not been found"
    );

    // Queued enabled `guest-fstrim`: evaluated LIVE at admission after freeze
    // published Frozen -> GenericError freeze gate!
    assert_eq!(replies[5]["id"], 6);
    assert_eq!(replies[5]["error"]["class"], "GenericError");
    assert_eq!(
        replies[5]["error"]["desc"],
        "filesystems are frozen; retry after thaw"
    );

    // Final thaw succeeds.
    assert_eq!(replies[6]["id"], 7);
    assert_eq!(replies[6]["return"], 2);

    // Exactly 2 handler calls total: the initial freeze (id 1) and the final thaw (id 7).
    // Zero handler calls for all 5 prohibited/gated queued commands!
    assert_eq!(ctx.handler_calls(), 2);

    assert!(ctx.audit.settle(Duration::from_secs(5)));
    let records = sink.records();
    assert_eq!(records.len(), 7, "{records:?}");
    let by_id = |id: i64| -> &Value {
        records
            .iter()
            .find(|r| r["id"].as_i64() == Some(id))
            .unwrap()
    };
    assert_eq!(by_id(2)["reason"], reason::DISABLED);
    assert_eq!(by_id(2)["freeze_state_before"], "frozen");
    assert_eq!(by_id(3)["reason"], reason::DISABLED);
    assert_eq!(by_id(3)["freeze_state_before"], "frozen");
    assert_eq!(by_id(4)["reason"], reason::DISABLED);
    assert_eq!(by_id(4)["freeze_state_before"], "frozen");
    assert_eq!(by_id(5)["reason"], reason::COMMAND_NOT_FOUND);
    assert_eq!(by_id(5)["freeze_state_before"], "frozen");
    assert_eq!(by_id(6)["reason"], reason::FROZEN);
    assert_eq!(by_id(6)["freeze_state_before"], "frozen");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_prohibited_commands_under_cvm_profile_never_invoke_handlers() {
    // Under the shipped CVM data-protection profile, queue every disabled
    // command + an unknown command while the session serves a control and
    // verify zero handler calls for every prohibited method.
    let config = Config::parse(&read_repo("packaging/config-data-protection.toml")).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let kernel = Arc::new(FakeKernel::new());
    let sink = SharedSink::default();
    let router = Router::new(Box::new(sink.clone()));
    let ctx = Arc::new(
        Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::new()),
            router.clone(),
            Marker::open(dir.path().join("frozen")).unwrap(),
        )
        .with_kernel(kernel)
        .with_mounts(Arc::new(StaticMounts(read_repo(
            "tests/fixtures/mountinfo/simple.txt",
        )))),
    );

    let (mut peer, ours) = tokio::io::duplex(16 * 1024);
    let (reader, writer) = tokio::io::split(ours);
    let (_cancel_tx, mut cancel_rx) = channel::cancel_pair();
    let dispatcher = Dispatcher::new(Arc::clone(&ctx));
    let sub = audit::subscriber(Level::TRACE, router);
    let session = tokio::spawn(
        async move {
            let mut decoder = FrameDecoder::new();
            run_session_until(reader, writer, &dispatcher, &mut decoder, &mut cancel_rx).await
        }
        .with_subscriber(sub),
    );

    // Send every CVM-disabled command plus a denied unknown command in one batch.
    let batch = concat!(
        "{\"execute\":\"guest-get-osinfo\",\"id\":1}\n",
        "{\"execute\":\"guest-network-get-interfaces\",\"id\":2}\n",
        "{\"execute\":\"guest-get-fsinfo\",\"id\":3}\n",
        "{\"execute\":\"guest-fstrim\",\"id\":4}\n",
        "{\"execute\":\"guest-shutdown\",\"id\":5}\n",
        "{\"execute\":\"guest-suspend-ram\",\"id\":6}\n",
        "{\"execute\":\"guest-exec\",\"id\":7}\n",
    );
    peer.write_all(batch.as_bytes()).await.unwrap();
    peer.shutdown().await.unwrap();

    let mut buf = Vec::new();
    peer.read_to_end(&mut buf).await.unwrap();
    let _report = session.await.unwrap();

    let replies: Vec<Value> = String::from_utf8(buf)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(replies.len(), 7, "{replies:?}");
    for (idx, name) in [
        "guest-get-osinfo",
        "guest-network-get-interfaces",
        "guest-get-fsinfo",
        "guest-fstrim",
        "guest-shutdown",
        "guest-suspend-ram",
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(replies[idx]["id"], (idx + 1) as i64);
        assert_eq!(replies[idx]["error"]["class"], "CommandNotFound");
        assert_eq!(
            replies[idx]["error"]["desc"],
            format!("command {name} has been disabled")
        );
    }
    assert_eq!(replies[6]["id"], 7);
    assert_eq!(replies[6]["error"]["class"], "CommandNotFound");
    assert_eq!(
        replies[6]["error"]["desc"],
        "The command guest-exec has not been found"
    );
    assert_eq!(
        ctx.handler_calls(),
        0,
        "every queued prohibited command must make zero handler calls"
    );
}
