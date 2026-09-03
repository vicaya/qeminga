//! Drives the public dispatcher with the `sync*` wire fixtures in
//! `tests/fixtures/qga/` (T2.1 "done when").
#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use qeminga::audit::Router;
use qeminga::config::Config;
use qeminga::dispatch::{Context, Dispatcher};
use qeminga::framing::DecodeEvent;
use qeminga::kernel::fake::FakeKernel;
use qeminga::marker::Marker;
use qeminga::mountinfo::StaticMounts;
use qeminga::state::FreezeStateMachine;
use serde_json::{Value, json};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/qga")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// A dispatcher over fakes only: the freeze-list fixture names real
/// mountpoints, so the kernel shim, the mount table and the marker path
/// must never be the production ones here.
fn dispatcher() -> Dispatcher {
    let dir = tempfile::tempdir().unwrap();
    let ctx = Context::new(
        Arc::new(Config::default()),
        Arc::new(FreezeStateMachine::new()),
        Router::new(Box::new(std::io::sink())),
    )
    .with_kernel(Arc::new(FakeKernel::new()))
    .with_mounts(Arc::new(StaticMounts(String::new())))
    .with_marker(Marker::new(dir.keep().join("frozen")));
    Dispatcher::new(Arc::new(ctx))
}

async fn send(d: &Dispatcher, name: &str) -> Vec<u8> {
    d.handle(DecodeEvent::Frame {
        bytes: fixture(name),
        sentinel: false,
    })
    .await
    .expect("a reply")
}

fn json_of(reply: &[u8]) -> Value {
    let body = reply.strip_prefix(&[0xFF]).unwrap_or(reply);
    serde_json::from_slice(&body[..body.len() - 1]).unwrap()
}

#[tokio::test]
async fn sync_fixtures_round_trip() {
    let d = dispatcher();
    let reply = send(&d, "request_ok_sync_with_id.json").await;
    assert_eq!(reply, b"{\"return\":7,\"id\":42}\n");

    let reply = send(&d, "request_ok_sync_min_id.json").await;
    assert_eq!(json_of(&reply), json!({"return": i64::MIN, "id": 1}));
    assert_ne!(reply[0], 0xFF);

    let reply = send(&d, "request_ok_sync_delimited.json").await;
    assert_eq!(
        reply[0], 0xFF,
        "guest-sync-delimited replies start with 0xFF"
    );
    assert_eq!(json_of(&reply), json!({"return": 123456}));

    let reply = send(&d, "request_ok_sync_string_id_rejected_by_handler.json").await;
    assert_eq!(json_of(&reply)["error"]["class"], "GenericError");
}
