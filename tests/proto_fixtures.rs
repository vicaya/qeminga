//! Round-trips the wire-format fixtures in `tests/fixtures/qga/` through
//! the `proto` module (T1.1 "done when").
#![forbid(unsafe_code)]
// Integration tests may unwrap freely (AGENTS.md); clippy's test allowance
// only covers `#[test]` functions, not their helpers.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use qeminga::proto::{Error, ErrorClass, Request, Response, parse_request};
use serde_json::json;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/qga")
}

fn fixtures_with_prefix(prefix: &str) -> Vec<(String, Vec<u8>)> {
    let mut out: Vec<(String, Vec<u8>)> = fs::read_dir(fixture_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(prefix) && name.ends_with(".json"))
        })
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&path).unwrap())
        })
        .collect();
    out.sort();
    assert!(!out.is_empty(), "no fixtures with prefix {prefix}");
    out
}

#[test]
fn ok_request_fixtures_parse() {
    for (name, bytes) in fixtures_with_prefix("request_ok_") {
        let req: Request = parse_request(&bytes).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert!(req.method.starts_with("guest-"), "{name}: {req:?}");
    }
}

#[test]
fn bad_request_fixtures_are_generic_errors() {
    for (name, bytes) in fixtures_with_prefix("request_bad_") {
        let err = parse_request(&bytes).expect_err(&name);
        assert!(matches!(err, Error::InvalidRequest(_)), "{name}: {err:?}");
        assert_eq!(err.class(), ErrorClass::GenericError, "{name}");
    }
}

#[test]
fn response_fixtures_match_serialisation() {
    let cases = [
        (
            "response_success_ping_id42.json",
            Response::from_result(Some(42), Ok(json!({}))),
        ),
        (
            "response_success_sync_no_id.json",
            Response::from_result(None, Ok(json!(123))),
        ),
        (
            "response_error_command_not_found.json",
            Response::from_result(None, Err(Error::CommandNotFound("guest-exec".into()))),
        ),
        (
            "response_error_frozen_id1.json",
            Response::from_result(Some(1), Err(Error::Frozen)),
        ),
    ];
    for (file, response) in cases {
        let expected = fs::read(fixture_dir().join(file)).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&response.to_json()),
            String::from_utf8_lossy(&expected),
            "{file}"
        );
    }
}

#[test]
fn sync_fixture_arguments_decode() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SyncArgs {
        id: i64,
    }
    let bytes = fs::read(fixture_dir().join("request_ok_sync_with_id.json")).unwrap();
    let req = parse_request(&bytes).unwrap();
    let args: SyncArgs = qeminga::proto::arguments(&req).unwrap();
    assert_eq!(args.id, 7);
    assert_eq!(req.id, Some(42));
}
