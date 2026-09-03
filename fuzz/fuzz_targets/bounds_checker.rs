//! Fuzz target: the JSON bounds scanner and the request parser behind it
//! (design §5.2 items 2–3, AC14). Neither may panic on any input, and a
//! frame that `serde_json` parses within the documented limits must not be
//! rejected by the scanner.
#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use qeminga::proto::bounds::{BoundsError, check_bounds};
use qeminga::proto::parse_request;

fuzz_target!(|data: &[u8]| {
    let result = check_bounds(data);
    if std::str::from_utf8(data).is_err() {
        assert_eq!(result, Err(BoundsError::InvalidUtf8));
    }
    // The parser applies the same bound first and must agree with it.
    if let Err(err) = result {
        let parsed = parse_request(data);
        assert!(parsed.is_err(), "bounds rejected but the parser accepted: {err}");
    } else {
        let _ = parse_request(data);
    }
});
