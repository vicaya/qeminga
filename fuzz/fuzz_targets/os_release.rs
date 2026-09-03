//! Fuzz target: the `os-release(5)` parser (design §3, AC14). Never
//! panics; every emitted key is a valid identifier.
#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use qeminga::handlers::osinfo::parse_os_release;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let map = parse_os_release(&text);
    for key in map.keys() {
        assert!(!key.is_empty());
        assert!(key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'));
    }
});
