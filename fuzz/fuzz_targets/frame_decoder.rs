//! Fuzz target: the newline frame decoder (design §5.2 item 1, AC14).
//!
//! The first byte selects how the remaining input is split into pushes so
//! the chunking-transparency property is fuzzed too. Invariants checked
//! on every event: no frame exceeds `MAX_FRAME_LEN`, no frame contains a
//! delimiter or a sentinel, and the buffer never exceeds the bound.
#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use qeminga::framing::{DecodeEvent, FrameDecoder, MAX_FRAME_LEN, SENTINEL};

fuzz_target!(|data: &[u8]| {
    let Some((&chunk_selector, input)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk_selector).max(1) * 7;
    let mut decoder = FrameDecoder::new();
    let mut chunked = Vec::new();
    for piece in input.chunks(chunk) {
        chunked.extend(decoder.push(piece));
        assert!(decoder.buffered_len() <= MAX_FRAME_LEN);
    }
    let whole = FrameDecoder::new().push(input);
    assert_eq!(chunked, whole, "chunking must be transparent");
    for event in &whole {
        if let DecodeEvent::Frame { bytes, .. } = event {
            assert!(bytes.len() <= MAX_FRAME_LEN);
            assert!(!bytes.contains(&b'\n'));
            assert!(!bytes.contains(&SENTINEL));
        }
    }
    decoder.reset();
    assert_eq!(decoder.buffered_len(), 0);
});
