//! Nesting-depth and string-length bounds on raw frames (design §5.2
//! items 2–3, AC14).
//!
//! [`check_bounds`] is a single linear pass over the frame bytes that runs
//! *before* `serde_json`. It tracks the current container depth and the
//! length of the string being scanned; it does not validate the full JSON
//! grammar (serde does that afterwards), so a frame that passes here may
//! still be rejected as malformed.
//!
//! **String length is measured in raw bytes between the quotes, escapes
//! included.** `"é"` counts as 6 bytes, not 2. This is simpler than
//! decoding escapes, still a strict bound on memory (a decoded string is
//! never longer than its escaped form), and it bounds the work serde does
//! per string.
#![forbid(unsafe_code)]

/// Maximum number of simultaneously open arrays/objects.
pub const MAX_DEPTH: usize = 32;

/// Maximum length in bytes of one JSON string (key or value), measured on
/// the raw escaped bytes between the quotes.
pub const MAX_STRING_BYTES: usize = 4096;

/// A bound violation found by [`check_bounds`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BoundsError {
    /// More than [`MAX_DEPTH`] containers were open at once.
    #[error("JSON nesting deeper than {MAX_DEPTH} levels")]
    DepthExceeded,
    /// A string longer than [`MAX_STRING_BYTES`] was found.
    #[error("JSON string longer than {MAX_STRING_BYTES} bytes")]
    StringTooLong,
    /// The frame is not valid UTF-8.
    #[error("frame is not valid UTF-8")]
    InvalidUtf8,
}

/// Checks the depth, string-length, and UTF-8 bounds of one frame.
///
/// Runs in `O(len)` time with `O(1)` extra memory and never panics.
pub fn check_bounds(bytes: &[u8]) -> Result<(), BoundsError> {
    if std::str::from_utf8(bytes).is_err() {
        return Err(BoundsError::InvalidUtf8);
    }
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut string_len: usize = 0;
    for &b in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
                continue;
            }
            string_len = string_len.saturating_add(1);
            if string_len > MAX_STRING_BYTES {
                return Err(BoundsError::StringTooLong);
            }
            continue;
        }
        match b {
            b'"' => {
                in_string = true;
                string_len = 0;
            }
            b'[' | b'{' => {
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(BoundsError::DepthExceeded);
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nested_arrays(n: usize) -> Vec<u8> {
        let mut v = vec![b'['; n];
        v.extend(std::iter::repeat_n(b']', n));
        v
    }

    fn nested_objects(n: usize) -> Vec<u8> {
        let mut v = Vec::new();
        for _ in 0..n {
            v.extend_from_slice(b"{\"a\":");
        }
        v.push(b'1');
        v.extend(std::iter::repeat_n(b'}', n));
        v
    }

    #[test]
    fn depth_32_is_accepted() {
        assert_eq!(check_bounds(&nested_arrays(32)), Ok(()));
        assert_eq!(check_bounds(&nested_objects(32)), Ok(()));
        assert!(serde_json::from_slice::<serde_json::Value>(&nested_objects(32)).is_ok());
    }

    #[test]
    fn depth_33_is_rejected() {
        assert_eq!(
            check_bounds(&nested_arrays(33)),
            Err(BoundsError::DepthExceeded)
        );
        assert_eq!(
            check_bounds(&nested_objects(33)),
            Err(BoundsError::DepthExceeded)
        );
        // Depth is about simultaneously open containers, not total count.
        let mut sequential = b"[".to_vec();
        for _ in 0..100 {
            sequential.extend_from_slice(b"[],");
        }
        sequential.extend_from_slice(b"1]");
        assert_eq!(check_bounds(&sequential), Ok(()));
    }

    #[test]
    fn string_of_4096_bytes_is_accepted() {
        let mut v = b"{\"k\":\"".to_vec();
        v.extend(std::iter::repeat_n(b'x', 4096));
        v.extend_from_slice(b"\"}");
        assert_eq!(check_bounds(&v), Ok(()));
    }

    #[test]
    fn string_of_4097_bytes_is_rejected() {
        let mut v = b"{\"k\":\"".to_vec();
        v.extend(std::iter::repeat_n(b'x', 4097));
        v.extend_from_slice(b"\"}");
        assert_eq!(check_bounds(&v), Err(BoundsError::StringTooLong));
    }

    #[test]
    fn escaped_string_counts_raw_escaped_bytes() {
        // 2048 × `\"` = 4096 raw bytes (2048 decoded): accepted.
        let mut v = b"\"".to_vec();
        for _ in 0..2048 {
            v.extend_from_slice(b"\\\"");
        }
        v.push(b'"');
        assert_eq!(check_bounds(&v), Ok(()));
        // One more escape pair pushes the raw length to 4098: rejected even
        // though the decoded length (2049) is well under the limit.
        v.pop();
        v.extend_from_slice(b"\\\"\"");
        assert_eq!(check_bounds(&v), Err(BoundsError::StringTooLong));
        // An escaped quote does not terminate the string, and an escaped
        // backslash does not start an escape.
        assert_eq!(check_bounds(br#"{"a\"b":"c\\"}"#), Ok(()));
        assert_eq!(check_bounds(br#"["a\\","b"]"#), Ok(()));
    }

    #[test]
    fn brackets_inside_strings_do_not_count_as_depth() {
        let mut v = b"\"".to_vec();
        v.extend(std::iter::repeat_n(b'[', 100));
        v.push(b'"');
        assert_eq!(check_bounds(&v), Ok(()));
    }

    #[test]
    fn limits_apply_to_keys_too() {
        let mut v = b"{\"".to_vec();
        v.extend(std::iter::repeat_n(b'k', 4097));
        v.extend_from_slice(b"\":1}");
        assert_eq!(check_bounds(&v), Err(BoundsError::StringTooLong));
    }

    #[test]
    fn string_length_resets_between_strings() {
        let mut v = b"[".to_vec();
        for _ in 0..10 {
            v.push(b'"');
            v.extend(std::iter::repeat_n(b'x', 4000));
            v.extend_from_slice(b"\",");
        }
        v.extend_from_slice(b"1]");
        assert_eq!(check_bounds(&v), Ok(()));
    }

    #[test]
    fn invalid_utf8_is_rejected() {
        assert_eq!(
            check_bounds(b"{\"execute\":\"\xff\"}"),
            Err(BoundsError::InvalidUtf8)
        );
        assert_eq!(check_bounds(b"\xc3\x28"), Err(BoundsError::InvalidUtf8));
        assert_eq!(check_bounds("{\"é\":\"ü\"}".as_bytes()), Ok(()));
    }

    #[test]
    fn unbalanced_input_does_not_panic_or_underflow() {
        assert_eq!(check_bounds(b"]]]]]]]]}}}}}}}}"), Ok(()));
        assert_eq!(check_bounds(b"\"unterminated"), Ok(()));
        assert_eq!(check_bounds(b"\"trailing escape\\"), Ok(()));
        assert_eq!(check_bounds(b""), Ok(()));
    }

    #[test]
    fn checker_is_linear_time() {
        // 64 KiB of the most expensive shape: alternating string starts,
        // escapes, and brackets.
        let mut v = Vec::with_capacity(65_536);
        while v.len() < 65_536 {
            v.extend_from_slice(b"[\"\\\"\",");
        }
        let start = std::time::Instant::now();
        let _ = check_bounds(&v);
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_millis(10),
            "took {elapsed:?}"
        );
    }

    proptest! {
        #[test]
        fn checker_never_panics(input in prop::collection::vec(any::<u8>(), 0..8192)) {
            let _ = check_bounds(&input);
        }

        #[test]
        fn valid_json_within_bounds_is_accepted(depth in 0usize..=MAX_DEPTH, len in 0usize..=MAX_STRING_BYTES) {
            let mut v = vec![b'['; depth];
            v.push(b'"');
            v.extend(std::iter::repeat_n(b'a', len));
            v.push(b'"');
            v.extend(std::iter::repeat_n(b']', depth));
            prop_assert_eq!(check_bounds(&v), Ok(()));
            prop_assert!(serde_json::from_slice::<serde_json::Value>(&v).is_ok());
        }
    }
}
