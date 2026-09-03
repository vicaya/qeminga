//! Newline-delimited frame decoder/encoder with `0xFF` resynchronisation
//! (design §4.1 Frame Decoder, §5.2 item 1, §3 `guest-sync-delimited`,
//! §5.7; AC4, AC14; C-10).
//!
//! The decoder is a byte-level state machine with a hard buffer bound:
//!
//! - Bytes accumulate until `\n`; a frame that is empty or ASCII
//!   whitespace only is skipped.
//! - A frame longer than [`MAX_FRAME_LEN`] bytes puts the decoder into
//!   **discard-until-newline**: the buffered prefix is dropped, nothing is
//!   buffered any more, and one [`DecodeEvent::Oversized`] is reported when
//!   the delimiter is finally seen so the tail of the blob is never parsed
//!   as the next command (AC4).
//! - A `0xFF` sentinel anywhere in the stream drops everything buffered
//!   before it, leaves discard mode, and flags the next emitted frame with
//!   `sentinel: true` (C-10).
//!
//! The decoder never allocates proportionally to its input beyond
//! [`MAX_FRAME_LEN`] and never panics on any byte sequence; this module is
//! the first fuzz target (T5.1).
#![forbid(unsafe_code)]

/// Maximum length of one frame in bytes, excluding the delimiter (§5.2).
pub const MAX_FRAME_LEN: usize = 65_536;

/// The resynchronisation sentinel used by `guest-sync-delimited`.
pub const SENTINEL: u8 = 0xFF;

/// One decoding outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeEvent {
    /// A complete frame (without its `\n`).
    Frame {
        /// The raw frame bytes, at most [`MAX_FRAME_LEN`] long.
        bytes: Vec<u8>,
        /// `true` when a `0xFF` sentinel preceded this frame.
        sentinel: bool,
    },
    /// An oversized frame was discarded up to the next delimiter.
    Oversized {
        /// Number of bytes dropped, excluding the delimiter.
        discarded: usize,
    },
}

/// Incremental frame decoder. See the module documentation for the rules.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    /// Bytes of the frame in progress; never longer than `MAX_FRAME_LEN`.
    buf: Vec<u8>,
    /// `true` while dropping the remainder of an oversized frame.
    discarding: bool,
    /// Bytes dropped so far in the current oversized frame.
    discarded: usize,
    /// A sentinel was seen; the next emitted frame carries the flag.
    sentinel_pending: bool,
}

impl FrameDecoder {
    /// Creates an empty decoder in normal mode.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds bytes into the decoder and returns the events they complete,
    /// in stream order. Splitting the input into chunks in any way yields
    /// the same events as feeding it at once.
    pub fn push(&mut self, mut input: &[u8]) -> Vec<DecodeEvent> {
        let mut events = Vec::new();
        while !input.is_empty() {
            let pos = input.iter().position(|&b| b == b'\n' || b == SENTINEL);
            let (data, delimiter, rest) = match pos {
                Some(p) => (&input[..p], Some(input[p]), &input[p + 1..]),
                None => (input, None, &input[input.len()..]),
            };
            self.consume_data(data);
            match delimiter {
                Some(b'\n') => self.end_of_frame(&mut events),
                Some(_) => self.sentinel(&mut events),
                None => {}
            }
            input = rest;
        }
        events
    }

    /// Drops any partial frame and discard/sentinel state (used after a
    /// channel reconnect, §5.7). Frames already returned are unaffected.
    pub fn reset(&mut self) {
        self.buf.clear();
        self.discarding = false;
        self.discarded = 0;
        self.sentinel_pending = false;
    }

    /// Number of bytes currently buffered (bounded by [`MAX_FRAME_LEN`]).
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// `true` while the decoder is dropping an oversized frame.
    pub fn is_discarding(&self) -> bool {
        self.discarding
    }

    /// Appends delimiter-free bytes, switching to discard mode instead of
    /// growing past the bound.
    fn consume_data(&mut self, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        if self.discarding {
            self.discarded = self.discarded.saturating_add(data.len());
            return;
        }
        if self.buf.len().saturating_add(data.len()) > MAX_FRAME_LEN {
            self.discarding = true;
            self.discarded = self.buf.len().saturating_add(data.len());
            self.buf.clear();
        } else {
            self.buf.extend_from_slice(data);
        }
    }

    /// Handles a `\n`.
    fn end_of_frame(&mut self, events: &mut Vec<DecodeEvent>) {
        if self.discarding {
            events.push(DecodeEvent::Oversized {
                discarded: self.discarded,
            });
            self.discarding = false;
            self.discarded = 0;
            return;
        }
        if self.buf.iter().all(u8::is_ascii_whitespace) {
            self.buf.clear();
            return;
        }
        events.push(DecodeEvent::Frame {
            bytes: std::mem::take(&mut self.buf),
            sentinel: self.sentinel_pending,
        });
        self.sentinel_pending = false;
    }

    /// Handles a `0xFF` sentinel.
    fn sentinel(&mut self, events: &mut Vec<DecodeEvent>) {
        if self.discarding {
            events.push(DecodeEvent::Oversized {
                discarded: self.discarded,
            });
            self.discarding = false;
            self.discarded = 0;
        }
        self.buf.clear();
        self.sentinel_pending = true;
    }
}

/// Encodes one reply: an optional leading `0xFF` sentinel, the JSON bytes,
/// and the `\n` delimiter.
pub fn encode(json: &[u8], sentinel: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len() + 2);
    if sentinel {
        out.push(SENTINEL);
    }
    out.extend_from_slice(json);
    out.push(b'\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn frame(bytes: &[u8], sentinel: bool) -> DecodeEvent {
        DecodeEvent::Frame {
            bytes: bytes.to_vec(),
            sentinel,
        }
    }

    #[test]
    fn single_frame_is_emitted_without_delimiter() {
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(b"{}\n"), vec![frame(b"{}", false)]);
        assert_eq!(d.buffered_len(), 0);
    }

    #[test]
    fn partial_frame_is_held_until_newline() {
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(b"{\"exe"), vec![]);
        assert_eq!(d.buffered_len(), 5);
        assert_eq!(
            d.push(b"cute\":1}\n"),
            vec![frame(b"{\"execute\":1}", false)]
        );
    }

    #[test]
    fn multiple_frames_in_one_push() {
        let mut d = FrameDecoder::new();
        assert_eq!(
            d.push(b"{\"a\":1}\n{\"b\":2}\n{\"c\""),
            vec![frame(b"{\"a\":1}", false), frame(b"{\"b\":2}", false)]
        );
        assert_eq!(d.push(b":3}\n"), vec![frame(b"{\"c\":3}", false)]);
    }

    #[test]
    fn empty_and_whitespace_only_frames_are_skipped() {
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(b"\n\n  \t\r\n{}\n \n"), vec![frame(b"{}", false)]);
    }

    #[test]
    fn oversized_frame_enters_discard_until_newline() {
        let mut d = FrameDecoder::new();
        let blob = vec![b'x'; MAX_FRAME_LEN + 1];
        assert_eq!(d.push(&blob), vec![]);
        assert!(d.is_discarding());
        assert_eq!(d.buffered_len(), 0);
        // The tail of the blob (more bytes before the newline) is never
        // emitted; the next valid frame is.
        let mut tail = b"tail-of-blob".to_vec();
        tail.extend_from_slice(b"\n{}\n");
        assert_eq!(
            d.push(&tail),
            vec![
                DecodeEvent::Oversized {
                    discarded: MAX_FRAME_LEN + 1 + b"tail-of-blob".len()
                },
                frame(b"{}", false)
            ]
        );
        assert!(!d.is_discarding());
    }

    #[test]
    fn oversized_is_reported_once_even_across_many_chunks() {
        let mut d = FrameDecoder::new();
        let mut events = Vec::new();
        for _ in 0..10 {
            events.extend(d.push(&vec![b'y'; 10_000]));
        }
        events.extend(d.push(b"\n"));
        assert_eq!(events, vec![DecodeEvent::Oversized { discarded: 100_000 }]);
    }

    #[test]
    fn exactly_max_len_frame_is_accepted() {
        let mut d = FrameDecoder::new();
        let mut exact = vec![b'a'; MAX_FRAME_LEN];
        exact.push(b'\n');
        let events = d.push(&exact);
        assert_eq!(events.len(), 1);
        assert!(
            matches!(&events[0], DecodeEvent::Frame { bytes, sentinel: false } if bytes.len() == MAX_FRAME_LEN)
        );

        let mut d = FrameDecoder::new();
        let mut over = vec![b'a'; MAX_FRAME_LEN + 1];
        over.push(b'\n');
        assert_eq!(
            d.push(&over),
            vec![DecodeEvent::Oversized {
                discarded: MAX_FRAME_LEN + 1
            }]
        );
    }

    #[test]
    fn sentinel_discards_buffered_bytes_and_flags_next_frame() {
        let mut d = FrameDecoder::new();
        assert_eq!(
            d.push(b"garbage\xFF{\"a\":1}\n"),
            vec![frame(b"{\"a\":1}", true)]
        );
        // The flag is consumed by that frame only.
        assert_eq!(d.push(b"{}\n"), vec![frame(b"{}", false)]);
    }

    #[test]
    fn sentinel_flag_survives_skipped_empty_frames() {
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(b"\xFF\n\n{}\n"), vec![frame(b"{}", true)]);
    }

    #[test]
    fn sentinel_exits_discard_state() {
        let mut d = FrameDecoder::new();
        let blob = vec![b'x'; MAX_FRAME_LEN + 100];
        assert_eq!(d.push(&blob), vec![]);
        assert!(d.is_discarding());
        // No newline before the sentinel: the frame is still delivered.
        assert_eq!(
            d.push(b"\xFF{\"execute\":\"guest-sync-delimited\"}\n"),
            vec![
                DecodeEvent::Oversized {
                    discarded: MAX_FRAME_LEN + 100
                },
                frame(b"{\"execute\":\"guest-sync-delimited\"}", true)
            ]
        );
        assert!(!d.is_discarding());
    }

    #[test]
    fn reset_drops_partial_frame() {
        let mut d = FrameDecoder::new();
        assert_eq!(d.push(b"{\"partial"), vec![]);
        d.reset();
        assert_eq!(d.buffered_len(), 0);
        assert_eq!(d.push(b"{}\n"), vec![frame(b"{}", false)]);

        // Reset also leaves discard mode and clears a pending sentinel.
        d.push(&vec![b'z'; MAX_FRAME_LEN + 1]);
        d.push(b"\xFF");
        d.reset();
        assert!(!d.is_discarding());
        assert_eq!(d.push(b"{}\n"), vec![frame(b"{}", false)]);
    }

    #[test]
    fn encode_appends_newline() {
        assert_eq!(encode(br#"{"return":{}}"#, false), b"{\"return\":{}}\n");
    }

    #[test]
    fn encode_with_sentinel_prefixes_0xff() {
        let out = encode(br#"{"return":1}"#, true);
        assert_eq!(out[0], 0xFF);
        assert_eq!(&out[1..], b"{\"return\":1}\n");
    }

    fn decode_all(input: &[u8]) -> Vec<DecodeEvent> {
        FrameDecoder::new().push(input)
    }

    /// Arbitrary byte strings biased towards delimiters and sentinels so
    /// the interesting transitions are exercised, occasionally with runs
    /// long enough to overflow the frame bound.
    fn stream() -> impl Strategy<Value = Vec<u8>> {
        let byte = prop_oneof![
            4 => Just(b'\n'),
            2 => Just(SENTINEL),
            2 => Just(b' '),
            10 => any::<u8>(),
        ];
        prop_oneof![
            8 => prop::collection::vec(byte.clone(), 0..512),
            1 => (prop::collection::vec(byte, 0..64), 0usize..3).prop_map(|(mut v, n)| {
                v.extend(std::iter::repeat_n(b'q', MAX_FRAME_LEN + n));
                v.push(b'\n');
                v
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn chunking_is_transparent(input in stream(), cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8)) {
            let expected = decode_all(&input);
            let mut points: Vec<usize> = cuts.iter().map(|i| i.index(input.len() + 1)).collect();
            points.push(0);
            points.push(input.len());
            points.sort_unstable();
            points.dedup();
            let mut d = FrameDecoder::new();
            let mut got = Vec::new();
            for w in points.windows(2) {
                got.extend(d.push(&input[w[0]..w[1]]));
            }
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn buffer_never_exceeds_max_plus_one(chunks in prop::collection::vec(stream(), 1..4)) {
            let mut d = FrameDecoder::new();
            for chunk in chunks {
                for piece in chunk.chunks(777) {
                    d.push(piece);
                    prop_assert!(d.buffered_len() <= MAX_FRAME_LEN + 1);
                }
            }
        }

        #[test]
        fn decoder_never_panics(input in prop::collection::vec(any::<u8>(), 0..4096)) {
            let mut d = FrameDecoder::new();
            for event in d.push(&input) {
                if let DecodeEvent::Frame { bytes, .. } = event {
                    prop_assert!(bytes.len() <= MAX_FRAME_LEN);
                    prop_assert!(!bytes.contains(&b'\n'));
                    prop_assert!(!bytes.contains(&SENTINEL));
                }
            }
            d.reset();
        }

        #[test]
        fn encode_then_decode_round_trips(json in "[^\\n\\x{ff}]{0,200}", sentinel in any::<bool>()) {
            let wire = encode(json.as_bytes(), sentinel);
            let events = decode_all(&wire);
            if json.bytes().all(|b| b.is_ascii_whitespace()) {
                prop_assert!(events.is_empty());
            } else {
                prop_assert_eq!(events, vec![DecodeEvent::Frame { bytes: json.into_bytes(), sentinel }]);
            }
        }
    }
}
