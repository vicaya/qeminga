//! Fuzz target: the typed binary IPC chunk decoder and stream assembler
//! (OQ-10 §4, #77).
//!
//! Feeds both single raw packets and length-delimited multi-packet streams
//! into both [`PeerRole::Executor`] and [`PeerRole::Parser`] assemblers.
//! Neither may panic on any input, concurrent stream counts and buffered byte
//! totals must stay strictly within documented caps, and every accepted
//! message must re-encode cleanly and round-trip identically.
#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use qeminga::ipc::{
    AssembledMessage, MAX_CONCURRENT_STREAMS, MAX_FSINFO_IPC_BYTES, MAX_PACKET_BYTES,
    MAX_REQUEST_PAYLOAD_BYTES, PeerRole, StreamAssembler, encode_request_chunks_with_id,
    encode_response_chunks,
};
use qeminga::kernel::ipc::RawPacket;

fn synthetic_packet(flags: u8, bytes: Vec<u8>) -> RawPacket {
    RawPacket {
        bytes,
        fds: Vec::new(),
        truncated: (flags & 0x01) != 0,
        cmsg_truncated: (flags & 0x02) != 0,
        control_message_count: usize::from((flags >> 2) & 0x03),
        non_rights_cmsgs: usize::from((flags >> 4) & 0x03),
        raw_controllen: if (flags & 0xFC) != 0 { 24 } else { 0 },
    }
}

fn check_round_trip(msg: AssembledMessage) {
    match msg {
        AssembledMessage::Request(req) => {
            let chunks = encode_request_chunks_with_id(
                req.session_gen,
                req.req_id,
                req.host_id,
                &req.request,
            )
            .expect("accepted request must re-encode within bounds");
            let mut verify = StreamAssembler::new(PeerRole::Executor);
            let mut decoded = None;
            for chunk in chunks {
                assert!(chunk.len() <= MAX_PACKET_BYTES);
                decoded = verify
                    .push(synthetic_packet(0, chunk))
                    .expect("re-encoded request chunks must be valid");
            }
            match decoded {
                Some(AssembledMessage::Request(round_tripped)) => {
                    assert_eq!(round_tripped, req);
                }
                other => panic!("expected re-encoded request, got {other:?}"),
            }
        }
        AssembledMessage::Response(resp) => {
            let chunks = encode_response_chunks(resp.session_gen, resp.req_id, &resp.response)
                .expect("accepted response must re-encode within bounds");
            if resp.channel_fd.is_none() {
                let mut verify = StreamAssembler::new(PeerRole::Parser);
                let mut decoded = None;
                for chunk in chunks {
                    assert!(chunk.len() <= MAX_PACKET_BYTES);
                    decoded = verify
                        .push(synthetic_packet(0, chunk))
                        .expect("re-encoded response chunks must be valid");
                }
                match decoded {
                    Some(AssembledMessage::Response(round_tripped)) => {
                        assert_eq!(round_tripped.session_gen, resp.session_gen);
                        assert_eq!(round_tripped.req_id, resp.req_id);
                        assert_eq!(round_tripped.response, resp.response);
                        assert!(round_tripped.channel_fd.is_none());
                    }
                    other => panic!("expected re-encoded response, got {other:?}"),
                }
            }
        }
    }
}

fn run_single(role: PeerRole, data: &[u8]) {
    let mut asm = StreamAssembler::new(role);
    if let Ok(Some(msg)) = asm.push(synthetic_packet(0, data.to_vec())) {
        check_round_trip(msg);
    }
    assert!(asm.active_streams() <= MAX_CONCURRENT_STREAMS);
}

fn run_stream(role: PeerRole, max_per_stream: usize, mut rest: &[u8]) {
    let mut asm = StreamAssembler::new(role);
    while rest.len() >= 3 {
        let pkt_flags = rest[0];
        let pkt_len = usize::from(u16::from_le_bytes([rest[1], rest[2]]));
        rest = &rest[3..];
        let take = pkt_len.min(rest.len());
        let body = rest[..take].to_vec();
        rest = &rest[take..];

        if let Ok(Some(msg)) = asm.push(synthetic_packet(pkt_flags, body)) {
            check_round_trip(msg);
        }
        assert!(asm.active_streams() <= MAX_CONCURRENT_STREAMS);
        assert!(asm.buffered_bytes() <= MAX_CONCURRENT_STREAMS * max_per_stream);
    }
}

fuzz_target!(|data: &[u8]| {
    run_single(PeerRole::Executor, data);
    run_single(PeerRole::Parser, data);
    run_stream(PeerRole::Executor, MAX_REQUEST_PAYLOAD_BYTES, data);
    run_stream(PeerRole::Parser, MAX_FSINFO_IPC_BYTES, data);
});
