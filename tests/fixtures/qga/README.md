# QGA wire-format fixtures

Samples of the QEMU guest-agent (QMP-style) line protocol used by the
`proto` tests (`tests/proto_fixtures.rs`) and later by the end-to-end
harness. One JSON document per file, no trailing newline required.

| Prefix | Meaning |
|---|---|
| `request_ok_*.json` | Must parse as a `Request`. |
| `request_bad_*.json` | Must be rejected with `GenericError` (C-3). |
| `response_*.json` | Exact serialisation of a `Response` built in the test. |
