//! QGA wire types and the error model (design §3, §4.3, §5.1, §9; C-1, C-2, C-3).
//!
//! The wire format is the QEMU guest-agent (QMP-style) JSON protocol, one
//! message per line:
//!
//! - request: `{"execute": "<name>", "arguments": {...}?, "id": <int>?}`
//! - success: `{"return": <value>, "id": <int>?}`
//! - error:   `{"error": {"class": "...", "desc": "..."}, "id": <int>?}`
//!
//! Only two QAPI error classes exist (C-2): [`ErrorClass::CommandNotFound`]
//! for non-allowlisted and runtime-disabled commands, and
//! [`ErrorClass::GenericError`] for everything else.
#![forbid(unsafe_code)]

pub mod bounds;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A parsed guest-agent request.
///
/// Only a JSON object is accepted (a derived `Deserialize` would also accept
/// a positional array). Unknown and duplicate top-level keys are rejected
/// (C-3); `arguments`, when present, must be an object; `id`, when present,
/// must be a JSON integer that fits `i64` and is echoed verbatim in the reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// The command name (`"execute"` on the wire).
    pub method: String,
    /// Command arguments, if any. Handlers decode them with [`arguments`].
    pub arguments: Option<Value>,
    /// Optional request id, echoed in the response.
    pub id: Option<i64>,
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RequestVisitor)
    }
}

struct RequestVisitor;

impl<'de> serde::de::Visitor<'de> for RequestVisitor {
    type Value = Request;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a request object with `execute`, optional `arguments` and `id`")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Request, A::Error> {
        use serde::de::Error as _;
        let mut method: Option<String> = None;
        let mut arguments: Option<Value> = None;
        let mut id: Option<i64> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "execute" => {
                    if method.is_some() {
                        return Err(A::Error::duplicate_field("execute"));
                    }
                    method = Some(map.next_value()?);
                }
                "arguments" => {
                    if arguments.is_some() {
                        return Err(A::Error::duplicate_field("arguments"));
                    }
                    // An explicit `null` is not "absent" (C-3): only an
                    // object is accepted.
                    let value: Value = map.next_value()?;
                    if !value.is_object() {
                        return Err(A::Error::custom("arguments must be an object"));
                    }
                    arguments = Some(value);
                }
                "id" => {
                    if id.is_some() {
                        return Err(A::Error::duplicate_field("id"));
                    }
                    // Only a JSON integer that fits i64 (C-3); `null`,
                    // floats, strings and out-of-range numbers are rejected.
                    let value: Value = map.next_value()?;
                    id = Some(
                        value
                            .as_i64()
                            .ok_or_else(|| A::Error::custom("id must be an integer"))?,
                    );
                }
                _ => {
                    return Err(A::Error::unknown_field(
                        &key,
                        &["execute", "arguments", "id"],
                    ));
                }
            }
        }
        Ok(Request {
            method: method.ok_or_else(|| A::Error::missing_field("execute"))?,
            arguments,
            id,
        })
    }
}

/// QAPI error classes used by qeminga (C-2). No other variants exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorClass {
    /// The command is not in the allowlist or is disabled at runtime.
    CommandNotFound,
    /// Any other failure, including rate limiting and the frozen gate.
    GenericError,
}

impl ErrorClass {
    /// The QAPI spelling of the class, as sent on the wire.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorClass::CommandNotFound => "CommandNotFound",
            ErrorClass::GenericError => "GenericError",
        }
    }
}

/// The `error` object of an error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    /// QAPI error class.
    pub class: ErrorClass,
    /// Human-readable description.
    pub desc: String,
}

/// Every way a request can fail before or inside a handler.
///
/// The mapping to the wire representation lives in a single place: the
/// [`From<&Error>`] implementation for [`ErrorBody`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The method is not in the static allowlist (design §5.1).
    #[error("The command {0} has not been found")]
    CommandNotFound(String),
    /// The method is allowlisted but disabled by configuration (C-2).
    #[error("command {0} has been disabled")]
    Disabled(String),
    /// The command is outside the frozen-safe set while frozen (§5.3).
    #[error("filesystems are frozen; retry after thaw")]
    Frozen,
    /// The per-class token bucket is exhausted (§5.3, C-2).
    #[error("rate limit exceeded for {class}")]
    RateLimited {
        /// Name of the exhausted command class.
        class: String,
    },
    /// The request could not be parsed as a request object (C-3).
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// The `arguments` object is missing, malformed, or has unknown keys.
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    /// A handler failed; the description is already safe to send.
    #[error("{0}")]
    Internal(String),
}

impl Error {
    /// The QAPI error class this error is reported under.
    pub const fn class(&self) -> ErrorClass {
        match self {
            Error::CommandNotFound(_) | Error::Disabled(_) => ErrorClass::CommandNotFound,
            Error::Frozen
            | Error::RateLimited { .. }
            | Error::InvalidRequest(_)
            | Error::InvalidArguments(_)
            | Error::Internal(_) => ErrorClass::GenericError,
        }
    }
}

impl From<&Error> for ErrorBody {
    fn from(err: &Error) -> Self {
        ErrorBody {
            class: err.class(),
            desc: err.to_string(),
        }
    }
}

impl From<Error> for ErrorBody {
    fn from(err: Error) -> Self {
        ErrorBody::from(&err)
    }
}

/// A reply to a request. Serialised with a fixed key order (`return`/`error`
/// first, then `id`); `id` is omitted when the request carried none.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Response {
    /// A successful reply.
    Success {
        /// The command's return value.
        #[serde(rename = "return")]
        ret: Value,
        /// Echo of the request id.
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<i64>,
    },
    /// An error reply.
    Error {
        /// The error class and description.
        error: ErrorBody,
        /// Echo of the request id.
        #[serde(skip_serializing_if = "Option::is_none")]
        id: Option<i64>,
    },
}

impl Response {
    /// Builds a response from a handler result, echoing `id`.
    pub fn from_result(id: Option<i64>, result: Result<Value, Error>) -> Self {
        match result {
            Ok(ret) => Response::Success { ret, id },
            Err(err) => Response::Error {
                error: ErrorBody::from(&err),
                id,
            },
        }
    }

    /// Builds an error response.
    pub fn error(id: Option<i64>, err: &Error) -> Self {
        Response::Error {
            error: ErrorBody::from(err),
            id,
        }
    }

    /// The echoed request id, if any.
    pub const fn id(&self) -> Option<i64> {
        match self {
            Response::Success { id, .. } | Response::Error { id, .. } => *id,
        }
    }

    /// Serialises the response as a single JSON document without a trailing
    /// newline (framing adds the delimiter).
    pub fn to_json(&self) -> Vec<u8> {
        // Serialising a `Value` plus strings and integers cannot fail; the
        // fallback keeps the wire well-formed if it ever did.
        serde_json::to_vec(self).unwrap_or_else(|_| {
            br#"{"error":{"class":"GenericError","desc":"response serialisation failed"}}"#.to_vec()
        })
    }
}

/// Parses one frame into a [`Request`].
///
/// The depth, string-length and UTF-8 bounds of [`bounds`] are checked
/// before any JSON parsing. Any failure is reported as
/// [`Error::InvalidRequest`] with a description that does not echo
/// attacker-controlled bytes.
pub fn parse_request(bytes: &[u8]) -> Result<Request, Error> {
    bounds::check_bounds(bytes).map_err(|err| Error::InvalidRequest(err.to_string()))?;
    serde_json::from_slice::<Request>(bytes).map_err(|err| Error::InvalidRequest(describe(&err)))
}

/// Describes a serde error without including any of the input.
fn describe(err: &serde_json::Error) -> String {
    use serde_json::error::Category;
    match err.classify() {
        Category::Io => "i/o error".to_owned(),
        Category::Syntax => format!(
            "malformed JSON at line {} column {}",
            err.line(),
            err.column()
        ),
        Category::Eof => "unexpected end of input".to_owned(),
        // Data errors (unknown key, wrong type, missing `execute`) would
        // quote the offending input; only the position is reported.
        Category::Data => format!(
            "request does not match the schema at line {} column {}",
            err.line(),
            err.column()
        ),
    }
}

/// Decodes `request.arguments` into `T`, treating a missing `arguments`
/// as `{}`.
///
/// Argument types must carry `#[serde(deny_unknown_fields)]` (C-3).
pub fn arguments<T: DeserializeOwned>(request: &Request) -> Result<T, Error> {
    let value = match &request.arguments {
        Some(value @ Value::Object(_)) => value.clone(),
        Some(_) => {
            return Err(Error::InvalidArguments(
                "arguments must be an object".to_owned(),
            ));
        }
        None => Value::Object(serde_json::Map::new()),
    };
    // serde's message would quote the offending value; keep the reply
    // free of attacker-controlled bytes.
    serde_json::from_value(value).map_err(|_| {
        Error::InvalidArguments(format!(
            "arguments do not match the schema of {}",
            request.method
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn request_parses_execute_only() {
        let req = parse_request(br#"{"execute":"guest-ping"}"#).unwrap();
        assert_eq!(
            req,
            Request {
                method: "guest-ping".to_owned(),
                arguments: None,
                id: None
            }
        );
    }

    #[test]
    fn request_parses_arguments_and_id() {
        let req =
            parse_request(br#"{"execute":"guest-sync","arguments":{"id":7},"id":42}"#).unwrap();
        assert_eq!(req.method, "guest-sync");
        assert_eq!(req.arguments, Some(json!({"id": 7})));
        assert_eq!(req.id, Some(42));
    }

    #[test]
    fn request_rejects_unknown_top_level_key() {
        let err = parse_request(br#"{"execute":"guest-ping","extra":1}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        assert_eq!(err.class(), ErrorClass::GenericError);
    }

    #[test]
    fn request_rejects_non_object() {
        for input in [&b"[1]"[..], b"\"guest-ping\"", b"42", b"null", b""] {
            let err = parse_request(input).unwrap_err();
            assert!(
                matches!(err, Error::InvalidRequest(_)),
                "{input:?}: {err:?}"
            );
        }
    }

    #[test]
    fn request_rejects_non_object_arguments() {
        for input in [
            &br#"{"execute":"guest-sync","arguments":[1]}"#[..],
            br#"{"execute":"guest-sync","arguments":1}"#,
            br#"{"execute":"guest-sync","arguments":"x"}"#,
        ] {
            let err = parse_request(input).unwrap_err();
            assert!(
                matches!(err, Error::InvalidRequest(_)),
                "{input:?}: {err:?}"
            );
        }
        // `null` is not "absent" (C-3): an explicit null is rejected too.
        let err = parse_request(br#"{"execute":"guest-sync","arguments":null}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
    }

    #[test]
    fn request_rejects_null_id() {
        let err = parse_request(br#"{"execute":"guest-ping","id":null}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        assert_eq!(err.class(), ErrorClass::GenericError);
    }

    #[test]
    fn request_rejects_duplicate_keys() {
        let err = parse_request(br#"{"execute":"guest-ping","execute":"guest-exec"}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        let err = parse_request(br#"{"execute":"guest-ping","id":1,"id":2}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
    }

    #[test]
    fn request_rejects_positional_array_form() {
        let err = parse_request(br#"["guest-ping"]"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        let err = parse_request(br#"["guest-ping",{},1]"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
    }

    #[test]
    fn request_rejects_missing_execute() {
        let err = parse_request(br#"{"arguments":{}}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
    }

    #[test]
    fn request_rejects_non_integer_id() {
        for input in [
            &br#"{"execute":"guest-ping","id":"42"}"#[..],
            br#"{"execute":"guest-ping","id":4.2}"#,
            br#"{"execute":"guest-ping","id":[42]}"#,
            br#"{"execute":"guest-ping","id":true}"#,
        ] {
            let err = parse_request(input).unwrap_err();
            assert!(
                matches!(err, Error::InvalidRequest(_)),
                "{input:?}: {err:?}"
            );
        }
    }

    #[test]
    fn request_rejects_id_beyond_i64() {
        let err =
            parse_request(br#"{"execute":"guest-ping","id":9223372036854775808}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        let err =
            parse_request(br#"{"execute":"guest-ping","id":-9223372036854775809}"#).unwrap_err();
        assert!(matches!(err, Error::InvalidRequest(_)), "{err:?}");
        let ok = parse_request(br#"{"execute":"guest-ping","id":9223372036854775807}"#).unwrap();
        assert_eq!(ok.id, Some(i64::MAX));
        let ok = parse_request(br#"{"execute":"guest-ping","id":-9223372036854775808}"#).unwrap();
        assert_eq!(ok.id, Some(i64::MIN));
    }

    #[test]
    fn success_response_serialises_return_and_echoes_id() {
        let resp = Response::from_result(Some(42), Ok(json!({})));
        assert_eq!(resp.to_json(), br#"{"return":{},"id":42}"#);
        let resp = Response::from_result(None, Ok(json!(7)));
        assert_eq!(resp.to_json(), br#"{"return":7}"#);
    }

    #[test]
    fn error_response_serialises_class_and_desc() {
        let resp =
            Response::from_result(None, Err(Error::CommandNotFound("guest-exec".to_owned())));
        assert_eq!(
            resp.to_json(),
            br#"{"error":{"class":"CommandNotFound","desc":"The command guest-exec has not been found"}}"#
        );
        let resp = Response::from_result(Some(-1), Err(Error::Frozen));
        assert_eq!(
            resp.to_json(),
            br#"{"error":{"class":"GenericError","desc":"filesystems are frozen; retry after thaw"},"id":-1}"#
        );
    }

    #[test]
    fn error_class_names_match_qapi() {
        assert_eq!(ErrorClass::CommandNotFound.as_str(), "CommandNotFound");
        assert_eq!(ErrorClass::GenericError.as_str(), "GenericError");
        // No other variants exist: an exhaustive match compiles without a
        // wildcard arm.
        let all = [ErrorClass::CommandNotFound, ErrorClass::GenericError];
        for class in all {
            match class {
                ErrorClass::CommandNotFound | ErrorClass::GenericError => {}
            }
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{}\"", class.as_str())
            );
        }
    }

    #[test]
    fn error_from_rate_limited_is_generic_error_with_class_name() {
        let err = Error::RateLimited {
            class: "PingSync".to_owned(),
        };
        let body = ErrorBody::from(&err);
        assert_eq!(body.class, ErrorClass::GenericError);
        assert_eq!(body.desc, "rate limit exceeded for PingSync");
    }

    #[test]
    fn disabled_maps_to_command_not_found_with_upstream_desc() {
        let body = ErrorBody::from(Error::Disabled("guest-fstrim".to_owned()));
        assert_eq!(body.class, ErrorClass::CommandNotFound);
        assert_eq!(body.desc, "command guest-fstrim has been disabled");
    }

    #[test]
    fn every_error_variant_maps_to_a_class() {
        let cases = [
            (
                Error::CommandNotFound("x".into()),
                ErrorClass::CommandNotFound,
            ),
            (Error::Disabled("x".into()), ErrorClass::CommandNotFound),
            (Error::Frozen, ErrorClass::GenericError),
            (
                Error::RateLimited { class: "x".into() },
                ErrorClass::GenericError,
            ),
            (Error::InvalidRequest("x".into()), ErrorClass::GenericError),
            (
                Error::InvalidArguments("x".into()),
                ErrorClass::GenericError,
            ),
            (Error::Internal("x".into()), ErrorClass::GenericError),
        ];
        for (err, class) in cases {
            assert_eq!(err.class(), class, "{err:?}");
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct SyncArgs {
        id: i64,
    }

    #[test]
    fn arguments_treats_none_as_empty_object() {
        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(deny_unknown_fields)]
        struct NoArgs {}
        let req = parse_request(br#"{"execute":"guest-ping"}"#).unwrap();
        assert_eq!(arguments::<NoArgs>(&req).unwrap(), NoArgs {});
        let req = parse_request(br#"{"execute":"guest-sync"}"#).unwrap();
        let err = arguments::<SyncArgs>(&req).unwrap_err();
        assert!(matches!(err, Error::InvalidArguments(_)), "{err:?}");
    }

    #[test]
    fn arguments_rejects_unknown_keys_and_wrong_types() {
        let req = parse_request(br#"{"execute":"guest-sync","arguments":{"id":1,"x":2}}"#).unwrap();
        assert!(matches!(
            arguments::<SyncArgs>(&req),
            Err(Error::InvalidArguments(_))
        ));
        let req = parse_request(br#"{"execute":"guest-sync","arguments":{"id":"1"}}"#).unwrap();
        assert!(matches!(
            arguments::<SyncArgs>(&req),
            Err(Error::InvalidArguments(_))
        ));
        let req = Request {
            method: "guest-sync".to_owned(),
            arguments: Some(json!([1])),
            id: None,
        };
        assert!(matches!(
            arguments::<SyncArgs>(&req),
            Err(Error::InvalidArguments(_))
        ));
        let req = parse_request(br#"{"execute":"guest-sync","arguments":{"id":5}}"#).unwrap();
        assert_eq!(arguments::<SyncArgs>(&req).unwrap(), SyncArgs { id: 5 });
    }

    #[test]
    fn parse_error_description_does_not_echo_input() {
        let secret = br#"{"execute":"guest-ping","id":"SECRET-TOKEN"}"#;
        let err = parse_request(secret).unwrap_err();
        assert!(!err.to_string().contains("SECRET-TOKEN"), "{err}");
        let err = parse_request(b"SECRET-GARBAGE").unwrap_err();
        assert!(!err.to_string().contains("SECRET"), "{err}");
    }

    #[test]
    fn parse_error_description_names_the_category_and_position() {
        // Syntax: a missing colon on line 1.
        let err = parse_request(br#"{"execute" "guest-ping"}"#).unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid request: malformed JSON at line 1 column 12"
        );
        // Eof: an unterminated object.
        let err = parse_request(b"{\"execute\":\"guest-ping\"").unwrap_err();
        assert_eq!(err.to_string(), "invalid request: unexpected end of input");
        // Data: valid JSON that violates the schema (non-string execute).
        let err = parse_request(br#"{"execute":7}"#).unwrap_err();
        assert!(
            err.to_string().starts_with(
                "invalid request: request does not match the schema at line 1 column "
            ),
            "{err}"
        );
    }

    #[test]
    fn parse_request_applies_bounds_before_serde() {
        // 33 nested arrays inside `arguments` would be a schema error for
        // serde (arguments must be an object) but the bounds check runs
        // first and names the depth violation.
        let mut v = b"{\"execute\":\"guest-ping\",\"arguments\":".to_vec();
        v.extend(std::iter::repeat_n(b'[', 33));
        v.extend(std::iter::repeat_n(b']', 33));
        v.push(b'}');
        let err = parse_request(&v).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidRequest(bounds::BoundsError::DepthExceeded.to_string())
        );

        // An over-long method name is rejected by the string bound, not by
        // the allowlist, so no 4 KiB string is ever allocated.
        let mut v = b"{\"execute\":\"".to_vec();
        v.extend(std::iter::repeat_n(b'x', bounds::MAX_STRING_BYTES + 1));
        v.extend_from_slice(b"\"}");
        let err = parse_request(&v).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidRequest(bounds::BoundsError::StringTooLong.to_string())
        );

        let err = parse_request(b"{\"execute\":\"\xff\"}").unwrap_err();
        assert_eq!(
            err,
            Error::InvalidRequest(bounds::BoundsError::InvalidUtf8.to_string())
        );
    }

    #[test]
    fn response_id_accessor() {
        assert_eq!(
            Response::from_result(Some(3), Ok(json!(null))).id(),
            Some(3)
        );
        assert_eq!(Response::error(None, &Error::Frozen).id(), None);
    }
}
