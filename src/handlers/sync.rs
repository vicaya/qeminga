//! `guest-sync` and `guest-sync-delimited` (design §3, C-10).
//!
//! Both echo the integer `id` argument. The dispatcher prefixes every
//! reply to `guest-sync-delimited` with the `0xFF` sentinel, whether or
//! not the request frame carried one (C-10).
#![forbid(unsafe_code)]

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::proto::{Error, Request, arguments};

/// Arguments of `guest-sync` and `guest-sync-delimited`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncArgs {
    /// The value to echo; any `i64`.
    pub id: i64,
}

/// `guest-sync`: replies with the `id` argument.
pub async fn sync(_ctx: &Context, req: &Request) -> Result<Value, Error> {
    let args: SyncArgs = arguments(req)?;
    Ok(json!(args.id))
}

/// `guest-sync-delimited`: same reply as [`sync`]; the sentinel prefix is
/// added by the dispatcher when encoding.
pub async fn sync_delimited(ctx: &Context, req: &Request) -> Result<Value, Error> {
    sync(ctx, req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::parse_request;

    #[tokio::test]
    async fn sync_echoes_id_argument() {
        let ctx = Context::for_tests();
        let req = parse_request(br#"{"execute":"guest-sync","arguments":{"id":123}}"#).unwrap();
        assert_eq!(sync(&ctx, &req).await.unwrap(), json!(123));
        let req =
            parse_request(br#"{"execute":"guest-sync-delimited","arguments":{"id":5}}"#).unwrap();
        assert_eq!(sync_delimited(&ctx, &req).await.unwrap(), json!(5));
    }

    #[tokio::test]
    async fn sync_requires_integer_id() {
        let ctx = Context::for_tests();
        for frame in [
            &br#"{"execute":"guest-sync"}"#[..],
            br#"{"execute":"guest-sync","arguments":{}}"#,
            br#"{"execute":"guest-sync","arguments":{"id":"1"}}"#,
            br#"{"execute":"guest-sync","arguments":{"id":1.5}}"#,
            br#"{"execute":"guest-sync","arguments":{"id":null}}"#,
            br#"{"execute":"guest-sync","arguments":{"id":1,"extra":2}}"#,
            br#"{"execute":"guest-sync","arguments":{"id":9223372036854775808}}"#,
        ] {
            let req = parse_request(frame).unwrap();
            let err = sync(&ctx, &req).await.unwrap_err();
            assert!(
                matches!(err, Error::InvalidArguments(_)),
                "{frame:?}: {err:?}"
            );
            assert_eq!(err.class(), crate::proto::ErrorClass::GenericError);
        }
    }

    #[tokio::test]
    async fn sync_id_is_i64_range() {
        let ctx = Context::for_tests();
        for id in [i64::MAX, i64::MIN, -1, 0] {
            let frame = format!(r#"{{"execute":"guest-sync","arguments":{{"id":{id}}}}}"#);
            let req = parse_request(frame.as_bytes()).unwrap();
            assert_eq!(sync(&ctx, &req).await.unwrap(), json!(id));
        }
    }
}
