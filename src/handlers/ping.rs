//! `guest-ping` (design §3): liveness check, replies `{}`.
#![forbid(unsafe_code)]

use serde_json::{Value, json};

use crate::dispatch::Context;
use crate::handlers::NoArgs;
use crate::proto::{Error, Request, arguments};

/// Replies `{}`. Any argument is rejected.
pub async fn handle(_ctx: &Context, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatch::Context;
    use crate::proto::parse_request;

    #[tokio::test]
    async fn ping_returns_empty_object() {
        let ctx = Context::for_tests();
        let req = parse_request(br#"{"execute":"guest-ping"}"#).unwrap();
        assert_eq!(handle(&ctx, &req).await.unwrap(), json!({}));
    }

    #[tokio::test]
    async fn ping_rejects_arguments() {
        let ctx = Context::for_tests();
        let req = parse_request(br#"{"execute":"guest-ping","arguments":{"x":1}}"#).unwrap();
        assert!(matches!(
            handle(&ctx, &req).await,
            Err(Error::InvalidArguments(_))
        ));
        let req = parse_request(br#"{"execute":"guest-ping","arguments":{}}"#).unwrap();
        assert_eq!(handle(&ctx, &req).await.unwrap(), json!({}));
    }
}
