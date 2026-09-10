//! `guest-info` (design §3.1, AC19; D1, D2; OQ-2).
//!
//! Replies with the upstream `GuestAgentInfo` shape: `version` and
//! `supported_commands` (underscore), each entry a `GuestAgentCommandInfo`
//! with `name`, `enabled`, and `success-response` (hyphen). The list is
//! built from [`SUPPORTED_COMMANDS`] plus the configuration flags; there
//! is no second hand-maintained list. A frozen state does not change the
//! advertised capabilities.
#![forbid(unsafe_code)]

use serde::Serialize;
use serde_json::{Value, json};

use crate::config::Config;
use crate::dispatch::Context;
use crate::handlers::{NoArgs, SUPPORTED_COMMANDS};
use crate::proto::{Error, Request, arguments};

/// One `GuestAgentCommandInfo` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CommandInfo {
    /// Wire name.
    pub name: &'static str,
    /// Whether the command can currently be executed.
    pub enabled: bool,
    /// Whether a successful call produces a reply.
    #[serde(rename = "success-response")]
    pub success_response: bool,
}

/// The `GuestAgentInfo` reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AgentInfo {
    /// Build version (Cargo manifest, not configurable).
    pub version: &'static str,
    /// Every allowlisted command, exactly once.
    pub supported_commands: Vec<CommandInfo>,
}

/// Builds the capability list for `config`.
pub fn agent_info(config: &Config) -> AgentInfo {
    AgentInfo {
        version: crate::VERSION,
        supported_commands: SUPPORTED_COMMANDS
            .iter()
            .map(|spec| CommandInfo {
                name: spec.name,
                enabled: is_enabled(config, spec.name),
                success_response: spec.success_response,
            })
            .collect(),
    }
}

/// The runtime/compile-time switches, mirrored from the dispatcher's
/// feature gate.
fn is_enabled(config: &Config, name: &str) -> bool {
    match name {
        "guest-fstrim" => config.fstrim_enabled(),
        "guest-suspend-ram" => config.suspend_ram_enabled(),
        "guest-shutdown" => config.shutdown_enabled(),
        "guest-get-osinfo" | "guest-network-get-interfaces" | "guest-get-fsinfo" => {
            config.information_enabled()
        }
        _ => true,
    }
}

/// `guest-info` handler.
pub async fn handle(ctx: &Context, req: &Request) -> Result<Value, Error> {
    let NoArgs {} = arguments(req)?;
    Ok(json!(agent_info(&ctx.config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Router;
    use crate::proto::parse_request;
    use crate::state::{FreezeState, FreezeStateMachine};
    use std::sync::Arc;

    fn ctx_with(config: Config, state: FreezeState) -> Context {
        Context::new(
            Arc::new(config),
            Arc::new(FreezeStateMachine::starting_in(state)),
            Router::new(Box::new(std::io::sink())),
            crate::marker::Marker::for_tests(),
        )
    }

    async fn info(ctx: &Context) -> Value {
        let req = parse_request(br#"{"execute":"guest-info"}"#).unwrap();
        handle(ctx, &req).await.unwrap()
    }

    fn entries(value: &Value) -> &Vec<Value> {
        value["supported_commands"].as_array().unwrap()
    }

    fn entry<'a>(value: &'a Value, name: &str) -> &'a Value {
        entries(value)
            .iter()
            .find(|e| e["name"] == name)
            .unwrap_or_else(|| panic!("{name} missing"))
    }

    #[tokio::test]
    async fn info_returns_version_and_supported_commands() {
        let value = info(&Context::for_tests()).await;
        assert_eq!(value["version"], crate::VERSION);
        assert!(
            value.get("supported_commands").is_some(),
            "underscore spelling"
        );
        assert!(value.get("supported-commands").is_none());
        assert_eq!(value.as_object().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn each_listed_command_appears_exactly_once() {
        let value = info(&Context::for_tests()).await;
        let mut names: Vec<&str> = entries(&value)
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), SUPPORTED_COMMANDS.len());
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), SUPPORTED_COMMANDS.len());
        for spec in SUPPORTED_COMMANDS {
            assert!(names.contains(&spec.name), "{}", spec.name);
        }
    }

    #[tokio::test]
    async fn entries_have_name_enabled_success_response() {
        let value = info(&Context::for_tests()).await;
        for e in entries(&value) {
            let obj = e.as_object().unwrap();
            let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
            keys.sort_unstable();
            assert_eq!(keys, ["enabled", "name", "success-response"], "{e}");
            assert!(e["name"].is_string());
            assert!(e["enabled"].is_boolean());
            assert!(e["success-response"].is_boolean());
        }
    }

    #[tokio::test]
    async fn shutdown_and_suspend_ram_are_the_only_success_response_false() {
        let value = info(&Context::for_tests()).await;
        let no_reply: Vec<&str> = entries(&value)
            .iter()
            .filter(|e| e["success-response"] == false)
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(no_reply, ["guest-shutdown", "guest-suspend-ram"]);
    }

    #[tokio::test]
    async fn suspend_ram_listed_disabled_when_feature_absent_or_runtime_off() {
        // Runtime off (default): listed, disabled, regardless of the build.
        let value = info(&Context::for_tests()).await;
        assert_eq!(entry(&value, "guest-suspend-ram")["enabled"], false);
        // Runtime on: enabled only when compiled in.
        let config = Config::parse("[features]\nsuspend_ram = true\n").unwrap();
        let value = info(&ctx_with(config, FreezeState::Thawed)).await;
        assert_eq!(
            entry(&value, "guest-suspend-ram")["enabled"],
            cfg!(feature = "suspend_ram")
        );
        // Runtime off with the feature compiled in: still disabled.
        let config = Config::parse("[features]\nsuspend_ram = false\n").unwrap();
        let value = info(&ctx_with(config, FreezeState::Thawed)).await;
        assert_eq!(entry(&value, "guest-suspend-ram")["enabled"], false);
    }

    #[tokio::test]
    async fn fstrim_listed_disabled_when_runtime_off() {
        let value = info(&Context::for_tests()).await;
        assert_eq!(entry(&value, "guest-fstrim")["enabled"], true);
        let config = Config::parse("[features]\nfstrim = false\n").unwrap();
        let value = info(&ctx_with(config, FreezeState::Thawed)).await;
        let fstrim = entry(&value, "guest-fstrim");
        assert_eq!(fstrim["enabled"], false);
        assert_eq!(fstrim["success-response"], true);
        // Everything else stays enabled.
        for e in entries(&value) {
            if e["name"] != "guest-fstrim" && e["name"] != "guest-suspend-ram" {
                assert_eq!(e["enabled"], true, "{e}");
            }
        }
    }

    #[tokio::test]
    async fn denied_commands_are_absent() {
        let value = info(&Context::for_tests()).await;
        for name in [
            "guest-exec",
            "guest-exec-status",
            "guest-file-open",
            "guest-file-read",
            "guest-file-write",
            "guest-file-close",
            "guest-file-seek",
            "guest-file-flush",
            "guest-set-user-password",
            "guest-ssh-add-authorized-keys",
            "guest-ssh-remove-authorized-keys",
            "guest-ssh-get-authorized-keys",
            "guest-set-time",
            "guest-set-vcpus",
            "guest-set-memory-blocks",
            "guest-suspend-disk",
            "guest-suspend-hybrid",
            "guest-get-users",
            "guest-get-host-name",
            "guest-get-time",
            "guest-get-timezone",
            "guest-get-devices",
            "guest-get-disks",
            "guest-get-diskstats",
            "guest-get-cpustats",
            "guest-get-load",
            "guest-get-vcpus",
            "guest-get-memory-blocks",
            "guest-get-memory-block-info",
            "guest-network-get-route",
        ] {
            assert!(
                !entries(&value).iter().any(|e| e["name"] == name),
                "{name} must not be advertised"
            );
        }
    }

    #[tokio::test]
    async fn frozen_state_does_not_change_capabilities() {
        let thawed = info(&Context::for_tests()).await;
        for state in [
            FreezeState::Freezing,
            FreezeState::Frozen,
            FreezeState::Thawing,
        ] {
            let frozen = info(&ctx_with(Config::default(), state)).await;
            assert_eq!(frozen, thawed, "{state}");
        }
    }

    #[tokio::test]
    async fn info_rejects_arguments() {
        let ctx = Context::for_tests();
        let req = parse_request(br#"{"execute":"guest-info","arguments":{"x":1}}"#).unwrap();
        assert!(matches!(
            handle(&ctx, &req).await,
            Err(Error::InvalidArguments(_))
        ));
    }
}
