//! Runtime configuration: TOML schema, defaults, and validation (design
//! §8.1, §8.2; D1, D2, D4; C-17).
//!
//! Every key has the default documented in §8.2, so an empty file is a
//! valid configuration. Unknown keys are errors (a typo must not silently
//! disable a control). Runtime feature switches whose compile-time half is
//! absent are reported by [`Config::warnings`], not as errors (§8.1).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// Default location of the configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/qeminga/config.toml";

/// The only supported configuration schema version.
pub const CONFIG_VERSION: u32 = 1;

/// Top-level configuration (`[agent]`, `[rate_limits]`, `[features]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `[agent]` section.
    pub agent: AgentConfig,
    /// `[rate_limits]` section (design §5.3).
    pub rate_limits: RateLimits,
    /// `[features]` section: runtime half of the two-level switches.
    pub features: Features,
}

/// Upper bound on both freeze timeouts (one day). The watchdog adds them
/// to an `Instant`, which would overflow (and abort the agent at the
/// moment a freeze succeeds) for values near `u64::MAX`; anything longer
/// than a day is an operator error caught at startup instead.
pub const MAX_FSFREEZE_TIMEOUT_SECS: u64 = 86_400;

/// `[agent]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    /// Configuration schema version; must be [`CONFIG_VERSION`].
    pub config_version: u32,
    /// The virtio-serial channel device.
    pub channel_path: PathBuf,
    /// Minimum level of records written to the audit sink.
    pub log_level: LogLevel,
    /// Recovery marker path (§4.4); must be absolute and on an unfreezable
    /// filesystem (the latter is checked at startup, not here).
    pub state_path: PathBuf,
    /// Auto-thaw after this many seconds without a status heartbeat (§4.4).
    pub fsfreeze_idle_timeout_secs: u64,
    /// Hard cap on the freeze duration in seconds (§4.4).
    pub fsfreeze_max_timeout_secs: u64,
    /// Deadline of a freeze operation in seconds, measured from the moment
    /// the request enters `Freezing` (§4.4): a walk still inside `FIFREEZE`
    /// after this long is aborted, the targets frozen so far are thawed,
    /// and the request fails. Heartbeats do not extend it. An explicit
    /// value must be positive, at most a day and at most
    /// `fsfreeze_max_timeout_secs`; when omitted the effective value is
    /// `min(DEFAULT_FSFREEZE_OPERATION_TIMEOUT_SECS, fsfreeze_max_timeout_secs)`
    /// (see [`AgentConfig::fsfreeze_operation_timeout_secs`]), so a
    /// configuration written before the key existed keeps starting.
    pub fsfreeze_operation_timeout_secs: Option<u64>,
}

/// The freeze operation deadline applied when
/// `fsfreeze_operation_timeout_secs` is omitted, capped by the hard cap.
pub const DEFAULT_FSFREEZE_OPERATION_TIMEOUT_SECS: u64 = 60;

impl AgentConfig {
    /// The effective freeze operation deadline in seconds: the explicit
    /// value, or `min(60, fsfreeze_max_timeout_secs)` when omitted.
    pub fn fsfreeze_operation_timeout_secs(&self) -> u64 {
        self.fsfreeze_operation_timeout_secs
            .unwrap_or(DEFAULT_FSFREEZE_OPERATION_TIMEOUT_SECS.min(self.fsfreeze_max_timeout_secs))
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            config_version: CONFIG_VERSION,
            channel_path: PathBuf::from("/dev/virtio-ports/org.qemu.guest_agent.0"),
            log_level: LogLevel::Info,
            state_path: PathBuf::from("/run/qeminga/frozen"),
            fsfreeze_idle_timeout_secs: 30,
            fsfreeze_max_timeout_secs: 300,
            fsfreeze_operation_timeout_secs: None,
        }
    }
}

/// `[rate_limits]` section: per-minute quotas per command class (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimits {
    /// `guest-ping`, `guest-sync*`, `guest-info` (C-9).
    pub ping_sync_per_min: u32,
    /// `guest-get-*`, `guest-network-get-interfaces`.
    pub get_commands_per_min: u32,
    /// `guest-fsfreeze-freeze`, `guest-fsfreeze-freeze-list`.
    pub fsfreeze_freeze_per_min: u32,
    /// `guest-fstrim`.
    pub fstrim_per_min: u32,
    /// `guest-shutdown`, `guest-suspend-ram`.
    pub shutdown_per_min: u32,
}

impl Default for RateLimits {
    fn default() -> Self {
        RateLimits {
            ping_sync_per_min: 120,
            get_commands_per_min: 30,
            fsfreeze_freeze_per_min: 10,
            fstrim_per_min: 5,
            shutdown_per_min: 2,
        }
    }
}

/// `[features]` section.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Features {
    /// Opt-in `guest-suspend-ram` (D1); needs the `suspend_ram` Cargo feature.
    pub suspend_ram: bool,
    /// `guest-fstrim` (D2); always compiled in.
    pub fstrim: bool,
    /// Install the seccomp filter (§5.5); needs the `seccomp` Cargo feature.
    pub seccomp: bool,
}

impl Default for Features {
    fn default() -> Self {
        Features {
            suspend_ram: false,
            fstrim: true,
            seccomp: true,
        }
    }
}

/// Log level names accepted in `log_level`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Everything.
    Trace,
    /// Debugging detail.
    Debug,
    /// Normal operation (default).
    Info,
    /// Denied commands and recoverable problems.
    Warn,
    /// Failures only.
    Error,
}

impl LogLevel {
    /// The corresponding `tracing` level.
    pub const fn as_tracing(self) -> tracing::Level {
        match self {
            LogLevel::Trace => tracing::Level::TRACE,
            LogLevel::Debug => tracing::Level::DEBUG,
            LogLevel::Info => tracing::Level::INFO,
            LogLevel::Warn => tracing::Level::WARN,
            LogLevel::Error => tracing::Level::ERROR,
        }
    }

    /// The lowercase name.
    pub const fn as_str(self) -> &'static str {
        match self {
            LogLevel::Trace => "trace",
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Warn => "warn",
            LogLevel::Error => "error",
        }
    }
}

/// Configuration errors. Every variant names the offending file or key.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("cannot read configuration file {path}: {source}")]
    Io {
        /// The file that failed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not valid TOML for the schema (unknown key, wrong type,
    /// unknown log level). The message comes from the TOML parser and
    /// names the key and position.
    #[error("invalid configuration{}: {message}", path_suffix(.path))]
    Parse {
        /// The file, when loaded from one.
        path: Option<PathBuf>,
        /// The parser's description.
        message: String,
    },
    /// The file parsed but a value is out of range.
    #[error("invalid configuration{}: {key}: {reason}", path_suffix(.path))]
    Invalid {
        /// The file, when loaded from one.
        path: Option<PathBuf>,
        /// The dotted key that is wrong.
        key: &'static str,
        /// Why.
        reason: String,
    },
}

fn path_suffix(path: &Option<PathBuf>) -> String {
    match path {
        Some(path) => format!(" in {}", path.display()),
        None => String::new(),
    }
}

impl ConfigError {
    fn with_path(self, path: &Path) -> Self {
        match self {
            ConfigError::Parse { message, .. } => ConfigError::Parse {
                path: Some(path.to_owned()),
                message,
            },
            ConfigError::Invalid { key, reason, .. } => ConfigError::Invalid {
                path: Some(path.to_owned()),
                key,
                reason,
            },
            other => other,
        }
    }
}

impl Config {
    /// Parses and validates TOML text.
    pub fn parse(text: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(text).map_err(|err| ConfigError::Parse {
            path: None,
            message: err.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Reads, parses and validates a file; errors name the path.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Config::parse(&text).map_err(|err| err.with_path(path))
    }

    /// Checks value ranges and cross-field constraints.
    pub fn validate(&self) -> Result<(), ConfigError> {
        fn invalid(key: &'static str, reason: impl Into<String>) -> ConfigError {
            ConfigError::Invalid {
                path: None,
                key,
                reason: reason.into(),
            }
        }
        let agent = &self.agent;
        if agent.config_version != CONFIG_VERSION {
            return Err(invalid(
                "agent.config_version",
                format!(
                    "unsupported version {}; this build supports {CONFIG_VERSION}",
                    agent.config_version
                ),
            ));
        }
        if agent.channel_path.as_os_str().is_empty() {
            return Err(invalid("agent.channel_path", "must not be empty"));
        }
        if !agent.state_path.is_absolute() {
            return Err(invalid(
                "agent.state_path",
                format!(
                    "must be an absolute path, got {}",
                    agent.state_path.display()
                ),
            ));
        }
        if agent.fsfreeze_idle_timeout_secs == 0 {
            return Err(invalid(
                "agent.fsfreeze_idle_timeout_secs",
                "must be greater than zero",
            ));
        }
        if agent.fsfreeze_operation_timeout_secs == Some(0) {
            return Err(invalid(
                "agent.fsfreeze_operation_timeout_secs",
                "must be greater than zero",
            ));
        }
        for (key, value) in [
            (
                "agent.fsfreeze_idle_timeout_secs",
                agent.fsfreeze_idle_timeout_secs,
            ),
            (
                "agent.fsfreeze_max_timeout_secs",
                agent.fsfreeze_max_timeout_secs,
            ),
            (
                "agent.fsfreeze_operation_timeout_secs",
                agent.fsfreeze_operation_timeout_secs.unwrap_or(0),
            ),
        ] {
            if value > MAX_FSFREEZE_TIMEOUT_SECS {
                return Err(invalid(
                    key,
                    format!("must be at most {MAX_FSFREEZE_TIMEOUT_SECS} (one day)"),
                ));
            }
        }
        if agent.fsfreeze_max_timeout_secs < agent.fsfreeze_idle_timeout_secs {
            return Err(invalid(
                "agent.fsfreeze_max_timeout_secs",
                format!(
                    "must be at least fsfreeze_idle_timeout_secs ({})",
                    agent.fsfreeze_idle_timeout_secs
                ),
            ));
        }
        // Only an explicit value is judged against the cap: an omitted one
        // is derived under it.
        if agent.fsfreeze_operation_timeout_secs.unwrap_or(0) > agent.fsfreeze_max_timeout_secs {
            return Err(invalid(
                "agent.fsfreeze_operation_timeout_secs",
                format!(
                    "must be at most fsfreeze_max_timeout_secs ({})",
                    agent.fsfreeze_max_timeout_secs
                ),
            ));
        }
        let quotas = [
            (
                "rate_limits.ping_sync_per_min",
                self.rate_limits.ping_sync_per_min,
            ),
            (
                "rate_limits.get_commands_per_min",
                self.rate_limits.get_commands_per_min,
            ),
            (
                "rate_limits.fsfreeze_freeze_per_min",
                self.rate_limits.fsfreeze_freeze_per_min,
            ),
            (
                "rate_limits.fstrim_per_min",
                self.rate_limits.fstrim_per_min,
            ),
            (
                "rate_limits.shutdown_per_min",
                self.rate_limits.shutdown_per_min,
            ),
        ];
        for (key, quota) in quotas {
            if quota == 0 {
                return Err(invalid(key, "must be greater than zero"));
            }
        }
        Ok(())
    }

    /// Runtime switches that have no effect in this build (§8.1): a warning,
    /// not an error.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.features.seccomp && !cfg!(feature = "seccomp") {
            out.push(
                "features.seccomp = true has no effect: this binary was built without the `seccomp` Cargo feature"
                    .to_owned(),
            );
        }
        if self.features.suspend_ram && !cfg!(feature = "suspend_ram") {
            out.push(
                "features.suspend_ram = true has no effect: this binary was built without the `suspend_ram` Cargo feature"
                    .to_owned(),
            );
        }
        out
    }

    /// `guest-fstrim` is available (runtime switch only, D2).
    pub fn fstrim_enabled(&self) -> bool {
        self.features.fstrim
    }

    /// `guest-suspend-ram` is available: compiled in **and** enabled (D1).
    pub fn suspend_ram_enabled(&self) -> bool {
        cfg!(feature = "suspend_ram") && self.features.suspend_ram
    }

    /// The seccomp filter is installed: compiled in **and** enabled (§5.5).
    pub fn seccomp_enabled(&self) -> bool {
        cfg!(feature = "seccomp") && self.features.seccomp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESIGN_EXAMPLE: &str = include_str!("../tests/fixtures/config/default.toml");

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/config")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    #[test]
    fn example_from_design_parses() {
        let config = Config::parse(DESIGN_EXAMPLE).unwrap();
        assert_eq!(config, Config::default(), "the §8.2 block is the default");
        assert!(config.warnings().is_empty() || !cfg!(feature = "seccomp"));
    }

    #[test]
    fn empty_file_yields_documented_defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(
            config.agent.channel_path,
            Path::new("/dev/virtio-ports/org.qemu.guest_agent.0")
        );
        assert_eq!(config.agent.config_version, 1);
        assert_eq!(config.agent.log_level, LogLevel::Info);
        assert_eq!(config.agent.state_path, Path::new("/run/qeminga/frozen"));
        assert_eq!(config.agent.fsfreeze_idle_timeout_secs, 30);
        assert_eq!(config.agent.fsfreeze_max_timeout_secs, 300);
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs, None);
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs(), 60);
        assert_eq!(config.rate_limits.ping_sync_per_min, 120);
        assert_eq!(config.rate_limits.get_commands_per_min, 30);
        assert_eq!(config.rate_limits.fsfreeze_freeze_per_min, 10);
        assert_eq!(config.rate_limits.fstrim_per_min, 5);
        assert_eq!(config.rate_limits.shutdown_per_min, 2);
        assert!(!config.features.suspend_ram);
        assert!(config.features.fstrim);
        assert!(config.features.seccomp);
        assert_eq!(Config::parse(&fixture("minimal.toml")).unwrap(), config);
    }

    #[test]
    fn partial_sections_keep_other_defaults() {
        let config = Config::parse("[rate_limits]\nfstrim_per_min = 7\n").unwrap();
        assert_eq!(config.rate_limits.fstrim_per_min, 7);
        assert_eq!(config.rate_limits.ping_sync_per_min, 120);
        assert_eq!(config.agent, AgentConfig::default());
    }

    fn parse_err(name: &str) -> ConfigError {
        Config::parse(&fixture(name)).expect_err(name)
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = parse_err("invalid_unknown_key.toml");
        let msg = err.to_string();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
        assert!(msg.contains("chanel_path"), "must name the key: {msg}");
        // Unknown sections too.
        let err = Config::parse("[agnet]\nconfig_version = 1\n").unwrap_err();
        assert!(err.to_string().contains("agnet"), "{err}");
    }

    #[test]
    fn unknown_log_level_is_an_error() {
        let err = parse_err("invalid_log_level.toml");
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
        assert!(err.to_string().contains("log_level"), "{err}");
        for (name, level) in [
            ("trace", LogLevel::Trace),
            ("debug", LogLevel::Debug),
            ("info", LogLevel::Info),
            ("warn", LogLevel::Warn),
            ("error", LogLevel::Error),
        ] {
            let config = Config::parse(&format!("[agent]\nlog_level = \"{name}\"\n")).unwrap();
            assert_eq!(config.agent.log_level, level);
            assert_eq!(level.as_str(), name);
        }
        // Case matters: "INFO" is not accepted.
        assert!(Config::parse("[agent]\nlog_level = \"INFO\"\n").is_err());
    }

    #[test]
    fn config_version_other_than_1_is_an_error() {
        let err = parse_err("invalid_config_version.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.config_version",
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("agent.config_version"), "{err}");
        let err = parse_err("invalid_version_type.toml");
        assert!(matches!(err, ConfigError::Parse { .. }), "{err}");
    }

    #[test]
    fn relative_state_path_is_an_error() {
        let err = parse_err("invalid_relative_state_path.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.state_path",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn timeouts_above_the_cap_are_an_error() {
        // The watchdog adds these to an Instant; a value near u64::MAX
        // would overflow there, at the moment the freeze succeeds.
        let err = parse_err("invalid_timeout_too_large.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.fsfreeze_max_timeout_secs",
                    ..
                }
            ),
            "{err}"
        );
        assert!(err.to_string().contains("86400"), "{err}");
        let mut config = Config::default();
        config.agent.fsfreeze_idle_timeout_secs = MAX_FSFREEZE_TIMEOUT_SECS + 1;
        config.agent.fsfreeze_max_timeout_secs = MAX_FSFREEZE_TIMEOUT_SECS + 1;
        let err = config.validate().unwrap_err();
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.fsfreeze_idle_timeout_secs",
                    ..
                }
            ),
            "{err}"
        );
        config.agent.fsfreeze_idle_timeout_secs = MAX_FSFREEZE_TIMEOUT_SECS;
        config.agent.fsfreeze_max_timeout_secs = MAX_FSFREEZE_TIMEOUT_SECS;
        config.validate().unwrap();
    }

    #[test]
    fn idle_timeout_zero_is_an_error() {
        let err = parse_err("invalid_idle_timeout_zero.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.fsfreeze_idle_timeout_secs",
                    ..
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn operation_timeout_is_bounded_by_the_hard_cap_and_positive() {
        // The freeze operation deadline (§4.4) must be positive, at most a
        // day, and at most the hard cap, which keeps the service manager's
        // stop timeout coupled to one figure (§8.4).
        let err = parse_err("invalid_operation_timeout_above_max.toml");
        assert!(
            matches!(
                &err,
                ConfigError::Invalid { key, .. } if *key == "agent.fsfreeze_operation_timeout_secs"
            ),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("must be at most fsfreeze_max_timeout_secs (300)"),
            "{err}"
        );
        let mut config = Config::default();
        config.agent.fsfreeze_operation_timeout_secs = Some(0);
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "{err}");
        config.agent.fsfreeze_operation_timeout_secs = Some(MAX_FSFREEZE_TIMEOUT_SECS + 1);
        config.agent.fsfreeze_max_timeout_secs = MAX_FSFREEZE_TIMEOUT_SECS;
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("one day"), "{err}");
        // Equal to the hard cap is allowed.
        let config = Config::parse(
            "[agent]\nfsfreeze_idle_timeout_secs = 10\nfsfreeze_max_timeout_secs = 10\nfsfreeze_operation_timeout_secs = 10\n",
        )
        .unwrap();
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs, Some(10));
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs(), 10);
    }

    #[test]
    fn an_omitted_operation_timeout_is_derived_under_the_hard_cap() {
        // A configuration written before the key existed, with a short
        // cap, keeps starting: the effective deadline is min(60, cap).
        let config = Config::parse(&fixture("legacy_short_cap.toml")).unwrap();
        assert_eq!(config.agent.fsfreeze_max_timeout_secs, 5);
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs, None);
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs(), 5);
        // A cap above the default leaves the default.
        let config = Config::parse("[agent]\nfsfreeze_max_timeout_secs = 600\n").unwrap();
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs(), 60);
        // An explicit value is never clamped: above the cap is an error.
        let err = Config::parse(
            "[agent]\nfsfreeze_idle_timeout_secs = 2\nfsfreeze_max_timeout_secs = 5\nfsfreeze_operation_timeout_secs = 6\n",
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("at most fsfreeze_max_timeout_secs (5)"),
            "{err}"
        );
        // And a valid explicit value under a short cap is kept as given.
        let config = Config::parse(
            "[agent]\nfsfreeze_idle_timeout_secs = 2\nfsfreeze_max_timeout_secs = 5\nfsfreeze_operation_timeout_secs = 3\n",
        )
        .unwrap();
        assert_eq!(config.agent.fsfreeze_operation_timeout_secs(), 3);
    }

    #[test]
    fn max_timeout_below_idle_is_an_error() {
        let err = parse_err("invalid_max_below_idle.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "agent.fsfreeze_max_timeout_secs",
                    ..
                }
            ),
            "{err}"
        );
        // Equal is allowed.
        let config = Config::parse(
            "[agent]\nfsfreeze_idle_timeout_secs = 60\nfsfreeze_max_timeout_secs = 60\n",
        )
        .unwrap();
        assert_eq!(config.agent.fsfreeze_max_timeout_secs, 60);
    }

    #[test]
    fn zero_quota_is_an_error() {
        let err = parse_err("invalid_zero_quota.toml");
        assert!(
            matches!(
                err,
                ConfigError::Invalid {
                    key: "rate_limits.fstrim_per_min",
                    ..
                }
            ),
            "{err}"
        );
        for key in [
            "ping_sync_per_min",
            "get_commands_per_min",
            "fsfreeze_freeze_per_min",
            "fstrim_per_min",
            "shutdown_per_min",
        ] {
            let err = Config::parse(&format!("[rate_limits]\n{key} = 0\n")).unwrap_err();
            assert!(err.to_string().contains(key), "{err}");
        }
        // Negative quotas are a type error at parse time.
        assert!(Config::parse("[rate_limits]\nfstrim_per_min = -1\n").is_err());
    }

    #[test]
    fn runtime_feature_without_compile_feature_is_a_warning_not_an_error() {
        let config =
            Config::parse("[features]\nseccomp = true\nsuspend_ram = true\nfstrim = true\n")
                .unwrap();
        let warnings = config.warnings();
        assert_eq!(
            warnings.iter().any(|w| w.contains("seccomp")),
            !cfg!(feature = "seccomp"),
            "{warnings:?}"
        );
        assert_eq!(
            warnings.iter().any(|w| w.contains("suspend_ram")),
            !cfg!(feature = "suspend_ram"),
            "{warnings:?}"
        );
        assert!(!warnings.iter().any(|w| w.contains("fstrim")));
        // Switches that are off never warn.
        let off = Config::parse("[features]\nseccomp = false\nsuspend_ram = false\n").unwrap();
        assert!(off.warnings().is_empty());
    }

    #[test]
    fn effective_flags_combine_both_layers() {
        let on = Config::parse("[features]\nseccomp = true\nsuspend_ram = true\nfstrim = true\n")
            .unwrap();
        assert!(on.fstrim_enabled());
        assert_eq!(on.suspend_ram_enabled(), cfg!(feature = "suspend_ram"));
        assert_eq!(on.seccomp_enabled(), cfg!(feature = "seccomp"));
        let off =
            Config::parse("[features]\nseccomp = false\nsuspend_ram = false\nfstrim = false\n")
                .unwrap();
        assert!(!off.fstrim_enabled());
        assert!(!off.suspend_ram_enabled());
        assert!(!off.seccomp_enabled());
    }

    #[test]
    fn load_reports_path_in_error() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing.toml");
        let err = Config::load(&missing).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }), "{err}");
        assert!(err.to_string().contains("missing.toml"), "{err}");

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[agent]\nfsfreeze_idle_timeout_secs = 0\n").unwrap();
        let err = Config::load(&bad).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bad.toml"), "{msg}");
        assert!(msg.contains("agent.fsfreeze_idle_timeout_secs"), "{msg}");

        let unparsable = dir.path().join("unparsable.toml");
        std::fs::write(&unparsable, "[agent\n").unwrap();
        let err = Config::load(&unparsable).unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { path: Some(_), .. }),
            "{err}"
        );
        assert!(err.to_string().contains("unparsable.toml"), "{err}");

        let good = dir.path().join("good.toml");
        std::fs::write(&good, DESIGN_EXAMPLE).unwrap();
        assert_eq!(Config::load(&good).unwrap(), Config::default());
    }

    #[test]
    fn log_level_maps_to_tracing() {
        assert_eq!(LogLevel::Trace.as_tracing(), tracing::Level::TRACE);
        assert_eq!(LogLevel::Error.as_tracing(), tracing::Level::ERROR);
        assert_eq!(LogLevel::Info.as_tracing(), tracing::Level::INFO);
    }
}
