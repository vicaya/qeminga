//! Target-specific seccomp-BPF profiles (design §5.5, §8.1; AC15; C-11,
//! C-17). Compiled only with the `seccomp` Cargo feature.
//!
//! One logical allowlist is resolved per target by `seccompiler`, so
//! portable operations use `openat`, `newfstatat`/`statx`, `ppoll` and
//! `epoll_pwait`; the x86-64 legacy aliases (`open`, `stat`, `lstat`,
//! `poll`, `epoll_wait`) are listed only in the x86-64 profile, each with
//! the observed need that justifies it. `ioctl` is restricted by request
//! number to `FIFREEZE`, `FITHAW` and `FITRIM`. The default action kills
//! the process; the `seccomp-log` feature switches it to logging for the
//! compatibility run that derives and verifies the list (C-17).
//!
//! The filter is installed by `main` after the capability drop and
//! `PR_SET_NO_NEW_PRIVS` (§5.4 step 6), so `seccomp(2)`/`prctl(2)` need
//! not stay available afterwards.
#![forbid(unsafe_code)]

use seccompiler::{BpfProgram, TargetArch};

use crate::kernel::ioctl::{FIFREEZE, FITHAW, FITRIM};

/// The two supported targets (§8.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `x86_64-unknown-linux-gnu`.
    X86_64,
    /// `aarch64-unknown-linux-gnu`.
    Aarch64,
}

impl Target {
    /// The target this binary was built for.
    pub const fn current() -> Target {
        if cfg!(target_arch = "aarch64") {
            Target::Aarch64
        } else {
            Target::X86_64
        }
    }

    fn arch(self) -> TargetArch {
        match self {
            Target::X86_64 => TargetArch::x86_64,
            Target::Aarch64 => TargetArch::aarch64,
        }
    }
}

/// A condition on one syscall argument (`seccompiler` dword `eq`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgEq {
    /// Argument index (0-based).
    pub index: u8,
    /// Required value (low 32 bits compared).
    pub value: u64,
}

/// One allow rule: a syscall name, optionally restricted by arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Syscall name as spelled for the target.
    pub syscall: &'static str,
    /// All conditions must hold for the rule to match.
    pub conditions: Vec<ArgEq>,
}

/// The ioctl requests that may pass the filter (§5.5 privileged handlers).
pub const IOCTL_REQUESTS: [u32; 3] = [FIFREEZE, FITHAW, FITRIM];

/// `PR_SET_NAME`: the only `prctl` option allowed after installation.
/// Tokio names every runtime and blocking-pool thread it spawns
/// (`prctl(PR_SET_NAME, ...)` via `pthread_setname_np`); everything else
/// `prctl` can do (`PR_SET_SECCOMP`, `PR_CAPBSET_DROP`, ...) stays denied.
pub const PR_SET_NAME: u64 = 15;

/// Syscalls needed on both targets, grouped by the §5.5 surfaces table.
pub const COMMON: &[&str] = &[
    // File, metadata and channel I/O.
    "read",
    "write",
    "readv",
    "writev",
    "close",
    "openat",
    "fcntl",
    "lseek",
    "pread64",
    "pwrite64",
    "newfstatat",
    "statx",
    "fstat",
    "statfs",
    "fstatfs",
    "getdents64",
    "readlinkat",
    "faccessat",
    "faccessat2",
    // Recovery marker: openat(O_CREAT|O_EXCL) above, plus:
    "fsync",
    "unlinkat",
    // Runtime and reactor: memory management.
    "brk",
    "mmap",
    "munmap",
    "mprotect",
    "mremap",
    "madvise",
    "membarrier",
    // Threads (tokio workers and the blocking pool).
    "clone",
    "clone3",
    "set_robust_list",
    "get_robust_list",
    "set_tid_address",
    "gettid",
    "getpid",
    "tgkill",
    "rseq",
    "futex",
    "futex_waitv",
    "sched_yield",
    "sched_getaffinity",
    "prlimit64",
    "getrlimit",
    "exit",
    "exit_group",
    // Event loop.
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_pwait2",
    "eventfd2",
    "ppoll",
    "pipe2",
    "socketpair",
    // Signals.
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "restart_syscall",
    // Clocks.
    "clock_gettime",
    "clock_nanosleep",
    "nanosleep",
    // Identity queries and randomness.
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "getrandom",
    // OS and network information.
    "uname",
    "socket",
    "bind",
    "getsockname",
    "sendto",
    "sendmsg",
    "recvmsg",
    "recvfrom",
    "setsockopt",
    // Privileged handlers (C-11: sync before reboot).
    "sync",
    "reboot",
    // ioctl is listed separately with argument conditions.
];

/// x86-64-only legacy aliases (§5.5), each with the observed need.
pub const X86_64_ONLY: &[&str] = &[
    // glibc's epoll_wait(3) is the epoll_wait syscall on x86-64 (mio's
    // poller); aarch64 has no such syscall and uses epoll_pwait.
    "epoll_wait",
    // glibc's poll(3) is the poll syscall on x86-64; aarch64 uses ppoll.
    "poll",
    // Older glibc and some NSS paths still issue open(2) on x86-64.
    "open",
    // As above for stat(2), used by older glibc path lookups.
    "stat",
    // As above for lstat(2), used by older glibc symlink checks.
    "lstat",
];

/// The allow rules for `target`, ioctl restricted to [`IOCTL_REQUESTS`].
pub fn rules(target: Target) -> Vec<Rule> {
    let mut out: Vec<Rule> = COMMON
        .iter()
        .map(|name| Rule {
            syscall: name,
            conditions: Vec::new(),
        })
        .collect();
    if target == Target::X86_64 {
        out.extend(X86_64_ONLY.iter().map(|name| Rule {
            syscall: name,
            conditions: Vec::new(),
        }));
    }
    out.extend(IOCTL_REQUESTS.iter().map(|request| Rule {
        syscall: "ioctl",
        conditions: vec![ArgEq {
            index: 1,
            value: u64::from(*request),
        }],
    }));
    out.push(Rule {
        syscall: "prctl",
        conditions: vec![ArgEq {
            index: 0,
            value: PR_SET_NAME,
        }],
    });
    out
}

/// `true` when an unlisted syscall is logged instead of killing the
/// process: the `seccomp-log` compatibility feature (C-17) **in a debug
/// build only**. A release build always enforces, so `--all-features`
/// (which enables `seccomp-log`) can never produce a release binary with
/// a logging filter.
pub const fn log_mode() -> bool {
    cfg!(feature = "seccomp-log") && cfg!(debug_assertions)
}

/// The filter mode for the startup audit record: `"enforce"` or `"log"`.
pub const fn mode() -> &'static str {
    if log_mode() { "log" } else { "enforce" }
}

/// The default (mismatch) action: kill the process, or log in
/// [`log_mode`].
pub const fn default_action() -> &'static str {
    if log_mode() { "log" } else { "kill_process" }
}

/// The name of the single filter in the JSON document.
const FILTER_NAME: &str = "qeminga";

/// The `seccompiler` JSON document for `target`.
pub fn profile_json(target: Target) -> String {
    let filter: Vec<serde_json::Value> = rules(target)
        .into_iter()
        .map(|rule| {
            if rule.conditions.is_empty() {
                serde_json::json!({ "syscall": rule.syscall })
            } else {
                let args: Vec<serde_json::Value> = rule
                    .conditions
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "index": c.index,
                            "type": "dword",
                            "op": "eq",
                            "val": c.value,
                        })
                    })
                    .collect();
                serde_json::json!({ "syscall": rule.syscall, "args": args })
            }
        })
        .collect();
    serde_json::json!({
        FILTER_NAME: {
            "mismatch_action": default_action(),
            "match_action": "allow",
            "filter": filter,
        }
    })
    .to_string()
}

/// A profile could not be built or installed.
#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    /// `seccompiler` rejected the document (unknown syscall for the
    /// target, bad condition).
    #[error("cannot compile seccomp profile: {0}")]
    Compile(String),
    /// The compiled document did not contain the expected filter.
    #[error("seccomp profile is missing filter {FILTER_NAME}")]
    Missing,
    /// `seccomp(2)` failed.
    #[error("cannot install seccomp filter: {0}")]
    Install(String),
}

/// Compiles the profile for `target` into a BPF program.
pub fn profile(target: Target) -> Result<BpfProgram, SeccompError> {
    let json = profile_json(target);
    let mut map = seccompiler::compile_from_json(json.as_bytes(), target.arch())
        .map_err(|err| SeccompError::Compile(err.to_string()))?;
    map.remove(FILTER_NAME).ok_or(SeccompError::Missing)
}

/// Installs `program` on every thread of the process. Requires
/// `PR_SET_NO_NEW_PRIVS` (or `CAP_SYS_ADMIN`), which §5.4 step 6 sets
/// first.
pub fn install(program: &BpfProgram) -> Result<(), SeccompError> {
    seccompiler::apply_filter_all_threads(program)
        .map_err(|err| SeccompError::Install(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_builds_for_x86_64_and_aarch64() {
        for target in [Target::X86_64, Target::Aarch64] {
            let program = profile(target).unwrap_or_else(|e| panic!("{target:?}: {e}"));
            assert!(
                program.len() > COMMON.len(),
                "{target:?}: {} instructions",
                program.len()
            );
        }
        // An unknown name is rejected rather than silently dropped.
        let json = r#"{"qeminga":{"mismatch_action":"kill_process","match_action":"allow","filter":[{"syscall":"no_such_syscall"}]}}"#;
        assert!(seccompiler::compile_from_json(json.as_bytes(), TargetArch::aarch64).is_err());
        // And the aarch64 table really lacks the x86-64 aliases.
        for name in X86_64_ONLY {
            let json = format!(
                r#"{{"qeminga":{{"mismatch_action":"kill_process","match_action":"allow","filter":[{{"syscall":"{name}"}}]}}}}"#
            );
            assert!(
                seccompiler::compile_from_json(json.as_bytes(), TargetArch::aarch64).is_err(),
                "{name} must not resolve on aarch64"
            );
            assert!(seccompiler::compile_from_json(json.as_bytes(), TargetArch::x86_64).is_ok());
        }
        let _ = Target::current();
    }

    #[test]
    fn ioctl_rule_allows_exactly_fifreeze_fithaw_fitrim() {
        for target in [Target::X86_64, Target::Aarch64] {
            let ioctl: Vec<&Rule> = rules(target)
                .iter()
                .filter(|r| r.syscall == "ioctl")
                .cloned()
                .map(|r| Box::leak(Box::new(r)) as &Rule)
                .collect();
            let mut values: Vec<u64> = ioctl
                .iter()
                .map(|r| {
                    assert_eq!(r.conditions.len(), 1, "one condition per ioctl rule");
                    assert_eq!(r.conditions[0].index, 1, "the request number argument");
                    r.conditions[0].value
                })
                .collect();
            values.sort_unstable();
            assert_eq!(
                values,
                [u64::from(FIFREEZE), u64::from(FITHAW), u64::from(FITRIM)]
            );
            // No unconditional ioctl (or prctl) rule exists.
            assert!(rules(target).iter().all(|r| {
                (r.syscall != "ioctl" && r.syscall != "prctl") || !r.conditions.is_empty()
            }));
            let prctl: Vec<Rule> = rules(target)
                .into_iter()
                .filter(|r| r.syscall == "prctl")
                .collect();
            assert_eq!(prctl.len(), 1);
            assert_eq!(
                prctl[0].conditions,
                [ArgEq {
                    index: 0,
                    value: PR_SET_NAME
                }]
            );
            let json = profile_json(target);
            assert_eq!(json.matches("\"syscall\":\"ioctl\"").count(), 3);
            assert!(json.contains(&format!("\"val\":{}", FIFREEZE)));
        }
    }

    #[test]
    fn x86_64_only_legacy_aliases_are_absent_from_aarch64_profile() {
        let names =
            |t: Target| -> Vec<&'static str> { rules(t).iter().map(|r| r.syscall).collect() };
        let a64 = names(Target::Aarch64);
        let x86 = names(Target::X86_64);
        for alias in ["open", "stat", "lstat", "poll", "epoll_wait"] {
            assert!(!a64.contains(&alias), "{alias} in aarch64 profile");
            assert!(x86.contains(&alias), "{alias} missing from x86-64 profile");
            assert!(X86_64_ONLY.contains(&alias));
            assert!(!COMMON.contains(&alias));
        }
        // Everything x86-64-only is documented with an observed need.
        let src = include_str!("seccomp.rs");
        let list_start = src.find("pub const X86_64_ONLY").unwrap();
        let list = &src[list_start..src[list_start..].find("];").unwrap() + list_start];
        for alias in X86_64_ONLY {
            let pos = list.find(&format!("\"{alias}\"")).unwrap();
            let before = &list[..pos];
            assert!(
                before.trim_end().ends_with("."),
                "{alias} needs a justification comment"
            );
        }
        // The portable spellings are common.
        for portable in ["openat", "newfstatat", "statx", "ppoll", "epoll_pwait"] {
            assert!(COMMON.contains(&portable), "{portable}");
        }
    }

    #[test]
    fn default_action_is_kill_process_unless_seccomp_log_in_a_debug_build() {
        if cfg!(feature = "seccomp-log") && cfg!(debug_assertions) {
            assert!(log_mode());
            assert_eq!(mode(), "log");
            assert_eq!(default_action(), "log");
            assert!(profile_json(Target::current()).contains("\"mismatch_action\":\"log\""));
        } else {
            assert!(!log_mode());
            assert_eq!(mode(), "enforce");
            assert_eq!(default_action(), "kill_process");
            assert!(
                profile_json(Target::current()).contains("\"mismatch_action\":\"kill_process\"")
            );
        }
        // A release build enforces whatever features are on.
        if !cfg!(debug_assertions) {
            assert_eq!(default_action(), "kill_process");
        }
        assert!(profile_json(Target::current()).contains("\"match_action\":\"allow\""));
    }

    #[test]
    fn sync_and_reboot_are_present() {
        for target in [Target::X86_64, Target::Aarch64] {
            let names: Vec<&str> = rules(target).iter().map(|r| r.syscall).collect();
            assert!(names.contains(&"sync"), "{target:?}");
            assert!(names.contains(&"reboot"), "{target:?}");
            assert!(names.contains(&"fsync"));
            assert!(names.contains(&"unlinkat"));
            assert!(names.contains(&"uname"));
            for netlink in [
                "socket",
                "bind",
                "sendto",
                "sendmsg",
                "recvmsg",
                "getsockname",
            ] {
                assert!(names.contains(&netlink), "{netlink}");
            }
        }
    }

    #[test]
    fn execve_and_mkdirat_are_absent() {
        for target in [Target::X86_64, Target::Aarch64] {
            let names: Vec<&str> = rules(target).iter().map(|r| r.syscall).collect();
            for forbidden in [
                "execve",
                "execveat",
                "mkdirat",
                "mkdir",
                "mount",
                "umount2",
                "pivot_root",
                "setns",
                "unshare",
                "bpf",
                "ptrace",
                "kill",
                "fork",
                "vfork",
                "connect",
                "accept",
                "accept4",
                "listen",
                "chmod",
                "fchmod",
                "chown",
                "rename",
                "renameat",
                "symlinkat",
                "linkat",
                "seccomp",
                "capset",
                "setresuid",
                "setresgid",
                "setgroups",
                "init_module",
                "finit_module",
                "kexec_load",
            ] {
                assert!(
                    !names.contains(&forbidden),
                    "{target:?}: {forbidden} must be absent"
                );
            }
            // No duplicates.
            let mut sorted = names.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                sorted.len() + 2,
                names.len(),
                "only ioctl repeats (3 rules)"
            );
            assert_eq!(names.iter().filter(|n| **n == "prctl").count(), 1);
        }
    }

    /// Installs the enforced (or logging) profile in a child process and
    /// runs the full allowed-command matrix through the dispatcher there
    /// (AC15). Driven by T5.2; needs `PR_SET_NO_NEW_PRIVS`, which the
    /// child sets itself, so root is not strictly required, but the
    /// freeze/thaw/trim/reboot ioctls need a fake kernel here and the real
    /// one in the privileged E2E.
    #[test]
    #[ignore = "installs a seccomp filter on the test process (run in the privileged job)"]
    fn privileged_install_then_full_command_matrix() {
        if std::env::var_os("QEMINGA_SECCOMP_CHILD").is_some() {
            // Test scaffolding that the daemon never needs (mkdir for the
            // tempdir) happens before the filter is installed.
            let dir = tempfile::tempdir().unwrap();
            nix::sys::prctl::set_no_new_privs().unwrap();
            let program = profile(Target::current()).unwrap();
            install(&program).unwrap();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                use crate::dispatch::{Context, Dispatcher};
                use crate::framing::DecodeEvent;
                let ctx = Context::new(
                    std::sync::Arc::new(crate::config::Config::default()),
                    std::sync::Arc::new(crate::state::FreezeStateMachine::new()),
                    crate::audit::Router::stderr(),
                )
                .with_kernel(std::sync::Arc::new(crate::kernel::fake::FakeKernel::new()))
                .with_marker(crate::marker::Marker::new(dir.path().join("frozen")));
                let dispatcher = Dispatcher::new(std::sync::Arc::new(ctx));
                for request in [
                    r#"{"execute":"guest-ping"}"#,
                    r#"{"execute":"guest-info"}"#,
                    r#"{"execute":"guest-sync","arguments":{"id":1}}"#,
                    r#"{"execute":"guest-sync-delimited","arguments":{"id":2}}"#,
                    r#"{"execute":"guest-get-osinfo"}"#,
                    r#"{"execute":"guest-network-get-interfaces"}"#,
                    r#"{"execute":"guest-get-fsinfo"}"#,
                    r#"{"execute":"guest-fsfreeze-status"}"#,
                    r#"{"execute":"guest-fsfreeze-freeze"}"#,
                    r#"{"execute":"guest-fsfreeze-status"}"#,
                    r#"{"execute":"guest-fsfreeze-thaw"}"#,
                    r#"{"execute":"guest-fsfreeze-freeze-list","arguments":{"mountpoints":["/"]}}"#,
                    r#"{"execute":"guest-fsfreeze-thaw"}"#,
                    r#"{"execute":"guest-fstrim"}"#,
                    r#"{"execute":"guest-shutdown"}"#,
                ] {
                    let reply = dispatcher
                        .handle(DecodeEvent::Frame {
                            bytes: request.as_bytes().to_vec(),
                            sentinel: false,
                        })
                        .await;
                    let text = reply
                        .map(|r| String::from_utf8_lossy(&r).into_owned())
                        .unwrap_or_default();
                    assert!(!text.contains("\"CommandNotFound\""), "{request}: {text}");
                    println!("MATRIX {request} -> {}", text.trim_end());
                }
            });
            println!("MATRIX done");
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "seccomp::tests::privileged_install_then_full_command_matrix",
                "--ignored",
                "--nocapture",
            ])
            .env("QEMINGA_SECCOMP_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child status {:?} (SIGSYS means a syscall is missing from the profile)\nstdout: {stdout}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(stdout.contains("MATRIX done"), "{stdout}");
        assert_eq!(stdout.matches("MATRIX {").count(), 15);
    }
}
