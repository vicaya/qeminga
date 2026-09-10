//! Capability dropping (design §5.4 six ordered steps and final set; G6;
//! D7; AC3; C-18). Lives under `kernel/` per §6 although it needs no
//! `unsafe`.
//!
//! Order (§5.4), each step through [`CapOps`] so the sequence is testable
//! against a recording fake:
//!
//! 1. (caller) open the channel and finish pre-drop setup;
//! 2. `PR_SET_KEEPCAPS`;
//! 3. `setgroups`, `setresgid`, `setresuid` to the service account;
//! 4. re-raise the final capabilities plus the temporary `CAP_SETPCAP`
//!    in the permitted and effective sets;
//! 5. drop every non-final capability from the bounding set, including
//!    `CAP_SETPCAP`; then clear all non-final effective, permitted,
//!    inheritable and ambient capabilities (and `KEEPCAPS`);
//! 6. `PR_SET_NO_NEW_PRIVS` (the caller then installs seccomp, §5.5).
//!
//! If the process is not root, the drop is skipped with a warning (C-18).
//! Under enforced hardening the caller then refuses to serve (§8.1); under
//! the development opt-out freeze, trim and shutdown will fail with
//! `EPERM`.
#![forbid(unsafe_code)]

use caps::{CapSet, Capability, CapsHashSet};
use nix::unistd::{Gid, Uid};

use crate::config::Authority;

/// The final effective and permitted set of the lifecycle profile (§5.4).
pub const FINAL_CAPS: [Capability; 3] = [
    Capability::CAP_SYS_ADMIN,
    Capability::CAP_SYS_BOOT,
    Capability::CAP_DAC_READ_SEARCH,
];

/// The final set for `authority` (§5.4, §5.9): `CAP_SYS_ADMIN` and
/// `CAP_DAC_READ_SEARCH` always (freeze, thaw and trim need them),
/// `CAP_SYS_BOOT` only when `guest-shutdown` is enabled.
pub fn final_capability_set(authority: &Authority) -> CapsHashSet {
    FINAL_CAPS
        .iter()
        .copied()
        .filter(|cap| authority.reboot || *cap != Capability::CAP_SYS_BOOT)
        .collect()
}

/// The service account, resolved from the passwd database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// Real, effective and saved uid to switch to.
    pub uid: Uid,
    /// Primary (and only) gid to switch to.
    pub gid: Gid,
}

/// The five capability sets, as a plain enum so plans can be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetKind {
    /// Effective.
    Effective,
    /// Permitted.
    Permitted,
    /// Inheritable.
    Inheritable,
    /// Bounding.
    Bounding,
    /// Ambient.
    Ambient,
}

impl From<SetKind> for CapSet {
    fn from(kind: SetKind) -> CapSet {
        match kind {
            SetKind::Effective => CapSet::Effective,
            SetKind::Permitted => CapSet::Permitted,
            SetKind::Inheritable => CapSet::Inheritable,
            SetKind::Bounding => CapSet::Bounding,
            SetKind::Ambient => CapSet::Ambient,
        }
    }
}

/// A recorded step of the drop plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// `PR_SET_KEEPCAPS`.
    KeepCaps(bool),
    /// `setgroups([gid])`.
    SetGroups(Gid),
    /// `setresgid(gid, gid, gid)`.
    SetResGid(Gid),
    /// `setresuid(uid, uid, uid)`.
    SetResUid(Uid),
    /// Replace a capability set (sorted for determinism).
    Set(SetKind, Vec<Capability>),
    /// Remove one capability from a set (bounding set trimming).
    Drop(SetKind, Capability),
    /// Empty a set.
    Clear(SetKind),
    /// `PR_SET_NO_NEW_PRIVS`.
    NoNewPrivs,
}

/// A failed step.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivilegeError {
    /// The service account does not exist.
    #[error("user {0} not found")]
    UnknownUser(String),
    /// A syscall in the sequence failed.
    #[error("{step} failed: {reason}")]
    Step {
        /// Which step.
        step: &'static str,
        /// The error text.
        reason: String,
    },
}

/// What [`drop_privileges`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The full sequence ran; the process now holds exactly the final set
    /// of its authority ([`final_capability_set`]: [`FINAL_CAPS`] less
    /// `CAP_SYS_BOOT` when `guest-shutdown` is disabled).
    Dropped,
    /// Not root at startup: nothing was changed (C-18).
    SkippedUnprivileged,
}

/// The OS operations the sequence needs; production is [`SystemCaps`].
pub trait CapOps {
    /// `geteuid() == 0`.
    fn is_root(&self) -> bool;
    /// Looks up the account in the passwd database.
    fn lookup(&self, user: &str) -> Result<Option<Account>, String>;
    /// `PR_SET_KEEPCAPS`.
    fn set_keepcaps(&self, keep: bool) -> Result<(), String>;
    /// `setgroups`.
    fn setgroups(&self, gid: Gid) -> Result<(), String>;
    /// `setresgid`.
    fn setresgid(&self, gid: Gid) -> Result<(), String>;
    /// `setresuid`.
    fn setresuid(&self, uid: Uid) -> Result<(), String>;
    /// The current bounding set.
    fn bounding(&self) -> Result<CapsHashSet, String>;
    /// Replaces a set.
    fn set(&self, cset: SetKind, caps: &CapsHashSet) -> Result<(), String>;
    /// Drops one capability from a set.
    fn drop(&self, cset: SetKind, cap: Capability) -> Result<(), String>;
    /// Clears a set.
    fn clear(&self, cset: SetKind) -> Result<(), String>;
    /// `PR_SET_NO_NEW_PRIVS`.
    fn set_no_new_privs(&self) -> Result<(), String>;
}

/// Production [`CapOps`] over the `caps` crate and `nix`.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemCaps;

impl CapOps for SystemCaps {
    fn is_root(&self) -> bool {
        Uid::effective().is_root()
    }

    fn lookup(&self, user: &str) -> Result<Option<Account>, String> {
        nix::unistd::User::from_name(user)
            .map(|u| {
                u.map(|u| Account {
                    uid: u.uid,
                    gid: u.gid,
                })
            })
            .map_err(|e| e.to_string())
    }

    fn set_keepcaps(&self, keep: bool) -> Result<(), String> {
        caps::securebits::set_keepcaps(keep).map_err(|e| e.to_string())
    }

    fn setgroups(&self, gid: Gid) -> Result<(), String> {
        nix::unistd::setgroups(&[gid]).map_err(|e| e.to_string())
    }

    fn setresgid(&self, gid: Gid) -> Result<(), String> {
        nix::unistd::setresgid(gid, gid, gid).map_err(|e| e.to_string())
    }

    fn setresuid(&self, uid: Uid) -> Result<(), String> {
        nix::unistd::setresuid(uid, uid, uid).map_err(|e| e.to_string())
    }

    fn bounding(&self) -> Result<CapsHashSet, String> {
        caps::read(None, CapSet::Bounding).map_err(|e| e.to_string())
    }

    fn set(&self, cset: SetKind, caps: &CapsHashSet) -> Result<(), String> {
        caps::set(None, cset.into(), caps).map_err(|e| e.to_string())
    }

    fn drop(&self, cset: SetKind, cap: Capability) -> Result<(), String> {
        caps::drop(None, cset.into(), cap).map_err(|e| e.to_string())
    }

    fn clear(&self, cset: SetKind) -> Result<(), String> {
        caps::clear(None, cset.into()).map_err(|e| e.to_string())
    }

    fn set_no_new_privs(&self) -> Result<(), String> {
        nix::sys::prctl::set_no_new_privs().map_err(|e| e.to_string())
    }
}

fn step(name: &'static str, result: Result<(), String>) -> Result<(), PrivilegeError> {
    result.map_err(|reason| PrivilegeError::Step { step: name, reason })
}

/// Runs the §5.4 sequence for the named service account, or skips it
/// with a warning when not root (C-18).
pub fn drop_privileges(
    user: &str,
    ops: &dyn CapOps,
    authority: &Authority,
) -> Result<Outcome, PrivilegeError> {
    if !ops.is_root() {
        tracing::warn!(
            event = "privilege_drop_skipped",
            "not running as root; capabilities are not dropped (a refusal under enforced hardening; otherwise freeze, trim and shutdown will fail with EPERM)"
        );
        return Ok(Outcome::SkippedUnprivileged);
    }
    let account = ops
        .lookup(user)
        .map_err(|reason| PrivilegeError::Step {
            step: "user lookup",
            reason,
        })?
        .ok_or_else(|| PrivilegeError::UnknownUser(user.to_owned()))?;
    drop_privileges_to(account, ops, authority)?;
    Ok(Outcome::Dropped)
}

/// Runs the §5.4 sequence for an already resolved account, keeping the
/// final set of `authority`. Does not check for root; every step reports
/// its own failure.
pub fn drop_privileges_to(
    account: Account,
    ops: &dyn CapOps,
    authority: &Authority,
) -> Result<(), PrivilegeError> {
    let finals = final_capability_set(authority);
    let mut with_setpcap = finals.clone();
    with_setpcap.insert(Capability::CAP_SETPCAP);

    // 2. Keep the permitted set across the uid change.
    step("PR_SET_KEEPCAPS", ops.set_keepcaps(true))?;
    // 3. Become the service account (groups first, while CAP_SETGID holds).
    step("setgroups", ops.setgroups(account.gid))?;
    step("setresgid", ops.setresgid(account.gid))?;
    step("setresuid", ops.setresuid(account.uid))?;
    // 4. Re-raise the finals plus the CAP_SETPCAP needed to trim the
    //    bounding set (the uid change cleared the effective set).
    step(
        "raise permitted",
        ops.set(SetKind::Permitted, &with_setpcap),
    )?;
    step(
        "raise effective",
        ops.set(SetKind::Effective, &with_setpcap),
    )?;
    // 5. Trim the bounding set to the finals (CAP_SETPCAP included), then
    //    clear everything non-final everywhere.
    let bounding = ops.bounding().map_err(|reason| PrivilegeError::Step {
        step: "read bounding set",
        reason,
    })?;
    let mut to_drop: Vec<Capability> = bounding
        .into_iter()
        .filter(|cap| !finals.contains(cap))
        .collect();
    to_drop.sort_by_key(|cap| cap.index());
    for cap in to_drop {
        step("bounding set drop", ops.drop(SetKind::Bounding, cap))?;
    }
    // Effective before permitted: the kernel refuses a permitted set that
    // no longer covers the effective set.
    step("set effective", ops.set(SetKind::Effective, &finals))?;
    step("set permitted", ops.set(SetKind::Permitted, &finals))?;
    step("clear inheritable", ops.clear(SetKind::Inheritable))?;
    step("clear ambient", ops.clear(SetKind::Ambient))?;
    step("PR_SET_KEEPCAPS", ops.set_keepcaps(false))?;
    // 6. No way back up; seccomp follows in the caller.
    step("PR_SET_NO_NEW_PRIVS", ops.set_no_new_privs())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// Records the plan; every operation succeeds unless scripted.
    struct FakeCaps {
        root: bool,
        users: Vec<(&'static str, Account)>,
        bounding: CapsHashSet,
        steps: RefCell<Vec<Step>>,
        fail: Option<&'static str>,
    }

    impl FakeCaps {
        fn root() -> Self {
            FakeCaps {
                root: true,
                users: vec![(
                    "qeminga",
                    Account {
                        uid: Uid::from_raw(600),
                        gid: Gid::from_raw(600),
                    },
                )],
                bounding: caps::all(),
                steps: RefCell::new(Vec::new()),
                fail: None,
            }
        }
        fn record(&self, s: Step) -> Result<(), String> {
            let name = match &s {
                Step::KeepCaps(_) => "keepcaps",
                Step::SetGroups(_) => "setgroups",
                Step::SetResGid(_) => "setresgid",
                Step::SetResUid(_) => "setresuid",
                Step::Set(..) => "set",
                Step::Drop(..) => "drop",
                Step::Clear(_) => "clear",
                Step::NoNewPrivs => "nnp",
            };
            self.steps.borrow_mut().push(s);
            if self.fail == Some(name) {
                return Err("scripted failure".to_owned());
            }
            Ok(())
        }
    }

    fn sorted(set: &CapsHashSet) -> Vec<Capability> {
        let mut v: Vec<Capability> = set.iter().copied().collect();
        v.sort_by_key(|c| c.index());
        v
    }

    impl CapOps for FakeCaps {
        fn is_root(&self) -> bool {
            self.root
        }
        fn lookup(&self, user: &str) -> Result<Option<Account>, String> {
            Ok(self.users.iter().find(|(n, _)| *n == user).map(|(_, a)| *a))
        }
        fn set_keepcaps(&self, keep: bool) -> Result<(), String> {
            self.record(Step::KeepCaps(keep))
        }
        fn setgroups(&self, gid: Gid) -> Result<(), String> {
            self.record(Step::SetGroups(gid))
        }
        fn setresgid(&self, gid: Gid) -> Result<(), String> {
            self.record(Step::SetResGid(gid))
        }
        fn setresuid(&self, uid: Uid) -> Result<(), String> {
            self.record(Step::SetResUid(uid))
        }
        fn bounding(&self) -> Result<CapsHashSet, String> {
            Ok(self.bounding.clone())
        }
        fn set(&self, cset: SetKind, caps: &CapsHashSet) -> Result<(), String> {
            self.record(Step::Set(cset, sorted(caps)))
        }
        fn drop(&self, cset: SetKind, cap: Capability) -> Result<(), String> {
            self.record(Step::Drop(cset, cap))
        }
        fn clear(&self, cset: SetKind) -> Result<(), String> {
            self.record(Step::Clear(cset))
        }
        fn set_no_new_privs(&self) -> Result<(), String> {
            self.record(Step::NoNewPrivs)
        }
    }

    #[test]
    fn final_capability_set_is_exactly_three() {
        let set = final_capability_set(&Authority::full());
        assert_eq!(set.len(), 3);
        assert!(set.contains(&Capability::CAP_SYS_ADMIN));
        assert!(set.contains(&Capability::CAP_SYS_BOOT));
        assert!(set.contains(&Capability::CAP_DAC_READ_SEARCH));
        assert!(!set.contains(&Capability::CAP_SETPCAP));
        assert!(!set.contains(&Capability::CAP_DAC_OVERRIDE));
    }

    #[test]
    fn a_profile_without_shutdown_gives_up_cap_sys_boot_everywhere() {
        // #43 §5: with `guest-shutdown` disabled the final set is two
        // capabilities, CAP_SYS_BOOT is trimmed from the bounding set with
        // the rest, and nothing re-raises it.
        let set = final_capability_set(&Authority::data_protection());
        assert_eq!(
            sorted(&set),
            [Capability::CAP_DAC_READ_SEARCH, Capability::CAP_SYS_ADMIN]
        );
        let ops = FakeCaps::root();
        assert_eq!(
            drop_privileges("qeminga", &ops, &Authority::data_protection()),
            Ok(Outcome::Dropped)
        );
        let steps = ops.steps.borrow().clone();
        assert!(
            steps.contains(&Step::Drop(SetKind::Bounding, Capability::CAP_SYS_BOOT)),
            "{steps:?}"
        );
        for step in &steps {
            if let Step::Set(_, caps) = step {
                assert!(!caps.contains(&Capability::CAP_SYS_BOOT), "{step:?}");
            }
        }
        // Information and trim have no capability of their own: the set
        // is the same with or without them.
        let info_only = Authority {
            reboot: false,
            information: true,
            trim: true,
            suspend: true,
        };
        assert_eq!(final_capability_set(&info_only), set);
    }

    #[test]
    fn drop_plan_lists_steps_in_design_order() {
        let ops = FakeCaps::root();
        assert_eq!(
            drop_privileges("qeminga", &ops, &Authority::full()),
            Ok(Outcome::Dropped)
        );
        let steps = ops.steps.borrow().clone();
        let uid = Uid::from_raw(600);
        let gid = Gid::from_raw(600);
        let finals = sorted(&final_capability_set(&Authority::full()));
        let mut with_setpcap = final_capability_set(&Authority::full());
        with_setpcap.insert(Capability::CAP_SETPCAP);
        let with_setpcap = sorted(&with_setpcap);

        // 2–4: keepcaps, identity change, re-raise finals + SETPCAP.
        assert_eq!(
            &steps[..6],
            &[
                Step::KeepCaps(true),
                Step::SetGroups(gid),
                Step::SetResGid(gid),
                Step::SetResUid(uid),
                Step::Set(SetKind::Permitted, with_setpcap.clone()),
                Step::Set(SetKind::Effective, with_setpcap),
            ]
        );
        // 5: bounding-set trim of every non-final capability, SETPCAP
        // included, in a deterministic order.
        let drops: Vec<Capability> = steps[6..]
            .iter()
            .take_while(|s| matches!(s, Step::Drop(SetKind::Bounding, _)))
            .map(|s| match s {
                Step::Drop(_, cap) => *cap,
                _ => unreachable!(),
            })
            .collect();
        let expected: Vec<Capability> = {
            let mut v: Vec<Capability> = caps::all()
                .into_iter()
                .filter(|c| !final_capability_set(&Authority::full()).contains(c))
                .collect();
            v.sort_by_key(|c| c.index());
            v
        };
        assert_eq!(drops, expected);
        assert!(drops.contains(&Capability::CAP_SETPCAP));
        assert!(!drops.contains(&Capability::CAP_SYS_ADMIN));
        // then the non-final e/p/i/ambient clearing and 6: no_new_privs.
        let tail = &steps[6 + drops.len()..];
        assert_eq!(
            tail,
            &[
                Step::Set(SetKind::Effective, finals.clone()),
                Step::Set(SetKind::Permitted, finals),
                Step::Clear(SetKind::Inheritable),
                Step::Clear(SetKind::Ambient),
                Step::KeepCaps(false),
                Step::NoNewPrivs,
            ]
        );
        assert!(
            matches!(steps.last(), Some(Step::NoNewPrivs)),
            "NNP is last"
        );
    }

    #[test]
    fn unprivileged_start_skips_drop_with_warning() {
        let mut ops = FakeCaps::root();
        ops.root = false;
        assert_eq!(
            drop_privileges("qeminga", &ops, &Authority::full()),
            Ok(Outcome::SkippedUnprivileged)
        );
        assert!(ops.steps.borrow().is_empty(), "nothing is changed");
        // The warning is a structured event; capture it.
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let router = crate::audit::Router::new(Box::new(Sink(sink.clone())));
        tracing::subscriber::with_default(
            crate::audit::subscriber(tracing::Level::WARN, router),
            || {
                drop_privileges("qeminga", &ops, &Authority::full()).unwrap();
            },
        );
        let text = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(text.contains("privilege_drop_skipped"), "{text}");
        assert!(text.contains("\"level\":\"WARN\""), "{text}");
    }

    #[test]
    fn unknown_user_and_step_failures_are_reported() {
        let ops = FakeCaps::root();
        assert_eq!(
            drop_privileges("nobody-here", &ops, &Authority::full()),
            Err(PrivilegeError::UnknownUser("nobody-here".to_owned()))
        );
        assert!(ops.steps.borrow().is_empty());
        let mut ops = FakeCaps::root();
        ops.fail = Some("setresuid");
        let err = drop_privileges("qeminga", &ops, &Authority::full()).unwrap_err();
        assert_eq!(
            err,
            PrivilegeError::Step {
                step: "setresuid",
                reason: "scripted failure".to_owned()
            }
        );
        assert_eq!(err.to_string(), "setresuid failed: scripted failure");
        assert_eq!(ops.steps.borrow().len(), 4, "stops at the failed step");
    }

    /// Re-executes this test binary as a child (env `QEMINGA_CAPS_CHILD`)
    /// which performs the real drop to uid/gid 65534 and prints its
    /// capability sets; the parent checks them (AC3).
    #[test]
    #[ignore = "needs root: performs a real uid change and capability drop in a child process"]
    fn privileged_drop_leaves_exactly_final_caps() {
        if std::env::var_os("QEMINGA_CAPS_CHILD").is_some() {
            let account = Account {
                uid: Uid::from_raw(65534),
                gid: Gid::from_raw(65534),
            };
            drop_privileges_to(account, &SystemCaps, &Authority::full()).expect("drop");
            let report = |cset: CapSet| {
                let mut v: Vec<String> = caps::read(None, cset)
                    .unwrap()
                    .iter()
                    .map(|c| c.to_string())
                    .collect();
                v.sort();
                v.join(",")
            };
            println!("CHILD effective={}", report(CapSet::Effective));
            println!("CHILD permitted={}", report(CapSet::Permitted));
            println!("CHILD bounding={}", report(CapSet::Bounding));
            println!("CHILD inheritable={}", report(CapSet::Inheritable));
            println!("CHILD ambient={}", report(CapSet::Ambient));
            println!("CHILD nnp={}", nix::sys::prctl::get_no_new_privs().unwrap());
            println!("CHILD uid={} gid={}", Uid::effective(), Gid::effective());
            return;
        }
        assert!(Uid::effective().is_root(), "run as root");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "kernel::caps::tests::privileged_drop_leaves_exactly_final_caps",
                "--ignored",
                "--nocapture",
            ])
            .env("QEMINGA_CAPS_CHILD", "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let field = |name: &str| -> String {
            stdout
                .lines()
                .find_map(|l| l.strip_prefix(&format!("CHILD {name}=")))
                .unwrap_or_else(|| panic!("{name} missing in {stdout}"))
                .to_owned()
        };
        let finals = "CAP_DAC_READ_SEARCH,CAP_SYS_ADMIN,CAP_SYS_BOOT";
        assert_eq!(field("effective"), finals);
        assert_eq!(field("permitted"), finals);
        assert_eq!(field("bounding"), finals, "nothing can be regained");
        assert_eq!(field("inheritable"), "");
        assert_eq!(field("ambient"), "");
        assert_eq!(field("nnp"), "true");
        assert_eq!(field("uid"), "65534 gid=65534");
    }

    /// `PR_GET_NO_NEW_PRIVS` after the drop; covered by the child report
    /// above and kept as its own named entry point.
    #[test]
    #[ignore = "needs root: see privileged_drop_leaves_exactly_final_caps"]
    fn privileged_no_new_privs_is_set() {
        privileged_drop_leaves_exactly_final_caps();
    }
}
