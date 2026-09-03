//! A scripted [`KernelOps`] test double.
//!
//! Records every call in order and returns per-path scripted results.
//! Compiled unconditionally so integration and end-to-end tests can use
//! it; it performs no kernel operation of any kind.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use nix::errno::Errno;

use super::{KernelError, KernelOps, RebootCommand};

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `fifreeze(path)`.
    Fifreeze(PathBuf),
    /// `fithaw(path)`.
    Fithaw(PathBuf),
    /// `fitrim(path, minimum)`.
    Fitrim(PathBuf, u64),
    /// `sync()`.
    Sync,
    /// `reboot(cmd)`.
    Reboot(RebootCommand),
}

/// Observer invoked synchronously on every call, before its scripted
/// result is returned (used to check ordering against other components).
pub type Hook = Box<dyn Fn(&Call) + Send + Sync>;

#[derive(Default)]
struct Inner {
    calls: Vec<Call>,
    freeze_errors: HashMap<PathBuf, Errno>,
    thaw_successes: HashMap<PathBuf, u32>,
    thaw_errors: HashMap<PathBuf, Errno>,
    trim_results: HashMap<PathBuf, Result<u64, Errno>>,
    reboot_error: Option<Errno>,
    hook: Option<Hook>,
}

/// The fake kernel. Thread-safe; cheap to share behind an `Arc`.
#[derive(Default)]
pub struct FakeKernel {
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for FakeKernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeKernel")
            .field("calls", &self.calls())
            .finish_non_exhaustive()
    }
}

impl FakeKernel {
    /// A fake where every freeze succeeds, every thaw succeeds once and
    /// then returns `EINVAL`, every trim reports 0 bytes, and reboot
    /// succeeds.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Every call so far, in order.
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// Forgets the recorded calls (scripts stay).
    pub fn clear_calls(&self) {
        self.lock().calls.clear();
    }

    /// Makes `fifreeze(path)` fail with `errno`.
    pub fn script_freeze_error(&self, path: impl AsRef<Path>, errno: Errno) {
        self.lock()
            .freeze_errors
            .insert(path.as_ref().to_owned(), errno);
    }

    /// Makes `fithaw(path)` succeed `n` times and then return `EINVAL`
    /// (models the kernel's freeze nesting depth). Unscripted paths
    /// succeed once.
    pub fn script_thaw_successes(&self, path: impl AsRef<Path>, n: u32) {
        self.lock()
            .thaw_successes
            .insert(path.as_ref().to_owned(), n);
    }

    /// Makes every `fithaw(path)` fail with `errno` immediately.
    pub fn script_thaw_error(&self, path: impl AsRef<Path>, errno: Errno) {
        self.lock()
            .thaw_errors
            .insert(path.as_ref().to_owned(), errno);
    }

    /// Scripts the result of `fitrim(path, _)`.
    pub fn script_trim(&self, path: impl AsRef<Path>, result: Result<u64, Errno>) {
        self.lock()
            .trim_results
            .insert(path.as_ref().to_owned(), result);
    }

    /// Makes `reboot` fail with `errno`.
    pub fn script_reboot_error(&self, errno: Errno) {
        self.lock().reboot_error = Some(errno);
    }

    /// Installs an observer called on every operation.
    pub fn set_hook(&self, hook: Hook) {
        self.lock().hook = Some(hook);
    }

    fn record(&self, call: Call) {
        let mut inner = self.lock();
        if let Some(hook) = &inner.hook {
            hook(&call);
        }
        inner.calls.push(call);
    }
}

impl KernelOps for FakeKernel {
    fn fifreeze(&self, mountpoint: &Path) -> Result<(), KernelError> {
        self.record(Call::Fifreeze(mountpoint.to_owned()));
        match self.lock().freeze_errors.get(mountpoint) {
            Some(errno) => Err(KernelError::Errno(*errno)),
            None => Ok(()),
        }
    }

    fn fithaw(&self, mountpoint: &Path) -> Result<(), KernelError> {
        self.record(Call::Fithaw(mountpoint.to_owned()));
        let mut inner = self.lock();
        if let Some(errno) = inner.thaw_errors.get(mountpoint) {
            return Err(KernelError::Errno(*errno));
        }
        let remaining = inner
            .thaw_successes
            .entry(mountpoint.to_owned())
            .or_insert(1);
        if *remaining > 0 {
            *remaining -= 1;
            Ok(())
        } else {
            Err(KernelError::Errno(Errno::EINVAL))
        }
    }

    fn fitrim(&self, mountpoint: &Path, minimum: u64) -> Result<u64, KernelError> {
        self.record(Call::Fitrim(mountpoint.to_owned(), minimum));
        match self.lock().trim_results.get(mountpoint) {
            Some(Ok(bytes)) => Ok(*bytes),
            Some(Err(errno)) => Err(KernelError::Errno(*errno)),
            None => Ok(0),
        }
    }

    fn sync(&self) {
        self.record(Call::Sync);
    }

    fn reboot(&self, cmd: RebootCommand) -> Result<(), KernelError> {
        self.record(Call::Reboot(cmd));
        match self.lock().reboot_error {
            Some(errno) => Err(KernelError::Errno(errno)),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn fake_records_calls_in_order() {
        let k = FakeKernel::new();
        k.fifreeze(Path::new("/home")).unwrap();
        k.fifreeze(Path::new("/")).unwrap();
        k.fithaw(Path::new("/")).unwrap();
        k.fitrim(Path::new("/"), 4096).unwrap();
        k.sync();
        k.reboot(RebootCommand::Halt).unwrap();
        assert_eq!(
            k.calls(),
            vec![
                Call::Fifreeze("/home".into()),
                Call::Fifreeze("/".into()),
                Call::Fithaw("/".into()),
                Call::Fitrim("/".into(), 4096),
                Call::Sync,
                Call::Reboot(RebootCommand::Halt),
            ]
        );
        k.clear_calls();
        assert!(k.calls().is_empty());
    }

    #[test]
    fn fake_returns_scripted_errno_per_path() {
        let k = FakeKernel::new();
        k.script_freeze_error("/proc", Errno::EOPNOTSUPP);
        k.script_freeze_error("/mnt/busy", Errno::EBUSY);
        k.script_freeze_error("/mnt/bad", Errno::EIO);
        assert_eq!(k.fifreeze(Path::new("/mnt/a")), Ok(()));
        assert!(
            k.fifreeze(Path::new("/proc"))
                .unwrap_err()
                .is_not_supported()
        );
        assert!(k.fifreeze(Path::new("/mnt/busy")).unwrap_err().is_busy());
        assert_eq!(
            k.fifreeze(Path::new("/mnt/bad")),
            Err(KernelError::Errno(Errno::EIO))
        );
        k.script_trim("/mnt/a", Ok(123));
        k.script_trim("/mnt/bad", Err(Errno::EOPNOTSUPP));
        assert_eq!(k.fitrim(Path::new("/mnt/a"), 0), Ok(123));
        assert_eq!(k.fitrim(Path::new("/mnt/other"), 0), Ok(0));
        assert!(
            k.fitrim(Path::new("/mnt/bad"), 0)
                .unwrap_err()
                .is_not_supported()
        );
        k.script_reboot_error(Errno::EPERM);
        assert!(
            k.reboot(RebootCommand::PowerOff)
                .unwrap_err()
                .is_permission()
        );
        k.script_thaw_error("/mnt/bad", Errno::EACCES);
        assert!(k.fithaw(Path::new("/mnt/bad")).unwrap_err().is_permission());
        assert!(k.fithaw(Path::new("/mnt/bad")).unwrap_err().is_permission());
    }

    #[test]
    fn fake_thaw_succeeds_n_times_then_einval() {
        let k = FakeKernel::new();
        k.script_thaw_successes("/", 3);
        let root = Path::new("/");
        for _ in 0..3 {
            assert_eq!(k.fithaw(root), Ok(()));
        }
        assert!(k.fithaw(root).unwrap_err().is_invalid());
        assert!(k.fithaw(root).unwrap_err().is_invalid());
        // Unscripted: exactly once.
        assert_eq!(k.fithaw(Path::new("/home")), Ok(()));
        assert!(k.fithaw(Path::new("/home")).unwrap_err().is_invalid());
        // Zero successes: EINVAL from the start.
        k.script_thaw_successes("/none", 0);
        assert!(k.fithaw(Path::new("/none")).unwrap_err().is_invalid());
        assert_eq!(k.calls().len(), 8);
    }

    #[test]
    fn hook_observes_every_call_before_it_is_recorded() {
        let k = Arc::new(FakeKernel::new());
        let seen = Arc::new(AtomicUsize::new(0));
        let seen2 = Arc::clone(&seen);
        k.set_hook(Box::new(move |call| {
            assert!(matches!(call, Call::Fifreeze(_) | Call::Sync));
            seen2.fetch_add(1, Ordering::SeqCst);
        }));
        k.fifreeze(Path::new("/")).unwrap();
        k.sync();
        assert_eq!(seen.load(Ordering::SeqCst), 2);
        assert_eq!(k.calls().len(), 2);
        let _ = format!("{k:?}");
    }

    #[test]
    fn fake_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FakeKernel>();
        assert_send_sync::<Arc<dyn KernelOps>>();
    }
}
