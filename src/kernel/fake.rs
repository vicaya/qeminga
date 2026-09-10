//! A scripted [`KernelOps`] test double.
//!
//! Records every call in order and returns per-path scripted results.
//! Compiled unconditionally so integration and end-to-end tests can use
//! it; it performs no kernel operation of any kind.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use nix::errno::Errno;

use super::{KernelError, KernelOps, Mount, RebootCommand, Trimmed};

/// One recorded call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `open_mount(path, dev)`.
    Open(PathBuf, (u32, u32)),
    /// `fifreeze(path)` (the handle's mountpoint).
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

/// A barrier a scripted `fifreeze` or `fithaw` waits at, modelling an
/// ioctl that blocks in the kernel. The call is recorded first and waits
/// *outside* the fake's mutex, so calls on other targets, `calls()` and
/// the scripts proceed meanwhile; the scripted result applies once the
/// gate is released. Tests hold a [`ReleaseOnDrop`] so a failed assertion
/// cannot leave a worker (and the runtime's shutdown) blocked.
#[derive(Clone, Debug, Default)]
pub struct Gate {
    inner: Arc<GateInner>,
}

#[derive(Debug, Default)]
struct GateInner {
    released: Mutex<bool>,
    changed: Condvar,
    waiting: AtomicUsize,
}

impl Gate {
    /// A closed gate.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lets every current and future waiter through.
    pub fn release(&self) {
        *self.lock() = true;
        self.inner.changed.notify_all();
    }

    /// `true` once released.
    pub fn is_released(&self) -> bool {
        *self.lock()
    }

    /// Number of calls currently blocked at the gate.
    pub fn waiting(&self) -> usize {
        self.inner.waiting.load(Ordering::SeqCst)
    }

    /// A guard that releases the gate when dropped.
    pub fn release_on_drop(&self) -> ReleaseOnDrop {
        ReleaseOnDrop(self.clone())
    }

    /// Blocks the calling thread until the gate is released (what the
    /// scripted calls do; test doubles of other traits can use it too).
    pub fn wait(&self) {
        self.inner.waiting.fetch_add(1, Ordering::SeqCst);
        let mut released = self.lock();
        while !*released {
            released = self
                .inner
                .changed
                .wait(released)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        drop(released);
        self.inner.waiting.fetch_sub(1, Ordering::SeqCst);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, bool> {
        self.inner
            .released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Releases its [`Gate`] when dropped.
#[derive(Debug)]
pub struct ReleaseOnDrop(Gate);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Default)]
struct Inner {
    calls: Vec<Call>,
    open_errors: HashMap<PathBuf, Errno>,
    devices: HashMap<PathBuf, (u32, u32)>,
    freeze_errors: HashMap<PathBuf, Errno>,
    thaw_successes: HashMap<PathBuf, u32>,
    thaw_errors: HashMap<PathBuf, Errno>,
    trim_results: HashMap<PathBuf, Result<(u64, Option<u64>), Errno>>,
    reboot_error: Option<Errno>,
    freeze_gates: HashMap<PathBuf, Gate>,
    thaw_gates: HashMap<PathBuf, Gate>,
    trim_gates: HashMap<PathBuf, Gate>,
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
    /// A fake where every mountpoint opens on the device asked for, every
    /// freeze succeeds, every thaw succeeds once and then returns
    /// `EINVAL`, every trim reports 0 bytes, and reboot succeeds.
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

    /// Lifts every scripted `fithaw` error (the kernel permits the drain
    /// again).
    pub fn clear_thaw_errors(&self) {
        self.lock().thaw_errors.clear();
    }

    /// Makes `open_mount(path, _)` fail with `errno`
    /// ([`KernelError::Open`]: no ioctl issued on that path).
    pub fn script_open_error(&self, path: impl AsRef<Path>, errno: Errno) {
        self.lock()
            .open_errors
            .insert(path.as_ref().to_owned(), errno);
    }

    /// Makes `path` lead to `dev` from now on: `open_mount(path, planned)`
    /// answers [`KernelError::WrongFilesystem`] unless `planned == dev`
    /// (models a mount placed over the planned one). Handles opened
    /// before keep their device, like real descriptors.
    pub fn script_mount_device(&self, path: impl AsRef<Path>, dev: (u32, u32)) {
        self.lock().devices.insert(path.as_ref().to_owned(), dev);
    }

    /// Scripts the result of `fitrim(path, _)`: the bytes trimmed (the
    /// effective minimum is the requested one) or an errno.
    pub fn script_trim(&self, path: impl AsRef<Path>, result: Result<u64, Errno>) {
        self.lock()
            .trim_results
            .insert(path.as_ref().to_owned(), result.map(|bytes| (bytes, None)));
    }

    /// Scripts `fitrim(path, _)` to report `bytes` trimmed with `minimum`
    /// as the effective minimum extent, whatever was requested (models a
    /// kernel rounding the request up to its discard granularity).
    pub fn script_trim_rounded(&self, path: impl AsRef<Path>, bytes: u64, minimum: u64) {
        self.lock()
            .trim_results
            .insert(path.as_ref().to_owned(), Ok((bytes, Some(minimum))));
    }

    /// Makes `reboot` fail with `errno`.
    pub fn script_reboot_error(&self, errno: Errno) {
        self.lock().reboot_error = Some(errno);
    }

    /// Makes every `fifreeze(path)` wait at the returned [`Gate`] (after
    /// being recorded, outside the fake's mutex) until it is released; the
    /// scripted result then applies.
    pub fn script_freeze_gate(&self, path: impl AsRef<Path>) -> Gate {
        let gate = Gate::new();
        self.lock()
            .freeze_gates
            .insert(path.as_ref().to_owned(), gate.clone());
        gate
    }

    /// Makes every `fithaw(path)` wait at the returned [`Gate`], as
    /// [`script_freeze_gate`](Self::script_freeze_gate) does for freezes.
    pub fn script_thaw_gate(&self, path: impl AsRef<Path>) -> Gate {
        let gate = Gate::new();
        self.lock()
            .thaw_gates
            .insert(path.as_ref().to_owned(), gate.clone());
        gate
    }

    /// Makes every `fitrim(path, _)` wait at the returned [`Gate`], as
    /// [`script_freeze_gate`](Self::script_freeze_gate) does for freezes.
    pub fn script_trim_gate(&self, path: impl AsRef<Path>) -> Gate {
        let gate = Gate::new();
        self.lock()
            .trim_gates
            .insert(path.as_ref().to_owned(), gate.clone());
        gate
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
    fn open_mount(&self, mountpoint: &Path, dev: (u32, u32)) -> Result<Mount, KernelError> {
        self.record(Call::Open(mountpoint.to_owned(), dev));
        let inner = self.lock();
        if let Some(errno) = inner.open_errors.get(mountpoint) {
            return Err(KernelError::Open(*errno));
        }
        match inner.devices.get(mountpoint) {
            Some(found) if *found != dev => Err(KernelError::WrongFilesystem {
                expected: dev,
                found: *found,
            }),
            _ => Ok(Mount::unopened(mountpoint, dev)),
        }
    }

    fn fifreeze(&self, mount: &Mount) -> Result<(), KernelError> {
        let mountpoint = mount.mountpoint();
        self.record(Call::Fifreeze(mountpoint.to_owned()));
        let gate = self.lock().freeze_gates.get(mountpoint).cloned();
        if let Some(gate) = gate {
            gate.wait();
        }
        match self.lock().freeze_errors.get(mountpoint) {
            Some(errno) => Err(KernelError::Errno(*errno)),
            None => Ok(()),
        }
    }

    fn fithaw(&self, mount: &Mount) -> Result<(), KernelError> {
        let mountpoint = mount.mountpoint();
        self.record(Call::Fithaw(mountpoint.to_owned()));
        let gate = self.lock().thaw_gates.get(mountpoint).cloned();
        if let Some(gate) = gate {
            gate.wait();
        }
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

    fn fitrim(&self, mount: &Mount, minimum: u64) -> Result<Trimmed, KernelError> {
        let mountpoint = mount.mountpoint();
        self.record(Call::Fitrim(mountpoint.to_owned(), minimum));
        let gate = self.lock().trim_gates.get(mountpoint).cloned();
        if let Some(gate) = gate {
            gate.wait();
        }
        match self.lock().trim_results.get(mountpoint) {
            Some(Ok((bytes, effective))) => Ok(Trimmed {
                bytes: *bytes,
                minimum: effective.unwrap_or(minimum),
            }),
            Some(Err(errno)) => Err(KernelError::Errno(*errno)),
            None => Ok(Trimmed { bytes: 0, minimum }),
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

    /// An unopened handle, as the fake's `open_mount` hands out.
    fn at(path: &str) -> Mount {
        Mount::unopened(path, (8, 1))
    }

    #[test]
    fn a_gated_freeze_waits_outside_the_fake_mutex_until_released() {
        // The gate models a FIFREEZE that blocks in the kernel: the call is
        // recorded first, then waits without holding the fake's mutex, so
        // other targets' calls and `calls()` proceed meanwhile.
        let k = Arc::new(FakeKernel::new());
        let gate = k.script_freeze_gate("/home");
        let _release = gate.release_on_drop();
        let worker = {
            let k = Arc::clone(&k);
            std::thread::spawn(move || k.fifreeze(&Mount::unopened("/home", (8, 2))))
        };
        while gate.waiting() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(k.calls(), vec![Call::Fifreeze("/home".into())]);
        k.fifreeze(&at("/")).unwrap();
        assert_eq!(gate.waiting(), 1);
        assert!(!worker.is_finished());
        gate.release();
        worker.join().unwrap().unwrap();
        assert_eq!(gate.waiting(), 0);
        assert!(gate.is_released());
        // A released gate no longer blocks.
        k.fifreeze(&Mount::unopened("/home", (8, 2))).unwrap();
    }

    #[test]
    fn a_gated_thaw_waits_and_a_scripted_error_still_applies_after_release() {
        let k = Arc::new(FakeKernel::new());
        let gate = k.script_thaw_gate("/");
        k.script_thaw_error("/", Errno::EACCES);
        let worker = {
            let k = Arc::clone(&k);
            std::thread::spawn(move || k.fithaw(&at("/")))
        };
        while gate.waiting() == 0 {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(!worker.is_finished());
        drop(gate.release_on_drop());
        let err = worker.join().unwrap().unwrap_err();
        assert!(matches!(err, KernelError::Errno(Errno::EACCES)));
    }

    #[test]
    fn fake_records_calls_in_order() {
        let k = FakeKernel::new();
        let home = k.open_mount(Path::new("/home"), (8, 2)).unwrap();
        assert!(!home.is_open(), "the fake holds no descriptor");
        assert_eq!(home.mountpoint(), Path::new("/home"));
        assert_eq!(home.dev(), (8, 2));
        k.fifreeze(&home).unwrap();
        k.fifreeze(&at("/")).unwrap();
        k.fithaw(&at("/")).unwrap();
        k.fitrim(&at("/"), 4096).unwrap();
        k.sync();
        k.reboot(RebootCommand::Halt).unwrap();
        assert_eq!(
            k.calls(),
            vec![
                Call::Open("/home".into(), (8, 2)),
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
    fn fake_open_mount_is_scripted_per_path() {
        let k = FakeKernel::new();
        // Unscripted: the path is on whatever device is asked for.
        assert_eq!(
            k.open_mount(Path::new("/data"), (8, 2)).unwrap().dev(),
            (8, 2)
        );
        // Scripted device: the planned device must match, as a real fstat
        // on the opened directory would find.
        k.script_mount_device("/data", (8, 3));
        let err = k.open_mount(Path::new("/data"), (8, 2)).unwrap_err();
        assert_eq!(
            err,
            KernelError::WrongFilesystem {
                expected: (8, 2),
                found: (8, 3)
            }
        );
        assert!(k.open_mount(Path::new("/data"), (8, 3)).is_ok());
        // Scripted open failure: no handle at all.
        k.script_open_error("/mnt/full", Errno::EMFILE);
        assert_eq!(
            k.open_mount(Path::new("/mnt/full"), (8, 4)).unwrap_err(),
            KernelError::Open(Errno::EMFILE)
        );
        assert_eq!(k.calls().len(), 4);
    }

    #[test]
    fn fake_returns_scripted_errno_per_path() {
        let k = FakeKernel::new();
        k.script_freeze_error("/proc", Errno::EOPNOTSUPP);
        k.script_freeze_error("/mnt/busy", Errno::EBUSY);
        k.script_freeze_error("/mnt/bad", Errno::EIO);
        assert_eq!(k.fifreeze(&at("/mnt/a")), Ok(()));
        assert!(k.fifreeze(&at("/proc")).unwrap_err().is_not_supported());
        assert!(k.fifreeze(&at("/mnt/busy")).unwrap_err().is_busy());
        assert_eq!(
            k.fifreeze(&at("/mnt/bad")),
            Err(KernelError::Errno(Errno::EIO))
        );
        k.script_trim("/mnt/a", Ok(123));
        k.script_trim("/mnt/bad", Err(Errno::EOPNOTSUPP));
        k.script_trim_rounded("/mnt/coarse", 7, 4096);
        let trimmed = |bytes, minimum| Ok(Trimmed { bytes, minimum });
        assert_eq!(k.fitrim(&at("/mnt/a"), 0), trimmed(123, 0));
        assert_eq!(k.fitrim(&at("/mnt/a"), 512), trimmed(123, 512));
        assert_eq!(k.fitrim(&at("/mnt/other"), 0), trimmed(0, 0));
        assert_eq!(
            k.fitrim(&at("/mnt/coarse"), 1),
            trimmed(7, 4096),
            "the effective minimum, not the requested one"
        );
        assert!(k.fitrim(&at("/mnt/bad"), 0).unwrap_err().is_not_supported());
        k.script_reboot_error(Errno::EPERM);
        assert!(
            k.reboot(RebootCommand::PowerOff)
                .unwrap_err()
                .is_permission()
        );
        k.script_thaw_error("/mnt/bad", Errno::EACCES);
        assert!(k.fithaw(&at("/mnt/bad")).unwrap_err().is_permission());
        assert!(k.fithaw(&at("/mnt/bad")).unwrap_err().is_permission());
    }

    #[test]
    fn fake_thaw_succeeds_n_times_then_einval() {
        let k = FakeKernel::new();
        k.script_thaw_successes("/", 3);
        let root = at("/");
        for _ in 0..3 {
            assert_eq!(k.fithaw(&root), Ok(()));
        }
        assert!(k.fithaw(&root).unwrap_err().is_invalid());
        assert!(k.fithaw(&root).unwrap_err().is_invalid());
        // Unscripted: exactly once.
        assert_eq!(k.fithaw(&at("/home")), Ok(()));
        assert!(k.fithaw(&at("/home")).unwrap_err().is_invalid());
        // Zero successes: EINVAL from the start.
        k.script_thaw_successes("/none", 0);
        assert!(k.fithaw(&at("/none")).unwrap_err().is_invalid());
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
        k.fifreeze(&at("/")).unwrap();
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
