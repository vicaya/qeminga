#!/usr/bin/env python3
"""FD-anchored filesystem operations for the qemu:///system KVM smoke lane.

Extracted from scripts/ci/libvirt-kvm-smoke.sh so both the shell entrypoint
(via ``python3 -IB``) and unprivileged unit tests can invoke the exact same
verified operations without duplicating parsing or mocking host ``/``.
"""

from collections import deque
import ctypes
import errno
import fcntl
import json
import os
import re
import stat
import struct
import sys
import xml.etree.ElementTree as ET

READ_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
PATH_NOFOLLOW_FLAGS = os.O_PATH | os.O_NOFOLLOW
RENAME_NOREPLACE = 1
SYMLOOP_MAX = 40
RUN_NAME_RE = re.compile(r"^qeminga-e2e-[0-9]+-[0-9]+-(x86_64|aarch64)$")
UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ALLOWED_EVIDENCE_FILES = frozenset(
    {
        "domain.xml",
        "qemu.log",
        "serial.log",
        "result.json",
        "versions.txt",
        "e2e-libvirt.log",
        "cleanup.txt",
    }
)
ALLOWED_TEST_FILES = frozenset(
    {
        "production_install",
        "accelerator_kvm",
        "libvirt_interop",
        "agent_shutdown",
    }
)

# Dedicated exit codes for evidence read/verification ops so callers can
# distinguish confirmed missing/unsafe/invalid evidence from indeterminate
# operational I/O or concurrent identity-change failures (exit 1).
EXIT_EVIDENCE_MISSING = 2
EXIT_EVIDENCE_DIR_UNSAFE = 3
EXIT_EVIDENCE_FILE_UNSAFE = 4
EXIT_EVIDENCE_INVALID = 5


class EvidenceMissingError(OSError):
    """Evidence directory, subdirectory, or file was confirmed absent."""


class EvidenceDirUnsafeError(OSError):
    """Evidence directory or an ancestor failed ownership or writability checks."""


class EvidenceUnsafeError(OSError):
    """Evidence file or tests subdirectory failed type, link, mount, trust, or size checks."""


class EvidenceInvalidError(OSError):
    """Evidence file was read cleanly, but its contents failed JSON/schema validation."""


_LIBC = ctypes.CDLL(None, use_errno=True)
_RENAMEAT2 = getattr(_LIBC, "renameat2", None)
if _RENAMEAT2 is not None:
    _RENAMEAT2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    _RENAMEAT2.restype = ctypes.c_int


def fd_mnt_id(fd):
    """Read the kernel mount ID for an open descriptor from /proc/self/fdinfo."""
    with open(f"/proc/self/fdinfo/{fd}", "r", encoding="ascii", errors="replace") as fh:
        for line in fh:
            if line.startswith("mnt_id:"):
                return int(line.split(":", 1)[1].strip())
    raise OSError(errno.EINVAL, f"missing mnt_id in /proc/self/fdinfo/{fd}")


def renameat2_noreplace(src_dir_fd, src_name, dst_dir_fd, dst_name):
    """Atomically publish src_name -> dst_name without replacing an existing entry.

    Requires kernel/filesystem support for ``renameat2(RENAME_NOREPLACE)`` and
    fails closed before publication when unavailable rather than falling back
    to non-atomic ``lstat`` + ``rename``.
    """
    if _RENAMEAT2 is None:
        raise OSError(
            errno.EOPNOTSUPP,
            f"atomic renameat2(RENAME_NOREPLACE) is unavailable for '{dst_name}'; "
            "refusing non-atomic directory publication",
        )
    rc = _RENAMEAT2(
        src_dir_fd,
        os.fsencode(src_name),
        dst_dir_fd,
        os.fsencode(dst_name),
        RENAME_NOREPLACE,
    )
    if rc == 0:
        return
    err = ctypes.get_errno()
    if err == errno.EEXIST:
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), dst_name)
    if err in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
        raise OSError(
            errno.EOPNOTSUPP,
            f"filesystem does not support atomic renameat2(RENAME_NOREPLACE) for "
            f"'{dst_name}' (errno {err}); refusing non-atomic directory publication",
        )
    raise OSError(err, os.strerror(err), dst_name)


def encode_acl(entries):
    return struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", tag, perm, eid) for tag, perm, eid in entries
    )


def decode_acl_fd(fd, attr=b"system.posix_acl_access"):
    try:
        raw = os.getxattr(fd, attr)
    except OSError as exc:
        if exc.errno in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOSYS):
            return None
        raise
    if not raw or len(raw) < 4:
        return None
    (ver,) = struct.unpack_from("<I", raw, 0)
    if ver != 2:
        return None
    entries = []
    for off in range(4, len(raw), 8):
        if off + 8 <= len(raw):
            entries.append(struct.unpack_from("<HHI", raw, off))
    return entries


def remove_xattr_if_present(fd, attr):
    try:
        os.removexattr(fd, attr)
    except OSError as exc:
        if exc.errno not in (errno.ENODATA, errno.EOPNOTSUPP, errno.ENOSYS):
            raise


def effective_perms_fd(fd, st, uid, groups):
    if uid == 0:
        return 7
    entries = decode_acl_fd(fd, b"system.posix_acl_access")
    if entries:
        mask = 7
        for tag, perm, _ in entries:
            if tag == 0x10:
                mask = perm
        if uid == st.st_uid:
            for tag, perm, _ in entries:
                if tag == 0x01:
                    return perm
            return 0
        for tag, perm, eid in entries:
            if tag == 0x02 and eid == uid:
                return perm & mask
        matched = [
            perm & mask
            for tag, perm, eid in entries
            if (tag == 0x04 and st.st_gid in groups)
            or (tag == 0x08 and eid in groups)
        ]
        if matched:
            val = 0
            for m in matched:
                val |= m
            return val
        for tag, perm, _ in entries:
            if tag == 0x20:
                return perm
        return 0
    if uid == st.st_uid:
        return (st.st_mode >> 6) & 7
    if st.st_gid in groups:
        return (st.st_mode >> 3) & 7
    return st.st_mode & 7


def can_traverse_fd(fd, st, uid, groups):
    return stat.S_ISDIR(st.st_mode) and bool(effective_perms_fd(fd, st, uid, groups) & 1)


def trusted_owner_uids():
    euid = os.geteuid()
    return {0} if euid == 0 else {0, euid}


def dir_trust_info(fd, st, trusted_uids):
    if st.st_uid not in trusted_uids:
        return False, True, f"owned by untrusted uid {st.st_uid}"
    entries = decode_acl_fd(fd, b"system.posix_acl_access")
    if entries:
        mask = 7
        for tag, perm, _ in entries:
            if tag == 0x10:
                mask = perm
        for tag, perm, eid in entries:
            if tag == 0x20 and (perm & 2):
                return True, True, "world-writable via POSIX ACL"
            if tag == 0x02 and eid not in trusted_uids and ((perm & mask) & 2):
                return True, True, f"writable by named uid {eid} via POSIX ACL"
            if tag == 0x04 and ((perm & mask) & 2):
                return True, True, f"group-writable (gid {st.st_gid}) via POSIX ACL"
            if tag == 0x08 and ((perm & mask) & 2):
                return True, True, f"writable by named gid {eid} via POSIX ACL"
        return True, False, ""
    if st.st_mode & 0o002:
        return True, True, f"world-writable (mode {oct(st.st_mode & 0o7777)})"
    if st.st_mode & 0o020:
        return True, True, f"group-writable (mode {oct(st.st_mode & 0o7777)})"
    return True, False, ""


def kernel_verdict_traversal(original_path, qemu_uid, qemu_gid, qemu_groups):
    if os.geteuid() != 0 or qemu_uid == 0:
        return
    r_fd, w_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        code = 0
        msg = b""
        try:
            os.setgroups(sorted(qemu_groups))
            os.setgid(qemu_gid)
            os.setuid(qemu_uid)
            st = os.stat(original_path)
            if not stat.S_ISDIR(st.st_mode):
                raise OSError(errno.ENOTDIR, f"'{original_path}' is not a directory")
            if not os.access(original_path, os.X_OK):
                raise OSError(errno.EACCES, f"kernel denied X_OK on '{original_path}'")
        except OSError as exc:
            code = 1
            msg = f"{exc.strerror or exc} (errno {exc.errno})".encode(
                "utf-8", errors="replace"
            )
        except Exception as exc:
            code = 1
            msg = str(exc).encode("utf-8", errors="replace")
        try:
            if msg:
                os.write(w_fd, msg)
        finally:
            os.close(w_fd)
            os._exit(code)
    os.close(w_fd)
    chunks = []
    try:
        while True:
            chunk = os.read(r_fd, 4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(r_fd)
    _, status = os.waitpid(pid, 0)
    if not (os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0):
        detail = (
            b"".join(chunks).decode("utf-8", errors="replace").strip()
            or f"status={status}"
        )
        raise OSError(
            errno.EACCES,
            f"kernel denied traversal of '{original_path}' for uid {qemu_uid}: {detail}",
        )


def verify_dir_fd(
    dfd,
    path_label,
    qemu_uid,
    qemu_groups,
    trusted_uids,
    allow_sticky_writable=True,
    check_traversal=True,
):
    st = os.fstat(dfd)
    if not stat.S_ISDIR(st.st_mode):
        raise EvidenceDirUnsafeError(
            errno.ENOTDIR, f"path component '{path_label}' is not a directory"
        )
    trusted_owner, is_writable, reason = dir_trust_info(dfd, st, trusted_uids)
    if not trusted_owner:
        raise EvidenceDirUnsafeError(
            errno.EACCES,
            f"refusing untrusted ancestor directory '{path_label}' ({reason}); "
            "choose a trusted non-shared path",
        )
    if is_writable:
        if not (allow_sticky_writable and bool(st.st_mode & stat.S_ISVTX)):
            raise EvidenceDirUnsafeError(
                errno.EACCES,
                f"refusing shared writable ancestor directory '{path_label}' ({reason}); "
                "choose a trusted non-shared path",
            )
    if check_traversal and not can_traverse_fd(dfd, st, qemu_uid, qemu_groups):
        raise EvidenceDirUnsafeError(
            errno.EACCES,
            f"QEMU uid {qemu_uid} cannot traverse existing ancestor directory '{path_label}'; "
            "adjust its permissions or ACLs or choose a traversable QEMINGA_E2E_IMAGES path",
        )
    return st, is_writable, reason


def _strip_root_prefix(abs_path, norm_root):
    if norm_root == "/":
        return [p for p in abs_path.split("/") if p]
    if abs_path == norm_root:
        return []
    prefix = norm_root + "/"
    if not abs_path.startswith(prefix):
        raise EvidenceDirUnsafeError(
            errno.EACCES,
            f"path '{abs_path}' is outside verified root '{norm_root}'",
        )
    return [p for p in abs_path[len(prefix) :].split("/") if p]


def _reject_dot_segments(raw_path, label="path"):
    if not raw_path:
        raise EvidenceDirUnsafeError(errno.EINVAL, f"{label} must not be empty")
    parts = raw_path.split("/")
    if "." in parts or ".." in parts:
        raise EvidenceDirUnsafeError(
            errno.EINVAL,
            f"{label} must not contain '.' or '..' segments: '{raw_path}'",
        )


def walk_existing_prefix(
    target,
    qemu_uid,
    qemu_groups,
    trusted_uids,
    *,
    check_traversal=True,
    root_fd=None,
    root_path="/",
):
    """Walk ``target`` component-by-component, validating every ancestor and symlink hop.

    When ``root_fd`` is ``None`` (production default), the walk starts at real
    host ``/``. Unprivileged tests may pass a fixture-owned ``root_fd`` and its
    lexical ``root_path`` to remain independent of host ``/`` UID mappings.
    """
    _reject_dot_segments(target, "target path")
    if not target.startswith("/"):
        raise EvidenceDirUnsafeError(errno.EINVAL, f"path must be absolute: '{target}'")
    norm = os.path.normpath(target)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    if root_fd is None:
        norm_root = "/"
        parts = [p for p in norm.split("/") if p]
        cur_fd = os.open("/", READ_DIR_FLAGS)
    else:
        norm_root = os.path.normpath(root_path)
        if not norm_root.startswith("/"):
            raise EvidenceDirUnsafeError(
                errno.EINVAL, f"root_path must be absolute: '{root_path}'"
            )
        parts = _strip_root_prefix(norm, norm_root)
        cur_fd = os.dup(root_fd)

    pending = deque(
        (part, os.path.join(norm_root, *parts[: idx + 1]), False)
        for idx, part in enumerate(parts)
    )
    try:
        cur_path = norm_root
        cur_st, cur_writable, cur_reason = verify_dir_fd(
            cur_fd,
            cur_path,
            qemu_uid,
            qemu_groups,
            trusted_uids,
            allow_sticky_writable=True,
            check_traversal=check_traversal,
        )
        deepest_lexical = norm_root
        remaining = []
        symlinks = 0
        while pending:
            comp, orig_prefix, from_symlink = pending.popleft()
            if comp == ".":
                if orig_prefix is not None:
                    deepest_lexical = orig_prefix
                continue
            if comp == "..":
                if root_fd is not None and cur_path == norm_root:
                    raise EvidenceDirUnsafeError(
                        errno.EACCES,
                        f"path '{target}' attempts to escape verified root '{norm_root}'",
                    )
                next_fd = os.open("..", READ_DIR_FLAGS, dir_fd=cur_fd)
                next_path = os.path.dirname(cur_path) or "/"
                try:
                    nst, nwritable, nreason = verify_dir_fd(
                        next_fd,
                        next_path,
                        qemu_uid,
                        qemu_groups,
                        trusted_uids,
                        allow_sticky_writable=True,
                        check_traversal=check_traversal,
                    )
                except Exception:
                    os.close(next_fd)
                    raise
                os.close(cur_fd)
                cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                    next_fd,
                    next_path,
                    nst,
                    nwritable,
                    nreason,
                )
                if orig_prefix is not None:
                    deepest_lexical = orig_prefix
                continue
            try:
                lst = os.lstat(comp, dir_fd=cur_fd)
            except FileNotFoundError:
                if from_symlink:
                    raise EvidenceDirUnsafeError(
                        errno.ENOENT,
                        f"dangling symlink encountered while resolving '{target}' at "
                        f"'{os.path.join(cur_path, comp)}'",
                    )
                remaining = [comp] + [p[0] for p in pending]
                break
            if stat.S_ISLNK(lst.st_mode):
                symlinks += 1
                if symlinks > SYMLOOP_MAX:
                    raise EvidenceDirUnsafeError(
                        errno.ELOOP, f"too many symbolic links resolving '{target}'"
                    )
                if lst.st_uid not in trusted_uids:
                    raise EvidenceDirUnsafeError(
                        errno.EACCES,
                        f"refusing untrusted symlink '{os.path.join(cur_path, comp)}' "
                        f"owned by uid {lst.st_uid}",
                    )
                link_target = os.readlink(comp, dir_fd=cur_fd)
                if not link_target:
                    raise EvidenceDirUnsafeError(
                        errno.ENOENT,
                        f"empty symlink at '{os.path.join(cur_path, comp)}'",
                    )
                if link_target.startswith("/"):
                    if root_fd is None:
                        link_parts = [p for p in link_target.split("/") if p]
                        anchor_fd = os.open("/", READ_DIR_FLAGS)
                    else:
                        prefix = norm_root.rstrip("/") + "/"
                        if link_target == norm_root:
                            link_parts = []
                        elif link_target.startswith(prefix):
                            link_parts = [
                                p for p in link_target[len(prefix) :].split("/") if p
                            ]
                        else:
                            raise EvidenceDirUnsafeError(
                                errno.EACCES,
                                f"symlink '{os.path.join(cur_path, comp)}' target "
                                f"'{link_target}' escapes verified root '{norm_root}'",
                            )
                        anchor_fd = os.dup(root_fd)
                    try:
                        rst, rwritable, rreason = verify_dir_fd(
                            anchor_fd,
                            norm_root,
                            qemu_uid,
                            qemu_groups,
                            trusted_uids,
                            allow_sticky_writable=True,
                            check_traversal=check_traversal,
                        )
                    except Exception:
                        os.close(anchor_fd)
                        raise
                    os.close(cur_fd)
                    cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                        anchor_fd,
                        norm_root,
                        rst,
                        rwritable,
                        rreason,
                    )
                else:
                    link_parts = [p for p in link_target.split("/") if p]
                if not link_parts:
                    if orig_prefix is not None:
                        deepest_lexical = orig_prefix
                    continue
                for idx in range(len(link_parts) - 1, -1, -1):
                    attach = orig_prefix if idx == len(link_parts) - 1 else None
                    pending.appendleft((link_parts[idx], attach, True))
                continue
            next_path = os.path.join(cur_path, comp)
            if not stat.S_ISDIR(lst.st_mode):
                raise EvidenceDirUnsafeError(
                    errno.ENOTDIR,
                    f"path component '{next_path}' is not a directory",
                )
            next_fd = os.open(comp, READ_DIR_FLAGS, dir_fd=cur_fd)
            try:
                nst = os.fstat(next_fd)
                if nst.st_dev != lst.st_dev or nst.st_ino != lst.st_ino:
                    raise EvidenceDirUnsafeError(
                        errno.EXDEV,
                        f"directory '{next_path}' changed during verification",
                    )
                nst, nwritable, nreason = verify_dir_fd(
                    next_fd,
                    next_path,
                    qemu_uid,
                    qemu_groups,
                    trusted_uids,
                    allow_sticky_writable=True,
                    check_traversal=check_traversal,
                )
            except Exception:
                os.close(next_fd)
                raise
            os.close(cur_fd)
            cur_fd, cur_path, cur_st, cur_writable, cur_reason = (
                next_fd,
                next_path,
                nst,
                nwritable,
                nreason,
            )
            if orig_prefix is not None:
                deepest_lexical = orig_prefix

        # The deepest existing directory will host newly created components,
        # run files, or evidence files, so it MUST NOT be writable by other
        # accounts even when the sticky bit is set.
        if cur_writable:
            raise EvidenceDirUnsafeError(
                errno.EACCES,
                f"refusing shared writable directory '{cur_path}' ({cur_reason}); "
                "choose a trusted non-shared path",
            )
        return cur_fd, cur_path, deepest_lexical, remaining
    except Exception:
        os.close(cur_fd)
        raise


def provision_private_dir_fd(tfd, qemu_uid, qemu_gid, qemu_groups):
    if os.geteuid() == 0:
        os.fchown(tfd, 0, 0)
    os.fchmod(tfd, 0o700)
    # Always strip any inherited default ACL BEFORE creating children or
    # adjusting access permissions so unrelated accounts never inherit access.
    remove_xattr_if_present(tfd, b"system.posix_acl_default")
    if qemu_uid == 0:
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        os.fchmod(tfd, 0o700)
        return

    disable_acl = os.environ.get("QEMINGA_TEST_DISABLE_ACL") == "1"
    acl_applied = False
    if not disable_acl:
        acl_bytes = encode_acl(
            [
                (0x01, 0o7, 0xFFFFFFFF),
                (0x02, 0o1, qemu_uid),
                (0x04, 0o0, 0xFFFFFFFF),
                (0x10, 0o1, 0xFFFFFFFF),
                (0x20, 0o0, 0xFFFFFFFF),
            ]
        )
        try:
            os.setxattr(tfd, b"system.posix_acl_access", acl_bytes)
            acl_applied = True
        except OSError as exc:
            if exc.errno not in (errno.EOPNOTSUPP, errno.ENOSYS):
                raise

    if acl_applied:
        if decode_acl_fd(tfd, b"system.posix_acl_default") is not None:
            raise OSError(errno.EIO, "inherited default ACL remained after removal")
        entries = decode_acl_fd(tfd, b"system.posix_acl_access") or []
        expected = {
            (0x01, 0o7, 0xFFFFFFFF),
            (0x02, 0o1, qemu_uid),
            (0x04, 0o0, 0xFFFFFFFF),
            (0x10, 0o1, 0xFFFFFFFF),
            (0x20, 0o0, 0xFFFFFFFF),
        }
        if set(entries) != expected:
            raise OSError(
                errno.EIO, f"unexpected POSIX access ACL after replacement: {entries}"
            )
    else:
        # No-ACL fallback: ALWAYS group-only search (`0710`, owning group
        # `qemu_gid` even when `qemu_gid == 0`), NEVER world-searchable `0711`.
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        owner_uid = 0 if os.geteuid() == 0 else -1
        os.fchown(tfd, owner_uid, qemu_gid)
        os.fchmod(tfd, 0o710)
        st = os.fstat(tfd)
        if st.st_gid != qemu_gid or (st.st_mode & 0o7777) != 0o710:
            raise OSError(errno.EIO, f"failed to apply 0710 group {qemu_gid} fallback")

    st = os.fstat(tfd)
    if not can_traverse_fd(tfd, st, qemu_uid, qemu_groups):
        raise OSError(
            errno.EACCES,
            f"QEMU uid {qemu_uid} still cannot traverse newly provisioned directory",
        )


def _reclaim_empty_published_dir(parent_fd, comp, expected_id):
    """Remove ``comp`` under ``parent_fd`` only if still empty and matching ``expected_id``."""
    try:
        cur_lst = os.lstat(comp, dir_fd=parent_fd)
        if (cur_lst.st_dev, cur_lst.st_ino) == expected_id:
            os.rmdir(comp, dir_fd=parent_fd)
    except OSError:
        pass


def create_component_in_fd(
    parent_fd,
    parent_path,
    comp,
    qemu_uid,
    qemu_gid,
    qemu_groups,
    fail_if_exists=False,
):
    tmp_name = f".qeminga-e2e-init.{os.urandom(8).hex()}"
    os.mkdir(tmp_name, 0o700, dir_fd=parent_fd)
    published = False
    synced = False
    tfd = None
    tfd_id = None
    try:
        tfd = os.open(tmp_name, READ_DIR_FLAGS, dir_fd=parent_fd)
        tfd_st = os.fstat(tfd)
        tfd_id = (tfd_st.st_dev, tfd_st.st_ino)
        provision_private_dir_fd(tfd, qemu_uid, qemu_gid, qemu_groups)
        os.fsync(tfd)
        try:
            renameat2_noreplace(parent_fd, tmp_name, parent_fd, comp)
        except FileExistsError:
            if fail_if_exists:
                raise OSError(
                    errno.EEXIST,
                    f"{os.path.join(parent_path, comp)} already exists; "
                    "refusing to reuse another run's files",
                )
            os.close(tfd)
            tfd = None
            os.rmdir(tmp_name, dir_fd=parent_fd)
            return None
        published = True
        os.fsync(parent_fd)
        synced = True
        ret_fd = tfd
        tfd = None
        return ret_fd
    finally:
        # If parent-directory fsync failed AFTER renameat2 published `comp`,
        # reclaim ONLY this invocation's still-empty directory while `tfd` is
        # still open (pinning its (st_dev, st_ino) against inode reuse) so an
        # ordinary retry does not stall on EEXIST.
        if published and not synced and tfd_id is not None:
            _reclaim_empty_published_dir(parent_fd, comp, tfd_id)
        if tfd is not None:
            os.close(tfd)
        if not published:
            try:
                os.rmdir(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass


def prepare_images_root(
    target, qemu_uid, qemu_gid, qemu_groups, *, root_fd=None, root_path="/"
):
    trusted_uids = trusted_owner_uids()
    cur_fd, cur_path, deepest_lexical, remaining = walk_existing_prefix(
        target,
        qemu_uid,
        qemu_groups,
        trusted_uids,
        check_traversal=True,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        kernel_verdict_traversal(deepest_lexical, qemu_uid, qemu_gid, qemu_groups)
        for comp in remaining:
            next_fd = create_component_in_fd(
                cur_fd,
                cur_path,
                comp,
                qemu_uid,
                qemu_gid,
                qemu_groups,
                fail_if_exists=False,
            )
            next_path = os.path.join(cur_path, comp)
            if next_fd is None:
                next_fd = os.open(comp, READ_DIR_FLAGS, dir_fd=cur_fd)
                try:
                    verify_dir_fd(
                        next_fd,
                        next_path,
                        qemu_uid,
                        qemu_groups,
                        trusted_uids,
                        allow_sticky_writable=False,
                        check_traversal=True,
                    )
                except Exception:
                    os.close(next_fd)
                    raise
            os.close(cur_fd)
            cur_fd, cur_path = next_fd, next_path
        kernel_verdict_traversal(
            os.path.normpath(target), qemu_uid, qemu_gid, qemu_groups
        )
    finally:
        os.close(cur_fd)


def create_run_dir(
    images_dir, run_name, qemu_uid, qemu_gid, qemu_groups, *, root_fd=None, root_path="/"
):
    if "/" in run_name or run_name in ("", ".", ".."):
        raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
    trusted_uids = trusted_owner_uids()
    img_fd, img_path, deepest_lexical, remaining = walk_existing_prefix(
        images_dir,
        qemu_uid,
        qemu_groups,
        trusted_uids,
        check_traversal=True,
        root_fd=root_fd,
        root_path=root_path,
    )
    rfd = None
    rfd_id = None
    verified = False
    try:
        if remaining:
            raise OSError(errno.ENOENT, f"images root '{images_dir}' does not exist")
        kernel_verdict_traversal(deepest_lexical, qemu_uid, qemu_gid, qemu_groups)
        rfd = create_component_in_fd(
            img_fd,
            img_path,
            run_name,
            qemu_uid,
            qemu_gid,
            qemu_groups,
            fail_if_exists=True,
        )
        rst = os.fstat(rfd)
        rfd_id = (rst.st_dev, rst.st_ino)
        # Keep `img_fd` and `rfd` open through final traversal verification so
        # any transient failure reclaims this invocation's still-empty directory
        # via the same identity-checked rollback before closing descriptors.
        kernel_verdict_traversal(
            os.path.join(os.path.normpath(images_dir), run_name),
            qemu_uid,
            qemu_gid,
            qemu_groups,
        )
        verified = True
    finally:
        if rfd is not None and not verified and rfd_id is not None:
            _reclaim_empty_published_dir(img_fd, run_name, rfd_id)
        if rfd is not None:
            os.close(rfd)
        os.close(img_fd)


def _assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, label):
    est = os.lstat(entry, dir_fd=dir_fd)
    if stat.S_ISLNK(est.st_mode):
        return est
    # On Linux overlayfs, directories report the overlay virtual st_dev while
    # regular files report their underlying upper/lower layer st_dev — yet both
    # share the exact same kernel mnt_id. Checking st_dev on directories catches
    # btrfs subvolumes too, while fd_mnt_id catches every mountpoint (including
    # cross-fs mounts, same-st_dev directory bind mounts, and single-file bind
    # mounts) on all filesystems.
    if stat.S_ISDIR(est.st_mode) and est.st_dev != root_dev:
        raise OSError(errno.EXDEV, f"'{label}' crosses filesystem boundary")
    efd = os.open(entry, PATH_NOFOLLOW_FLAGS, dir_fd=dir_fd)
    try:
        fst = os.fstat(efd)
        if (stat.S_ISDIR(fst.st_mode) and fst.st_dev != root_dev) or fd_mnt_id(
            efd
        ) != root_mnt_id:
            raise OSError(errno.EXDEV, f"'{label}' crosses mount boundary")
    finally:
        os.close(efd)
    return est


def scan_open_dir_same_mount(dir_fd, root_dev, root_mnt_id, cur_path):
    """Verify every descendant stays on the same (st_dev, mnt_id) before any deletion."""
    for entry in os.listdir(dir_fd):
        child_path = f"{cur_path}/{entry}"
        est = _assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path)
        if stat.S_ISDIR(est.st_mode):
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dir_fd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev or fd_mnt_id(cfd) != root_mnt_id:
                    raise OSError(
                        errno.EXDEV, f"'{child_path}' crosses mount boundary"
                    )
                scan_open_dir_same_mount(cfd, root_dev, root_mnt_id, child_path)
            finally:
                os.close(cfd)


def rmtree_same_mount(dir_fd, root_dev, root_mnt_id, cur_path):
    """Recursively remove contents of verified open ``dir_fd``, rechecking mount IDs."""
    for entry in os.listdir(dir_fd):
        child_path = f"{cur_path}/{entry}"
        est = _assert_entry_same_mount(dir_fd, entry, root_dev, root_mnt_id, child_path)
        if stat.S_ISDIR(est.st_mode):
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dir_fd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev or fd_mnt_id(cfd) != root_mnt_id:
                    raise OSError(
                        errno.EXDEV, f"'{child_path}' crosses mount boundary"
                    )
                rmtree_same_mount(cfd, root_dev, root_mnt_id, child_path)
            finally:
                os.close(cfd)
            os.rmdir(entry, dir_fd=dir_fd)
        else:
            os.unlink(entry, dir_fd=dir_fd)


def handoff_file(
    images_dir,
    run_name,
    filename,
    qemu_uid,
    qemu_gid,
    qemu_groups,
    do_chown,
    *,
    root_fd=None,
    root_path="/",
):
    if (
        "/" in run_name
        or "/" in filename
        or run_name in ("", ".", "..")
        or filename in ("", ".", "..")
    ):
        raise OSError(
            errno.EINVAL, f"invalid run/file name: '{run_name}' / '{filename}'"
        )
    trusted_uids = trusted_owner_uids()
    img_fd, img_path, _, remaining = walk_existing_prefix(
        images_dir,
        qemu_uid,
        qemu_groups,
        trusted_uids,
        check_traversal=True,
        root_fd=root_fd,
        root_path=root_path,
    )
    delegated = False
    try:
        if remaining:
            raise OSError(errno.ENOENT, f"images root '{images_dir}' does not exist")
        img_st = os.fstat(img_fd)
        img_mnt = fd_mnt_id(img_fd)
        rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        try:
            rst = os.fstat(rfd)
            run_mnt = fd_mnt_id(rfd)
            if rst.st_dev != img_st.st_dev or run_mnt != img_mnt:
                raise OSError(
                    errno.EXDEV,
                    f"refusing cross-mount run directory '{os.path.join(img_path, run_name)}'",
                )
            verify_dir_fd(
                rfd,
                os.path.join(img_path, run_name),
                qemu_uid,
                qemu_groups,
                trusted_uids,
                allow_sticky_writable=False,
                check_traversal=True,
            )
            ffd = os.open(
                filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rfd
            )
            try:
                fst = os.fstat(ffd)
                if fd_mnt_id(ffd) != run_mnt:
                    raise OSError(
                        errno.EXDEV,
                        f"refusing cross-mount guest file '{filename}'",
                    )
                if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                    raise OSError(
                        errno.EINVAL,
                        f"refusing unsafe guest file '{filename}' "
                        "(must be regular file with nlink == 1)",
                    )
                remove_xattr_if_present(ffd, b"system.posix_acl_access")
                os.fchmod(ffd, 0o600)
                if do_chown and qemu_uid != 0:
                    if os.geteuid() == 0:
                        os.fchown(ffd, qemu_uid, qemu_gid)
                    else:
                        delegated = True
                fst_after = os.fstat(ffd)
                if (fst_after.st_mode & 0o777) != 0o600:
                    raise OSError(
                        errno.EIO, f"guest file '{filename}' did not reach mode 0600"
                    )
            finally:
                os.close(ffd)
        finally:
            os.close(rfd)
    finally:
        os.close(img_fd)
    return delegated


def _evidence_owner_uids(session):
    if session:
        return {os.geteuid()}
    return trusted_owner_uids()


def _evidence_ancestor_uids(session):
    if session:
        return {0, os.geteuid()}
    return trusted_owner_uids()


def _create_evidence_dir_in_fd(
    parent_fd, parent_path, comp, dir_mode, owner_uids
):
    tmp_name = f".qeminga-e2e-evinit.{os.urandom(8).hex()}"
    os.mkdir(tmp_name, 0o700, dir_fd=parent_fd)
    published = False
    tfd = None
    try:
        tfd = os.open(tmp_name, READ_DIR_FLAGS, dir_fd=parent_fd)
        if os.geteuid() == 0 and dir_mode == 0o755:
            os.fchown(tfd, 0, 0)
        remove_xattr_if_present(tfd, b"system.posix_acl_default")
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        os.fchmod(tfd, dir_mode)
        os.fsync(tfd)
        try:
            renameat2_noreplace(parent_fd, tmp_name, parent_fd, comp)
        except FileExistsError:
            os.close(tfd)
            tfd = None
            os.rmdir(tmp_name, dir_fd=parent_fd)
            existing = os.open(comp, READ_DIR_FLAGS, dir_fd=parent_fd)
            try:
                verify_dir_fd(
                    existing,
                    os.path.join(parent_path, comp),
                    0,
                    {0},
                    owner_uids,
                    allow_sticky_writable=False,
                    check_traversal=False,
                )
            except Exception:
                os.close(existing)
                raise
            return existing
        published = True
        os.fsync(parent_fd)
        ret_fd = tfd
        tfd = None
        return ret_fd
    finally:
        if tfd is not None:
            os.close(tfd)
        if not published:
            try:
                os.rmdir(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass


def _open_verified_evidence_dir(
    out_dir, *, create_missing=True, session=False, root_fd=None, root_path="/"
):
    _reject_dot_segments(out_dir, "evidence directory")
    abs_out = os.path.abspath(out_dir)
    ancestor_uids = _evidence_ancestor_uids(session)
    owner_uids = _evidence_owner_uids(session)
    dir_mode = 0o700 if session else 0o755
    cur_fd, cur_path, _, remaining = walk_existing_prefix(
        abs_out,
        0,
        {0},
        ancestor_uids,
        check_traversal=False,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        if remaining and not create_missing:
            raise EvidenceMissingError(
                errno.ENOENT, f"evidence directory '{abs_out}' does not exist"
            )
        for comp in remaining:
            next_fd = _create_evidence_dir_in_fd(
                cur_fd, cur_path, comp, dir_mode, owner_uids
            )
            next_path = os.path.join(cur_path, comp)
            os.close(cur_fd)
            cur_fd, cur_path = next_fd, next_path
        verify_dir_fd(
            cur_fd,
            cur_path,
            0,
            {0},
            owner_uids,
            allow_sticky_writable=False,
            check_traversal=False,
        )
        return cur_fd, cur_path
    except Exception:
        os.close(cur_fd)
        raise


def _publish_evidence_stream(
    out_fd,
    dest_name,
    write_fn,
    mode=0o644,
    *,
    noreplace=False,
    expected_dest_id=None,
):
    if "/" in dest_name or dest_name in ("", ".", ".."):
        raise OSError(errno.EINVAL, f"invalid evidence filename '{dest_name}'")
    try:
        dst_lst = os.lstat(dest_name, dir_fd=out_fd)
        if stat.S_ISDIR(dst_lst.st_mode):
            raise OSError(errno.EISDIR, f"evidence target '{dest_name}' is a directory")
    except FileNotFoundError:
        pass
    tmp_name = f".qeminga-evidence.{os.urandom(8).hex()}"
    tfd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=out_fd,
    )
    published = False
    try:
        write_fn(tfd)
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        os.fchmod(tfd, mode)
        os.fsync(tfd)
        os.close(tfd)
        tfd = None
        if noreplace:
            renameat2_noreplace(out_fd, tmp_name, out_fd, dest_name)
        else:
            if expected_dest_id is not None:
                try:
                    cur_lst = os.lstat(dest_name, dir_fd=out_fd)
                except FileNotFoundError:
                    return False
                if stat.S_ISDIR(cur_lst.st_mode):
                    raise OSError(
                        errno.EISDIR, f"evidence target '{dest_name}' is a directory"
                    )
                if (cur_lst.st_dev, cur_lst.st_ino) != expected_dest_id:
                    return False
            # Atomic replacement unlinks any pre-existing directory entry (including
            # a symlink or hard-linked file) without opening or truncating its inode,
            # and sets permissions exclusively on the newly created file.
            os.replace(tmp_name, dest_name, src_dir_fd=out_fd, dst_dir_fd=out_fd)
        published = True
        os.fsync(out_fd)
        return True
    finally:
        if tfd is not None:
            os.close(tfd)
        if not published:
            try:
                os.unlink(tmp_name, dir_fd=out_fd)
            except OSError:
                pass


def _write_all_fd(dst_fd, data):
    view = memoryview(data)
    while view:
        written = os.write(dst_fd, view)
        view = view[written:]


def _copy_fd_to_fd(src_fd, dst_fd):
    while True:
        chunk = os.read(src_fd, 65536)
        if not chunk:
            break
        _write_all_fd(dst_fd, chunk)


def verify_evidence_dir(out_dir, *, session=False, root_fd=None, root_path="/"):
    """Verify an existing trusted/caller-controlled evidence directory without mutating it."""
    out_fd, _ = _open_verified_evidence_dir(
        out_dir,
        create_missing=False,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    os.close(out_fd)


def prepare_evidence_dir(
    out_dir, *, init_run=False, session=False, root_fd=None, root_path="/"
):
    """Validate/create a trusted evidence directory; optionally reset known run outputs."""
    owner_uids = _evidence_owner_uids(session)
    dir_mode = 0o700 if session else 0o755
    out_fd, out_path = _open_verified_evidence_dir(
        out_dir,
        create_missing=True,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        if init_run:
            out_st = os.fstat(out_fd)
            out_mnt = fd_mnt_id(out_fd)
            fcntl.flock(out_fd, fcntl.LOCK_EX)
            try:
                try:
                    rst = os.lstat("result.json", dir_fd=out_fd)
                    if not stat.S_ISDIR(rst.st_mode):
                        os.unlink("result.json", dir_fd=out_fd)
                except FileNotFoundError:
                    pass
            finally:
                try:
                    fcntl.flock(out_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            tests_fd = _create_evidence_dir_in_fd(
                out_fd, out_path, "tests", dir_mode, owner_uids
            )
            try:
                tst = os.fstat(tests_fd)
                if tst.st_dev != out_st.st_dev or fd_mnt_id(tests_fd) != out_mnt:
                    raise EvidenceDirUnsafeError(
                        errno.EXDEV,
                        f"refusing cross-mount evidence subdirectory '{os.path.join(out_path, 'tests')}'",
                    )
                for name in ALLOWED_TEST_FILES:
                    try:
                        est = os.lstat(name, dir_fd=tests_fd)
                        if not stat.S_ISDIR(est.st_mode):
                            os.unlink(name, dir_fd=tests_fd)
                    except FileNotFoundError:
                        pass
            finally:
                os.close(tests_fd)
    finally:
        os.close(out_fd)


def publish_evidence_bytes(
    out_dir,
    dest_name,
    data,
    *,
    subdir=None,
    session=False,
    root_fd=None,
    root_path="/",
):
    owner_uids = _evidence_owner_uids(session)
    dir_mode = 0o700 if session else 0o755
    file_mode = 0o600 if session else 0o644
    if subdir == "tests":
        if dest_name not in ALLOWED_TEST_FILES:
            raise OSError(errno.EINVAL, f"unexpected test result filename '{dest_name}'")
    elif subdir is None:
        if dest_name not in ALLOWED_EVIDENCE_FILES:
            raise OSError(errno.EINVAL, f"unexpected evidence filename '{dest_name}'")
    else:
        raise OSError(errno.EINVAL, f"unexpected evidence subdirectory '{subdir}'")

    out_fd, out_path = _open_verified_evidence_dir(
        out_dir,
        create_missing=True,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        if subdir is not None:
            out_st = os.fstat(out_fd)
            out_mnt = fd_mnt_id(out_fd)
            sub_fd = _create_evidence_dir_in_fd(
                out_fd, out_path, subdir, dir_mode, owner_uids
            )
            try:
                sst = os.fstat(sub_fd)
                if sst.st_dev != out_st.st_dev or fd_mnt_id(sub_fd) != out_mnt:
                    raise EvidenceDirUnsafeError(
                        errno.EXDEV,
                        f"refusing cross-mount evidence subdirectory '{os.path.join(out_path, subdir)}'",
                    )
                _publish_evidence_stream(
                    sub_fd,
                    dest_name,
                    lambda fd: _write_all_fd(fd, data),
                    mode=file_mode,
                )
            finally:
                os.close(sub_fd)
        else:
            lock_result = dest_name == "result.json"
            if lock_result:
                fcntl.flock(out_fd, fcntl.LOCK_EX)
            try:
                _publish_evidence_stream(
                    out_fd,
                    dest_name,
                    lambda fd: _write_all_fd(fd, data),
                    mode=file_mode,
                )
            finally:
                if lock_result:
                    try:
                        fcntl.flock(out_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
    finally:
        os.close(out_fd)


MAX_EVIDENCE_READ_BYTES = 1024 * 1024
MAX_TEST_MARKER_BYTES = 64
MAX_IDENTITY_RETRIES = 3


def _read_evidence_bytes_from_open_dir(
    out_fd,
    out_path,
    dest_name,
    *,
    subdir=None,
    bound=MAX_EVIDENCE_READ_BYTES,
    owner_uids,
    max_identity_retries=MAX_IDENTITY_RETRIES,
    return_identity=False,
):
    sub_fd = None
    try:
        out_mnt = fd_mnt_id(out_fd)
        if subdir is not None:
            out_st = os.fstat(out_fd)
            sub_label = os.path.join(out_path, subdir)
            for attempt in range(max_identity_retries + 1):
                try:
                    sub_lst = os.lstat(subdir, dir_fd=out_fd)
                except FileNotFoundError:
                    raise EvidenceMissingError(
                        errno.ENOENT,
                        f"evidence subdirectory '{sub_label}' does not exist",
                    )
                if stat.S_ISLNK(sub_lst.st_mode):
                    raise EvidenceUnsafeError(
                        errno.ELOOP,
                        f"refusing symlinked evidence subdirectory '{sub_label}'",
                    )
                if not stat.S_ISDIR(sub_lst.st_mode):
                    raise EvidenceUnsafeError(
                        errno.ENOTDIR,
                        f"refusing non-directory evidence subdirectory '{sub_label}'",
                    )
                try:
                    sub_fd = os.open(subdir, READ_DIR_FLAGS, dir_fd=out_fd)
                except FileNotFoundError:
                    if attempt < max_identity_retries:
                        continue
                    raise OSError(
                        errno.EAGAIN,
                        f"evidence subdirectory '{sub_label}' changed during verification",
                    )
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise EvidenceUnsafeError(
                            exc.errno,
                            f"refusing unsafe evidence subdirectory '{sub_label}'",
                        )
                    raise
                sst = os.fstat(sub_fd)
                if sst.st_dev != sub_lst.st_dev or sst.st_ino != sub_lst.st_ino:
                    os.close(sub_fd)
                    sub_fd = None
                    if attempt < max_identity_retries:
                        continue
                    raise OSError(
                        errno.EAGAIN,
                        f"evidence subdirectory '{sub_label}' changed during verification",
                    )
                sub_mnt = fd_mnt_id(sub_fd)
                if sst.st_dev != out_st.st_dev or sub_mnt != out_mnt:
                    raise EvidenceUnsafeError(
                        errno.EXDEV,
                        f"refusing cross-mount evidence subdirectory '{sub_label}'",
                    )
                sub_trusted, sub_writable, sub_reason = dir_trust_info(
                    sub_fd, sst, owner_uids
                )
                if not sub_trusted or sub_writable:
                    raise EvidenceUnsafeError(
                        errno.EACCES,
                        f"refusing untrusted or shared-writable evidence subdirectory "
                        f"'{sub_label}' ({sub_reason})",
                    )
                break
            dir_fd = sub_fd
            dir_mnt = sub_mnt
            target_label = os.path.join(sub_label, dest_name)
        else:
            dir_fd = out_fd
            dir_mnt = out_mnt
            target_label = os.path.join(out_path, dest_name)

        for attempt in range(max_identity_retries + 1):
            try:
                lst = os.lstat(dest_name, dir_fd=dir_fd)
            except FileNotFoundError:
                raise EvidenceMissingError(
                    errno.ENOENT, f"evidence file '{target_label}' does not exist"
                )
            if stat.S_ISLNK(lst.st_mode):
                raise EvidenceUnsafeError(
                    errno.ELOOP,
                    f"refusing symlinked evidence file '{target_label}'",
                )
            if not stat.S_ISREG(lst.st_mode):
                raise EvidenceUnsafeError(
                    errno.EINVAL,
                    f"refusing non-regular evidence file '{target_label}'",
                )
            if lst.st_uid not in owner_uids:
                raise EvidenceUnsafeError(
                    errno.EACCES,
                    f"refusing untrusted evidence file '{target_label}' "
                    f"(owned by untrusted uid {lst.st_uid})",
                )
            if lst.st_mode & 0o022:
                raise EvidenceUnsafeError(
                    errno.EACCES,
                    f"refusing shared-writable evidence file '{target_label}' "
                    f"(mode {oct(lst.st_mode & 0o7777)})",
                )
            try:
                ffd = os.open(
                    dest_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd
                )
            except FileNotFoundError:
                if attempt < max_identity_retries:
                    continue
                raise OSError(
                    errno.EAGAIN,
                    f"evidence file '{target_label}' changed during verification",
                )
            except OSError as exc:
                if exc.errno == errno.ELOOP:
                    raise EvidenceUnsafeError(
                        errno.ELOOP,
                        f"refusing symlinked evidence file '{target_label}'",
                    )
                raise
            try:
                fst = os.fstat(ffd)
                if fst.st_dev != lst.st_dev or fst.st_ino != lst.st_ino:
                    if attempt < max_identity_retries:
                        continue
                    raise OSError(
                        errno.EAGAIN,
                        f"evidence file '{target_label}' changed during verification",
                    )
                if fd_mnt_id(ffd) != dir_mnt:
                    raise EvidenceUnsafeError(
                        errno.EXDEV,
                        f"refusing cross-mount or bind-mounted evidence file '{target_label}'",
                    )
                if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                    raise EvidenceUnsafeError(
                        errno.EINVAL,
                        f"refusing unsafe evidence file '{target_label}' "
                        "(must be regular file with nlink == 1)",
                    )
                trusted_owner, is_writable, reason = dir_trust_info(
                    ffd, fst, owner_uids
                )
                if not trusted_owner or is_writable:
                    raise EvidenceUnsafeError(
                        errno.EACCES,
                        f"refusing untrusted or shared-writable evidence file "
                        f"'{target_label}' ({reason})",
                    )
                if fst.st_size > bound:
                    raise EvidenceUnsafeError(
                        errno.EFBIG,
                        f"evidence file '{target_label}' exceeds {bound} bytes",
                    )
                chunks = []
                total = 0
                while True:
                    chunk = os.read(ffd, 65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > bound:
                        raise EvidenceUnsafeError(
                            errno.EFBIG,
                            f"evidence file '{target_label}' exceeds {bound} bytes",
                        )
                    chunks.append(chunk)
                data = b"".join(chunks)
                if subdir == "tests" and b"\x00" in data:
                    raise EvidenceUnsafeError(
                        errno.EINVAL,
                        f"refusing NUL byte in test status marker '{target_label}'",
                    )
                if return_identity:
                    return data, (fst.st_dev, fst.st_ino)
                return data
            finally:
                os.close(ffd)
    finally:
        if sub_fd is not None:
            os.close(sub_fd)


def read_evidence_bytes(
    out_dir,
    dest_name,
    *,
    subdir=None,
    max_bytes=None,
    session=False,
    root_fd=None,
    root_path="/",
    max_identity_retries=MAX_IDENTITY_RETRIES,
):
    """Read a verified regular single-link evidence or test-marker file from a trusted directory."""
    if subdir == "tests":
        if dest_name not in ALLOWED_TEST_FILES:
            raise EvidenceUnsafeError(
                errno.EINVAL, f"unexpected test result filename '{dest_name}'"
            )
        bound = MAX_TEST_MARKER_BYTES if max_bytes is None else max_bytes
    elif subdir is None:
        if dest_name not in ALLOWED_EVIDENCE_FILES:
            raise EvidenceUnsafeError(
                errno.EINVAL, f"unexpected evidence filename '{dest_name}'"
            )
        bound = MAX_EVIDENCE_READ_BYTES if max_bytes is None else max_bytes
    else:
        raise EvidenceUnsafeError(
            errno.EINVAL, f"unexpected evidence subdirectory '{subdir}'"
        )

    owner_uids = _evidence_owner_uids(session)
    out_fd, out_path = _open_verified_evidence_dir(
        out_dir,
        create_missing=False,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        return _read_evidence_bytes_from_open_dir(
            out_fd,
            out_path,
            dest_name,
            subdir=subdir,
            bound=bound,
            owner_uids=owner_uids,
            max_identity_retries=max_identity_retries,
        )
    finally:
        os.close(out_fd)


def _reject_json_constant(token):
    raise ValueError(f"disallowed JSON constant '{token}'")


def validate_result_bytes(
    data,
    *,
    suite,
    source_repository,
    source_sha,
    arch,
    expect_sha256,
    machine,
    image,
    image_release,
    image_sha,
    mandatory_tests,
    require_pass=False,
):
    """Explicitly parse and validate bounded ``result.json`` bytes without jq version quirks."""
    try:
        text = data.decode("utf-8")
        obj = json.loads(text, parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return False
    if not isinstance(obj, dict):
        return False
    if type(obj.get("schema")) is not int or obj.get("schema") != 1:
        return False
    if obj.get("suite") != suite:
        return False
    if obj.get("source_repository") != source_repository:
        return False
    if obj.get("source_sha") != source_sha:
        return False
    if obj.get("architecture") != arch:
        return False
    digest = obj.get("candidate_binary_sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        return False
    virt = obj.get("virtualization")
    if not isinstance(virt, dict):
        return False
    if virt.get("hypervisor") != "qemu" or virt.get("machine") != machine:
        return False
    accel = virt.get("accelerator")
    if not isinstance(accel, str) or not accel:
        return False
    guest = obj.get("guest")
    if not isinstance(guest, dict):
        return False
    if (
        guest.get("image") != image
        or guest.get("image_release") != image_release
        or guest.get("image_sha256") != image_sha
    ):
        return False
    tests = obj.get("tests")
    if not isinstance(tests, dict):
        return False
    for key in mandatory_tests:
        if tests.get(key) not in ("pass", "fail", "not_run"):
            return False
    result_val = obj.get("result")
    if not require_pass and result_val == "fail":
        return True
    return (
        result_val == "pass"
        and isinstance(expect_sha256, str)
        and bool(SHA256_RE.fullmatch(expect_sha256))
        and digest == expect_sha256
        and accel == "kvm"
        and all(tests.get(key) == "pass" for key in mandatory_tests)
    )


def build_fallback_result_bytes(spec, no_digest):
    """Build the canonical all-not_run failure ``result.json`` payload."""
    doc = {
        "schema": 1,
        "suite": spec["suite"],
        "source_repository": spec["source_repository"],
        "source_sha": spec["source_sha"],
        "architecture": spec["arch"],
        "candidate_binary_sha256": no_digest,
        "virtualization": {
            "hypervisor": "qemu",
            "accelerator": "unknown",
            "machine": spec["machine"],
        },
        "guest": {
            "image": spec["image"],
            "image_release": spec["image_release"],
            "image_sha256": spec["image_sha"],
        },
        "tests": {key: "not_run" for key in spec["mandatory_tests"]},
        "result": "fail",
    }
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def verify_result_file(
    out_dir,
    spec,
    *,
    require_pass=False,
    session=False,
    root_fd=None,
    root_path="/",
):
    """Read and validate ``result.json``; raises ``EvidenceInvalidError`` if malformed/mismatched."""
    data = read_evidence_bytes(
        out_dir,
        "result.json",
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    if not validate_result_bytes(data, **spec, require_pass=require_pass):
        raise EvidenceInvalidError(
            errno.EINVAL,
            f"result.json in '{out_dir}' is malformed or does not match run binding",
        )
    return True


def ensure_result_file(
    out_dir,
    spec,
    fallback_bytes,
    *,
    session=False,
    root_fd=None,
    root_path="/",
    max_publish_retries=MAX_IDENTITY_RETRIES,
):
    """Atomically preserve a valid ``result.json`` or publish ``fallback_bytes`` under ``flock``.

    Returns ``True`` when the fallback report was published and ``False`` when an
    existing valid run-bound report was preserved untouched.
    """
    if not validate_result_bytes(fallback_bytes, **spec, require_pass=False):
        raise OSError(errno.EINVAL, "fallback result.json payload failed self-validation")
    owner_uids = _evidence_owner_uids(session)
    file_mode = 0o600 if session else 0o644
    out_fd, out_path = _open_verified_evidence_dir(
        out_dir,
        create_missing=True,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        fcntl.flock(out_fd, fcntl.LOCK_EX)
        try:
            for attempt in range(max_publish_retries + 1):
                try:
                    data, existing_id = _read_evidence_bytes_from_open_dir(
                        out_fd,
                        out_path,
                        "result.json",
                        bound=MAX_EVIDENCE_READ_BYTES,
                        owner_uids=owner_uids,
                        return_identity=True,
                    )
                except EvidenceMissingError:
                    existing_state = ("missing", None)
                except EvidenceUnsafeError:
                    try:
                        cur_lst = os.lstat("result.json", dir_fd=out_fd)
                    except FileNotFoundError:
                        existing_state = ("missing", None)
                    else:
                        if stat.S_ISDIR(cur_lst.st_mode):
                            raise OSError(
                                errno.EISDIR,
                                "evidence target 'result.json' is a directory",
                            )
                        existing_state = ("unsafe", (cur_lst.st_dev, cur_lst.st_ino))
                else:
                    if validate_result_bytes(data, **spec, require_pass=False):
                        return False
                    existing_state = ("present", existing_id)

                if existing_state[0] == "missing":
                    try:
                        _publish_evidence_stream(
                            out_fd,
                            "result.json",
                            lambda fd: _write_all_fd(fd, fallback_bytes),
                            mode=file_mode,
                            noreplace=True,
                        )
                        return True
                    except FileExistsError:
                        if attempt < max_publish_retries:
                            continue
                        raise OSError(
                            errno.EAGAIN,
                            f"evidence file '{os.path.join(out_path, 'result.json')}' "
                            "appeared concurrently during ensure-result",
                        )
                else:
                    published = _publish_evidence_stream(
                        out_fd,
                        "result.json",
                        lambda fd: _write_all_fd(fd, fallback_bytes),
                        mode=file_mode,
                        expected_dest_id=existing_state[1],
                    )
                    if published:
                        return True
                    if attempt < max_publish_retries:
                        continue
                    raise OSError(
                        errno.EAGAIN,
                        f"evidence file '{os.path.join(out_path, 'result.json')}' "
                        "changed concurrently before fallback publication",
                    )
        finally:
            try:
                fcntl.flock(out_fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(out_fd)


def _open_verified_run_dir_ro(images_dir, run_name, *, root_fd=None, root_path="/"):
    """Read-only verification of image root and run directory shared by diagnostics and cleanup.

    Returns ``(status, img_fd, rfd, rst, run_mnt, lexical_run, resolved_run)``.
    When ``status == "absent"``, ``img_fd`` and ``rfd`` are ``None`` and ``resolved_run``
    preserves every missing image-root component plus ``run_name`` so callers never
    collapse an absent image root onto an ancestor directory.
    """
    if not RUN_NAME_RE.fullmatch(run_name):
        raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
    trusted_uids = trusted_owner_uids()
    img_fd, img_path, _, remaining = walk_existing_prefix(
        images_dir,
        0,
        {0},
        trusted_uids,
        check_traversal=False,
        root_fd=root_fd,
        root_path=root_path,
    )
    lexical_run = os.path.join(os.path.normpath(images_dir), run_name)
    resolved_images = os.path.join(img_path, *remaining) if remaining else img_path
    resolved_run = os.path.join(resolved_images, run_name)
    try:
        if remaining:
            os.close(img_fd)
            return ("absent", None, None, None, None, lexical_run, resolved_run)
        img_st = os.fstat(img_fd)
        img_mnt = fd_mnt_id(img_fd)
        try:
            lst = os.lstat(run_name, dir_fd=img_fd)
        except FileNotFoundError:
            os.close(img_fd)
            return ("absent", None, None, None, None, lexical_run, resolved_run)
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
            raise OSError(
                errno.ENOTDIR,
                f"refusing non-directory run path '{resolved_run}'",
            )
        rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        try:
            rst = os.fstat(rfd)
            run_mnt = fd_mnt_id(rfd)
            if rst.st_dev != lst.st_dev or rst.st_ino != lst.st_ino:
                raise OSError(
                    errno.EXDEV,
                    f"run directory '{resolved_run}' changed during verification",
                )
            if rst.st_dev != img_st.st_dev or run_mnt != img_mnt:
                raise OSError(
                    errno.EXDEV,
                    f"refusing cross-mount run directory '{resolved_run}'",
                )
            verify_dir_fd(
                rfd,
                resolved_run,
                0,
                {0},
                trusted_uids,
                allow_sticky_writable=False,
                check_traversal=False,
            )
        except Exception:
            os.close(rfd)
            raise
        return ("present", img_fd, rfd, rst, run_mnt, lexical_run, resolved_run)
    except Exception:
        os.close(img_fd)
        raise


def collect_serial_log(
    images_dir,
    run_name,
    out_dir,
    dest_name="serial.log",
    *,
    root_fd=None,
    root_path="/",
):
    """Copy ``serial.log`` from a verified run directory into a verified evidence directory."""
    if dest_name != "serial.log":
        raise OSError(errno.EINVAL, f"unexpected serial log filename '{dest_name}'")
    status, img_fd, rfd, _, run_mnt, _, _ = _open_verified_run_dir_ro(
        images_dir, run_name, root_fd=root_fd, root_path=root_path
    )
    if status != "present":
        return False
    try:
        try:
            ffd = os.open(
                "serial.log",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=rfd,
            )
        except FileNotFoundError:
            return False
        try:
            fst = os.fstat(ffd)
            if fd_mnt_id(ffd) != run_mnt:
                raise OSError(
                    errno.EXDEV,
                    "refusing cross-mount or bind-mounted 'serial.log'",
                )
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                raise OSError(
                    errno.EINVAL,
                    "refusing unsafe diagnostic file 'serial.log' "
                    "(must be regular file with nlink == 1)",
                )
            out_fd, _ = _open_verified_evidence_dir(
                out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
            )
            try:
                _publish_evidence_stream(
                    out_fd,
                    dest_name,
                    lambda dst: _copy_fd_to_fd(ffd, dst),
                    mode=0o644,
                )
            finally:
                os.close(out_fd)
        finally:
            os.close(ffd)
        return True
    finally:
        os.close(rfd)
        os.close(img_fd)


def collect_qemu_log(
    qlog_path,
    out_dir,
    dest_name="qemu.log",
    *,
    root_fd=None,
    root_path="/",
):
    """Copy a verified regular QEMU log file into a verified evidence directory."""
    if dest_name != "qemu.log":
        raise OSError(errno.EINVAL, f"unexpected QEMU log filename '{dest_name}'")
    abs_qlog = os.path.abspath(qlog_path)
    parent = os.path.dirname(abs_qlog)
    base = os.path.basename(abs_qlog)
    if not base or base in (".", ".."):
        return False
    trusted_uids = trusted_owner_uids()
    pfd, _, _, remaining = walk_existing_prefix(
        parent,
        0,
        {0},
        trusted_uids,
        check_traversal=False,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        if remaining:
            return False
        p_mnt = fd_mnt_id(pfd)
        try:
            ffd = os.open(
                base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd
            )
        except FileNotFoundError:
            return False
        try:
            fst = os.fstat(ffd)
            if fd_mnt_id(ffd) != p_mnt:
                raise OSError(errno.EXDEV, f"refusing cross-mount QEMU log '{base}'")
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                raise OSError(
                    errno.EINVAL,
                    f"refusing unsafe QEMU log '{base}' (must be regular file with nlink == 1)",
                )
            out_fd, _ = _open_verified_evidence_dir(
                out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
            )
            try:
                _publish_evidence_stream(
                    out_fd,
                    dest_name,
                    lambda dst: _copy_fd_to_fd(ffd, dst),
                    mode=0o644,
                )
            finally:
                os.close(out_fd)
            return True
        finally:
            os.close(ffd)
    finally:
        os.close(pfd)


def collect_serial_log_session(
    images_dir,
    run_name,
    out_dir,
    dest_name="serial.log",
    *,
    root_fd=None,
    root_path="/",
):
    """Copy ``serial.log`` in unprivileged session mode via O_NOFOLLOW + private 0600 publish."""
    if not RUN_NAME_RE.fullmatch(run_name):
        raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
    if dest_name != "serial.log":
        raise OSError(errno.EINVAL, f"unexpected serial log filename '{dest_name}'")
    try:
        img_fd = os.open(images_dir, READ_DIR_FLAGS)
    except (FileNotFoundError, NotADirectoryError):
        return False
    try:
        try:
            rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        except (FileNotFoundError, NotADirectoryError):
            return False
        try:
            try:
                ffd = os.open(
                    "serial.log",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                    dir_fd=rfd,
                )
            except FileNotFoundError:
                return False
            try:
                fst = os.fstat(ffd)
                if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                    raise OSError(
                        errno.EINVAL,
                        "refusing unsafe diagnostic file 'serial.log' "
                        "(must be regular file with nlink == 1)",
                    )
                out_fd, _ = _open_verified_evidence_dir(
                    out_dir,
                    create_missing=True,
                    session=True,
                    root_fd=root_fd,
                    root_path=root_path,
                )
                try:
                    _publish_evidence_stream(
                        out_fd,
                        dest_name,
                        lambda dst: _copy_fd_to_fd(ffd, dst),
                        mode=0o600,
                    )
                finally:
                    os.close(out_fd)
            finally:
                os.close(ffd)
            return True
        finally:
            os.close(rfd)
    finally:
        os.close(img_fd)


def collect_qemu_log_session(
    qlog_path,
    out_dir,
    dest_name="qemu.log",
    *,
    root_fd=None,
    root_path="/",
):
    """Copy a session QEMU log file via O_NOFOLLOW + verified evidence dir + private 0600 publish."""
    if dest_name != "qemu.log":
        raise OSError(errno.EINVAL, f"unexpected QEMU log filename '{dest_name}'")
    abs_qlog = os.path.abspath(qlog_path)
    parent = os.path.dirname(abs_qlog)
    base = os.path.basename(abs_qlog)
    if not base or base in (".", ".."):
        return False
    try:
        pfd = os.open(parent, READ_DIR_FLAGS)
    except (FileNotFoundError, NotADirectoryError):
        return False
    try:
        try:
            ffd = os.open(
                base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd
            )
        except FileNotFoundError:
            return False
        try:
            fst = os.fstat(ffd)
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                raise OSError(
                    errno.EINVAL,
                    f"refusing unsafe QEMU log '{base}' (must be regular file with nlink == 1)",
                )
            out_fd, _ = _open_verified_evidence_dir(
                out_dir,
                create_missing=True,
                session=True,
                root_fd=root_fd,
                root_path=root_path,
            )
            try:
                _publish_evidence_stream(
                    out_fd,
                    dest_name,
                    lambda dst: _copy_fd_to_fd(ffd, dst),
                    mode=0o600,
                )
            finally:
                os.close(out_fd)
            return True
        finally:
            os.close(ffd)
    finally:
        os.close(pfd)


def verify_cleanup_target(images_dir, run_name, *, root_fd=None, root_path="/"):
    """Read-only verification of image root and run directory before destructive virsh calls."""
    status, img_fd, rfd, rst, run_mnt, lexical_run, resolved_run = (
        _open_verified_run_dir_ro(
            images_dir, run_name, root_fd=root_fd, root_path=root_path
        )
    )
    if status != "present":
        return ("absent", lexical_run, resolved_run)
    try:
        scan_open_dir_same_mount(rfd, rst.st_dev, run_mnt, resolved_run)
        return ("present", lexical_run, resolved_run)
    finally:
        os.close(rfd)
        os.close(img_fd)


def verify_domain_xml(xml_text, expected_name, lexical_run_dir, resolved_run_dir):
    """Confirm a libvirt domain's XML belongs strictly to this run directory and return its UUID."""
    if not RUN_NAME_RE.fullmatch(expected_name):
        raise OSError(errno.EINVAL, f"invalid domain name '{expected_name}'")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise OSError(errno.EINVAL, f"cannot parse domain XML for '{expected_name}': {exc}")
    name_el = root.find("name")
    dom_name = (name_el.text or "").strip() if name_el is not None else ""
    if dom_name != expected_name:
        raise OSError(
            errno.EACCES,
            f"domain XML <name> '{dom_name}' does not match expected '{expected_name}'",
        )
    uuid_el = root.find("uuid")
    dom_uuid = (uuid_el.text or "").strip().lower() if uuid_el is not None else ""
    if not UUID_RE.fullmatch(dom_uuid):
        raise OSError(
            errno.EACCES,
            f"domain '{expected_name}' XML is missing a valid <uuid>",
        )
    allowed_dirs = {
        os.path.normpath(p).rstrip("/") + "/"
        for p in (lexical_run_dir, resolved_run_dir)
        if p
    }
    if not allowed_dirs:
        raise OSError(errno.EINVAL, "missing expected run directory for domain XML check")

    def path_in_run_dir(raw_path):
        if not raw_path or not raw_path.startswith("/"):
            return False
        if ".." in raw_path.split("/"):
            return False
        norm = os.path.normpath(raw_path)
        return any(norm.startswith(prefix) for prefix in allowed_dirs)

    found_root_disk = False
    for disk in root.findall("./devices/disk"):
        disk_type = (disk.attrib.get("type") or "").strip()
        if disk_type != "file":
            raise OSError(
                errno.EACCES,
                f"domain '{expected_name}' has unexpected non-file disk type '{disk_type}'",
            )
        src = disk.find("source")
        file_path = (src.attrib.get("file") or "").strip() if src is not None else ""
        if not file_path or not path_in_run_dir(file_path):
            raise OSError(
                errno.EACCES,
                f"domain '{expected_name}' references disk '{file_path}' outside expected run directory",
            )
        if os.path.basename(os.path.normpath(file_path)) == "root.qcow2":
            found_root_disk = True

    for tag in ("./devices/serial/source", "./devices/console/source"):
        for src in root.findall(tag):
            path_val = (src.attrib.get("path") or "").strip()
            if path_val and not path_in_run_dir(path_val):
                raise OSError(
                    errno.EACCES,
                    f"domain '{expected_name}' references console path '{path_val}' outside expected run directory",
                )

    nvram = root.find("./os/nvram")
    if nvram is not None:
        nvram_paths = []
        nvram_text = (nvram.text or "").strip()
        if nvram_text:
            nvram_paths.append(nvram_text)
        nvram_src = nvram.find("source")
        if nvram_src is not None:
            nvram_file = (nvram_src.attrib.get("file") or "").strip()
            if nvram_file:
                nvram_paths.append(nvram_file)
        for nvram_path in nvram_paths:
            if not path_in_run_dir(nvram_path):
                raise OSError(
                    errno.EACCES,
                    f"domain '{expected_name}' references nvram '{nvram_path}' outside expected run directory",
                )

    if not found_root_disk:
        raise OSError(
            errno.EACCES,
            f"domain '{expected_name}' XML does not reference expected run root.qcow2; refusing destructive cleanup",
        )
    return dom_uuid


def cleanup_run_dir(images_dir, run_name, *, root_fd=None, root_path="/"):
    """Verify ancestor trust, run-dir identity, and same-mount tree before removing."""
    status, img_fd, rfd, rst, run_mnt, _, resolved_run = _open_verified_run_dir_ro(
        images_dir, run_name, root_fd=root_fd, root_path=root_path
    )
    if status != "present":
        return "absent"
    try:
        # Pass 1: verify EVERY entry stays on (rst.st_dev, run_mnt) BEFORE the first unlink.
        scan_open_dir_same_mount(rfd, rst.st_dev, run_mnt, resolved_run)
        # Pass 2: remove entries while rechecking every opened descriptor's mount ID.
        rmtree_same_mount(rfd, rst.st_dev, run_mnt, resolved_run)
        # Re-verify identity while `rfd` is still open before unlinking the directory.
        cur_lst = os.lstat(run_name, dir_fd=img_fd)
        if cur_lst.st_dev != rst.st_dev or cur_lst.st_ino != rst.st_ino:
            raise OSError(
                errno.EXDEV,
                f"run directory '{resolved_run}' changed before removal",
            )
        os.rmdir(run_name, dir_fd=img_fd)
        return "removed"
    finally:
        os.close(rfd)
        os.close(img_fd)


def strip_session_dir_acl(target):
    dfd = os.open(target, READ_DIR_FLAGS)
    try:
        remove_xattr_if_present(dfd, b"system.posix_acl_default")
        remove_xattr_if_present(dfd, b"system.posix_acl_access")
        os.fchmod(dfd, 0o700)
    finally:
        os.close(dfd)


def resolve_cli_root():
    """Return ``(root_fd, root_path)`` for CLI invocations.

    Real root (``euid == 0``) ALWAYS walks from host ``/`` and refuses
    ``QEMINGA_TEST_SYSFS_ROOT``. Unprivileged simulated tests may point
    ``QEMINGA_TEST_SYSFS_ROOT`` at a caller-owned fixture root so tests stay
    independent of host ``/`` UID mappings inside user namespaces.
    """
    test_root = os.environ.get("QEMINGA_TEST_SYSFS_ROOT", "")
    if not test_root:
        return None, "/"
    if os.geteuid() == 0:
        raise OSError(
            errno.EPERM,
            "QEMINGA_TEST_SYSFS_ROOT is forbidden when running as root",
        )
    if not os.path.isabs(test_root):
        raise OSError(
            errno.EINVAL, f"QEMINGA_TEST_SYSFS_ROOT must be absolute: '{test_root}'"
        )
    norm_root = os.path.normpath(test_root)
    rfd = os.open(norm_root, READ_DIR_FLAGS)
    try:
        st = os.fstat(rfd)
        if st.st_uid != os.geteuid():
            raise OSError(
                errno.EACCES,
                f"QEMINGA_TEST_SYSFS_ROOT '{norm_root}' is not owned by caller",
            )
    except Exception:
        os.close(rfd)
        raise
    return rfd, norm_root


def _result_spec_from_argv(args):
    return {
        "suite": args[0],
        "source_repository": args[1],
        "source_sha": args[2],
        "arch": args[3],
        "expect_sha256": args[4],
        "machine": args[5],
        "image": args[6],
        "image_release": args[7],
        "image_sha": args[8],
        "mandatory_tests": tuple(t for t in args[9].split() if t),
    }


def main(argv):
    if not argv:
        sys.stderr.write("libvirt-kvm-smoke: missing sys_fs_ops subcommand\n")
        return 1
    op = argv[0]
    quiet_missing = False
    root_fd = None
    try:
        if op == "strip-session-dir-acl":
            strip_session_dir_acl(argv[1])
            return 0
        if op == "verify-domain-xml":
            xml_text = sys.stdin.read()
            dom_uuid = verify_domain_xml(xml_text, argv[1], argv[2], argv[3])
            print(dom_uuid)
            return 0

        root_fd, root_path = resolve_cli_root()
        if op == "prepare-images-root":
            prepare_images_root(
                argv[1],
                int(argv[2]),
                int(argv[3]),
                {int(x) for x in argv[4].split(",") if x},
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "create-run-dir":
            create_run_dir(
                argv[1],
                argv[2],
                int(argv[3]),
                int(argv[4]),
                {int(x) for x in argv[5].split(",") if x},
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "handoff-file":
            delegated = handoff_file(
                argv[1],
                argv[2],
                argv[3],
                int(argv[4]),
                int(argv[5]),
                {int(x) for x in argv[6].split(",") if x},
                argv[7] == "1",
                root_fd=root_fd,
                root_path=root_path,
            )
            if delegated:
                print("DELEGATE_CHOWN")
        elif op in ("prepare-evidence-dir", "prepare-session-evidence-dir"):
            is_session = op == "prepare-session-evidence-dir"
            init_run = len(argv) > 2 and argv[2] == "init-run"
            prepare_evidence_dir(
                argv[1],
                init_run=init_run,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op in ("verify-evidence-dir", "verify-session-evidence-dir"):
            is_session = op == "verify-session-evidence-dir"
            verify_evidence_dir(
                argv[1],
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op in ("publish-evidence-stdin", "publish-session-evidence-stdin"):
            is_session = op == "publish-session-evidence-stdin"
            subdir = argv[3] if len(argv) > 3 and argv[3] else None
            data = sys.stdin.buffer.read()
            publish_evidence_bytes(
                argv[1],
                argv[2],
                data,
                subdir=subdir,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op in ("read-evidence-stdout", "read-session-evidence-stdout"):
            is_session = op == "read-session-evidence-stdout"
            args = argv[1:]
            if args and args[0] == "--quiet-missing":
                quiet_missing = True
                args = args[1:]
            subdir = args[2] if len(args) > 2 and args[2] else None
            data = read_evidence_bytes(
                args[0],
                args[1],
                subdir=subdir,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
            try:
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            except BrokenPipeError:
                # Downstream validator already exited (e.g., on early syntax
                # error); the file read itself succeeded, so let the pipe
                # consumer's exit status decide the outcome.
                return 0
        elif op in ("verify-result", "verify-session-result"):
            is_session = op == "verify-session-result"
            spec = _result_spec_from_argv(argv[2:12])
            require_pass = argv[12] == "1"
            if not require_pass:
                quiet_missing = True
            verify_result_file(
                argv[1],
                spec,
                require_pass=require_pass,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op in ("ensure-result", "ensure-session-result"):
            is_session = op == "ensure-session-result"
            spec = _result_spec_from_argv(argv[2:12])
            fallback_bytes = build_fallback_result_bytes(spec, argv[12])
            published = ensure_result_file(
                argv[1],
                spec,
                fallback_bytes,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
            if published:
                sys.stdout.buffer.write(fallback_bytes)
                sys.stdout.buffer.flush()
        elif op == "collect-serial-log":
            collect_serial_log(
                argv[1],
                argv[2],
                argv[3],
                argv[4] if len(argv) > 4 else "serial.log",
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-serial-log-session":
            collect_serial_log_session(
                argv[1],
                argv[2],
                argv[3],
                argv[4] if len(argv) > 4 else "serial.log",
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-qemu-log":
            collect_qemu_log(
                argv[1],
                argv[2],
                argv[3] if len(argv) > 3 else "qemu.log",
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-qemu-log-session":
            collect_qemu_log_session(
                argv[1],
                argv[2],
                argv[3] if len(argv) > 3 else "qemu.log",
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "verify-cleanup-target":
            status, lexical_run, resolved_run = verify_cleanup_target(
                argv[1], argv[2], root_fd=root_fd, root_path=root_path
            )
            print(f"{status}\t{lexical_run}\t{resolved_run}")
        elif op == "cleanup-run-dir":
            status = cleanup_run_dir(
                argv[1],
                argv[2],
                root_fd=root_fd,
                root_path=root_path,
            )
            print(status)
        else:
            raise OSError(errno.EINVAL, f"unknown sys_fs_ops op '{op}'")
        return 0
    except EvidenceMissingError as exc:
        if not quiet_missing:
            msg = exc.strerror if exc.strerror else str(exc)
            sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return EXIT_EVIDENCE_MISSING
    except EvidenceDirUnsafeError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return EXIT_EVIDENCE_DIR_UNSAFE
    except EvidenceUnsafeError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return EXIT_EVIDENCE_FILE_UNSAFE
    except EvidenceInvalidError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return EXIT_EVIDENCE_INVALID
    except OSError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return 1
    finally:
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
