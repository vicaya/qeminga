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
QEMU_LOG_LAUNCH_HEADER_RE = re.compile(
    rb"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\.\d+(?:[+-]\d{4}|Z):\s+starting up\b"
)
QEMU_LOG_UUID_RE = re.compile(
    rb"(?:^|[\s,'\"=])(?:-uuid(?:=|\s+)|uuid=)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=$|[\s,'\"\\])",
    re.IGNORECASE,
)
ALLOWED_EVIDENCE_FILES = frozenset(
    {
        "domain.xml",
        "qemu.log",
        "serial.log",
        "result.json",
        "versions.txt",
        "e2e-libvirt.log",
        "e2e-libvirt.fallback.log",
        "cleanup.txt",
    }
)
PRIVATE_EVIDENCE_FILES = frozenset({"e2e-libvirt.fallback.log"})
ALLOWED_TEST_FILES = frozenset(
    {
        "production_install",
        "accelerator_kvm",
        "libvirt_interop",
        "agent_shutdown",
    }
)
RUN_TOKEN_NAME = ".run-token"
RUN_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_RUN_TOKEN_BYTES = 256

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

    def __init__(self, err, msg, *, observed_id=None, is_dir=False):
        super().__init__(err, msg)
        self.observed_id = observed_id
        self.is_dir = is_dir


class EvidenceInvalidError(OSError):
    """Evidence file was read cleanly, but its contents failed JSON/schema validation."""


def _parse_dir_id(expected_dir_id):
    if expected_dir_id is None:
        return None
    parts = expected_dir_id.split(":")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise OSError(
            errno.EINVAL, f"invalid expected run directory identity '{expected_dir_id}'"
        )
    return (int(parts[0]), int(parts[1]), int(parts[2]))

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


def _file_is_private_fd(fd, st):
    """Return ``(is_private, reason)`` confirming no group, other, or ACL access is granted."""
    entries = decode_acl_fd(fd, b"system.posix_acl_access")
    if entries:
        mask = 7
        for tag, perm, _ in entries:
            if tag == 0x10:
                mask = perm
        for tag, perm, eid in entries:
            if tag == 0x20 and perm != 0:
                return False, "other access granted via POSIX ACL"
            if tag == 0x02 and eid != st.st_uid and (perm & mask) != 0:
                return False, f"named uid {eid} access granted via POSIX ACL"
            if tag == 0x04 and (perm & mask) != 0:
                return False, f"group (gid {st.st_gid}) access granted via POSIX ACL"
            if tag == 0x08 and (perm & mask) != 0:
                return False, f"named gid {eid} access granted via POSIX ACL"
        return True, ""
    if st.st_mode & 0o077:
        return False, f"mode {oct(st.st_mode & 0o7777)}"
    return True, ""


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
        dir_id = f"{rst.st_dev}:{rst.st_ino}:{fd_mnt_id(rfd)}"
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
        return dir_id
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


def _read_run_token_record(out_fd, out_path, owner_uids):
    """Read and parse ``.run-token`` returning ``(token, owner_or_None)``."""
    raw = _read_evidence_bytes_from_open_dir(
        out_fd,
        out_path,
        RUN_TOKEN_NAME,
        bound=MAX_RUN_TOKEN_BYTES,
        owner_uids=owner_uids,
    )
    lines = [
        line.strip()
        for line in raw.decode("ascii", errors="replace").splitlines()
        if line.strip()
    ]
    if not lines or len(lines) > 2:
        raise EvidenceUnsafeError(
            errno.EINVAL,
            f"evidence directory '{out_path}' has malformed run token record",
        )
    actual_token = lines[0]
    if not RUN_TOKEN_RE.fullmatch(actual_token):
        raise EvidenceUnsafeError(
            errno.EINVAL,
            f"evidence directory '{out_path}' has invalid run token value",
        )
    actual_owner = None
    if len(lines) == 2:
        if not RUN_NAME_RE.fullmatch(lines[1]):
            raise EvidenceUnsafeError(
                errno.EINVAL,
                f"evidence directory '{out_path}' has invalid run owner value",
            )
        actual_owner = lines[1]
    return actual_token, actual_owner


def _verify_expected_run_token(
    out_fd,
    out_path,
    run_token,
    owner_uids,
    *,
    run_owner=None,
    reject_unfenced_if_initialized=False,
):
    """Verify per-attempt ``.run-token`` (and optional owner) inside an already-locked ``out_fd``.

    - When ``run_token`` is supplied, ``.run-token`` must exist as a verified
      regular single-link file matching ``run_token`` (and matching ``run_owner``
      if both are present), else raises ``ESTALE``.
    - Else when ``run_owner`` is supplied (standalone ``cleanup --out``), if
      ``.run-token`` exists it must be valid and record the exact matching
      ``run_owner`` (else raises ``ESTALE``); directories without ``.run-token``
      keep standalone pre-token behavior.
    - Else when ``reject_unfenced_if_initialized`` is ``True``, any existing
      ``.run-token`` refuses the unfenced write with ``ESTALE`` so a delayed or
      unfenced writer cannot publish against a live fenced run attempt.
    """
    if run_owner is not None:
        if not isinstance(run_owner, str) or not RUN_NAME_RE.fullmatch(run_owner):
            raise OSError(errno.EINVAL, f"invalid run attempt owner '{run_owner}'")
    if run_token is not None:
        if not isinstance(run_token, str) or not RUN_TOKEN_RE.fullmatch(run_token):
            raise OSError(errno.EINVAL, f"invalid run attempt token '{run_token}'")
        try:
            actual_token, actual_owner = _read_run_token_record(
                out_fd, out_path, owner_uids
            )
        except (EvidenceMissingError, EvidenceUnsafeError):
            raise OSError(
                errno.ESTALE,
                f"evidence directory '{out_path}' run token is missing or invalid; "
                "refusing stale attempt write",
            )
        if actual_token != run_token or (
            run_owner is not None
            and actual_owner is not None
            and actual_owner != run_owner
        ):
            raise OSError(
                errno.ESTALE,
                f"evidence directory '{out_path}' was reset by another run attempt; "
                "refusing stale write",
            )
        return
    if run_owner is not None:
        try:
            _, actual_owner = _read_run_token_record(out_fd, out_path, owner_uids)
        except EvidenceMissingError:
            return
        except EvidenceUnsafeError:
            raise OSError(
                errno.ESTALE,
                f"evidence directory '{out_path}' run token is invalid; "
                "refusing unverified cleanup diagnostic write",
            )
        if actual_owner != run_owner:
            raise OSError(
                errno.ESTALE,
                f"evidence directory '{out_path}' belongs to run attempt "
                f"'{actual_owner or 'unknown'}', not '{run_owner}'; refusing stale write",
            )
        return
    if reject_unfenced_if_initialized:
        try:
            os.lstat(RUN_TOKEN_NAME, dir_fd=out_fd)
        except FileNotFoundError:
            return
        raise OSError(
            errno.ESTALE,
            f"evidence directory '{out_path}' is bound to an active run attempt; "
            "refusing unfenced write",
        )


def prepare_evidence_dir(
    out_dir,
    *,
    init_run=False,
    run_owner=None,
    session=False,
    root_fd=None,
    root_path="/",
):
    """Validate/create a trusted evidence directory; optionally reset outputs and rotate ``.run-token``."""
    if run_owner is not None and (
        not isinstance(run_owner, str) or not RUN_NAME_RE.fullmatch(run_owner)
    ):
        raise OSError(errno.EINVAL, f"invalid run attempt owner '{run_owner}'")
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
                for name in ALLOWED_EVIDENCE_FILES:
                    try:
                        rst = os.lstat(name, dir_fd=out_fd)
                        if not stat.S_ISDIR(rst.st_mode):
                            os.unlink(name, dir_fd=out_fd)
                    except FileNotFoundError:
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
                run_token = os.urandom(16).hex()
                token_body = (
                    f"{run_token}\n{run_owner}\n"
                    if run_owner is not None
                    else f"{run_token}\n"
                ).encode("ascii")
                _publish_evidence_stream(
                    out_fd,
                    RUN_TOKEN_NAME,
                    lambda fd: _write_all_fd(fd, token_body),
                    mode=0o600,
                )
                return run_token
            finally:
                try:
                    fcntl.flock(out_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
        return None
    finally:
        os.close(out_fd)


def publish_evidence_bytes(
    out_dir,
    dest_name,
    data,
    *,
    subdir=None,
    session=False,
    run_token=None,
    run_owner=None,
    root_fd=None,
    root_path="/",
):
    owner_uids = _evidence_owner_uids(session)
    dir_mode = 0o700 if session else 0o755
    file_mode = (
        0o600
        if (session or (subdir is None and dest_name in PRIVATE_EVIDENCE_FILES))
        else 0o644
    )
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
        fcntl.flock(out_fd, fcntl.LOCK_EX)
        try:
            _verify_expected_run_token(
                out_fd,
                out_path,
                run_token,
                owner_uids,
                run_owner=run_owner,
                reject_unfenced_if_initialized=True,
            )
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
                _publish_evidence_stream(
                    out_fd,
                    dest_name,
                    lambda fd: _write_all_fd(fd, data),
                    mode=file_mode,
                )
        finally:
            try:
                fcntl.flock(out_fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(out_fd)


MAX_EVIDENCE_READ_BYTES = 1024 * 1024
MAX_EVIDENCE_STAGE_BYTES = 16 * 1024 * 1024
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
    require_private=False,
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
            lst_id = (lst.st_dev, lst.st_ino)
            if stat.S_ISLNK(lst.st_mode):
                raise EvidenceUnsafeError(
                    errno.ELOOP,
                    f"refusing symlinked evidence file '{target_label}'",
                    observed_id=lst_id,
                )
            if not stat.S_ISREG(lst.st_mode):
                raise EvidenceUnsafeError(
                    errno.EINVAL,
                    f"refusing non-regular evidence file '{target_label}'",
                    observed_id=lst_id,
                    is_dir=stat.S_ISDIR(lst.st_mode),
                )
            if lst.st_uid not in owner_uids:
                raise EvidenceUnsafeError(
                    errno.EACCES,
                    f"refusing untrusted evidence file '{target_label}' "
                    f"(owned by untrusted uid {lst.st_uid})",
                    observed_id=lst_id,
                )
            if lst.st_mode & 0o022:
                raise EvidenceUnsafeError(
                    errno.EACCES,
                    f"refusing shared-writable evidence file '{target_label}' "
                    f"(mode {oct(lst.st_mode & 0o7777)})",
                    observed_id=lst_id,
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
                    # `lstat` just observed a regular file, so `ELOOP` means the
                    # entry changed between `lstat` and `open`; retry so the next
                    # `lstat` captures the replacement entry's actual inode.
                    if attempt < max_identity_retries:
                        continue
                    raise OSError(
                        errno.EAGAIN,
                        f"evidence file '{target_label}' changed during verification",
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
                fst_id = (fst.st_dev, fst.st_ino)
                if fd_mnt_id(ffd) != dir_mnt:
                    raise EvidenceUnsafeError(
                        errno.EXDEV,
                        f"refusing cross-mount or bind-mounted evidence file '{target_label}'",
                        observed_id=fst_id,
                    )
                if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                    raise EvidenceUnsafeError(
                        errno.EINVAL,
                        f"refusing unsafe evidence file '{target_label}' "
                        "(must be regular file with nlink == 1)",
                        observed_id=fst_id,
                        is_dir=stat.S_ISDIR(fst.st_mode),
                    )
                trusted_owner, is_writable, reason = dir_trust_info(
                    ffd, fst, owner_uids
                )
                if not trusted_owner or is_writable:
                    raise EvidenceUnsafeError(
                        errno.EACCES,
                        f"refusing untrusted or shared-writable evidence file "
                        f"'{target_label}' ({reason})",
                        observed_id=fst_id,
                    )
                if require_private:
                    is_priv, priv_reason = _file_is_private_fd(ffd, fst)
                    if not is_priv:
                        raise EvidenceUnsafeError(
                            errno.EACCES,
                            f"refusing non-private evidence file '{target_label}' ({priv_reason})",
                            observed_id=fst_id,
                        )
                if fst.st_size > bound:
                    raise EvidenceUnsafeError(
                        errno.EFBIG,
                        f"evidence file '{target_label}' exceeds {bound} bytes",
                        observed_id=fst_id,
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
                            observed_id=fst_id,
                        )
                    chunks.append(chunk)
                data = b"".join(chunks)
                if subdir == "tests" and b"\x00" in data:
                    raise EvidenceUnsafeError(
                        errno.EINVAL,
                        f"refusing NUL byte in test status marker '{target_label}'",
                        observed_id=fst_id,
                    )
                if return_identity:
                    return data, fst_id
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
            require_private=(subdir is None and dest_name in PRIVATE_EVIDENCE_FILES),
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


def _build_result_bytes(spec, *, digest, accel, tests, result):
    """Build a canonical ``libvirt-kvm-smoke-v1`` ``result.json`` payload."""
    doc = {
        "schema": 1,
        "suite": spec["suite"],
        "source_repository": spec["source_repository"],
        "source_sha": spec["source_sha"],
        "architecture": spec["arch"],
        "candidate_binary_sha256": digest,
        "virtualization": {
            "hypervisor": "qemu",
            "accelerator": accel,
            "machine": spec["machine"],
        },
        "guest": {
            "image": spec["image"],
            "image_release": spec["image_release"],
            "image_sha256": spec["image_sha"],
        },
        "tests": tests,
        "result": result,
    }
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def build_fallback_result_bytes(spec, no_digest):
    """Build the canonical all-not_run failure ``result.json`` payload."""
    return _build_result_bytes(
        spec,
        digest=no_digest,
        accel="unknown",
        tests={key: "not_run" for key in spec["mandatory_tests"]},
        result="fail",
    )


def _raise_result_invalid_error(data, spec, out_dir):
    expect = spec.get("expect_sha256")
    has_valid_expect = isinstance(expect, str) and bool(SHA256_RE.fullmatch(expect))
    if not has_valid_expect:
        try:
            obj = json.loads(
                data.decode("utf-8"), parse_constant=_reject_json_constant
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
            obj = None
        if isinstance(obj, dict) and obj.get("result") == "pass":
            raise EvidenceInvalidError(
                errno.EINVAL,
                f"passing result.json in '{out_dir}' requires --expect-sha256 "
                "(omission supports failure reports only)",
            )
    raise EvidenceInvalidError(
        errno.EINVAL,
        f"result.json in '{out_dir}' is malformed or does not match run binding",
    )


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
        _raise_result_invalid_error(data, spec, out_dir)
    return True


def ensure_result_file(
    out_dir,
    spec,
    fallback_bytes,
    *,
    session=False,
    run_token=None,
    run_owner=None,
    root_fd=None,
    root_path="/",
    max_publish_retries=MAX_IDENTITY_RETRIES,
):
    """Preserve a valid ``result.json`` or publish ``fallback_bytes`` under ``flock(out_fd, LOCK_EX)``.

    Coordinated suite operations (``prepare_evidence_dir(..., init_run=True)``,
    ``publish_evidence_bytes`` for ``result.json`` and ``tests/*``,
    ``write_result_file``, ``ensure_result_file``, and ``stage_evidence_dir``)
    serialize on ``flock(out_fd)``. When ``out_dir`` has been initialized by a
    run attempt (``.run-token`` exists), verifies ``run_token`` or ``run_owner``
    under ``LOCK_EX`` before reading or replacing ``result.json`` (failing with
    ``ESTALE`` on mismatch or unfenced call so a delayed ``ensure-result``
    cannot replace a newer attempt's report); directories where ``run`` never
    initialized an attempt keep early-failure fallback behavior. When
    ``result.json`` is absent, publication uses kernel-atomic
    ``renameat2(RENAME_NOREPLACE)`` so a newly created report is never clobbered
    even by an uncoordinated writer. When an existing destination is invalid or
    unsafe, the rejected inode identity observed during validation
    (``EvidenceUnsafeError.observed_id`` or ``existing_id``) is carried directly
    into the pre-replace identity recheck and retried on change (without a
    second ``lstat`` after rejection); because POSIX/Linux has no single atomic
    inode-compare-and-replace syscall, the final ``lstat`` and ``os.replace``
    remain distinct operations with respect to writers outside the ``flock``
    protocol.

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
            _verify_expected_run_token(
                out_fd,
                out_path,
                run_token,
                owner_uids,
                run_owner=run_owner,
                reject_unfenced_if_initialized=True,
            )
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
                except EvidenceUnsafeError as exc:
                    if exc.is_dir:
                        raise OSError(
                            errno.EISDIR,
                            "evidence target 'result.json' is a directory",
                        )
                    if exc.observed_id is None:
                        if attempt < max_publish_retries:
                            continue
                        raise OSError(
                            errno.EAGAIN,
                            f"evidence file '{os.path.join(out_path, 'result.json')}' "
                            "failed verification without stable identity",
                        )
                    existing_state = ("unsafe", exc.observed_id)
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


def write_result_file(
    out_dir,
    spec,
    digest,
    accel,
    *,
    all_not_run=False,
    session=False,
    run_token=None,
    root_fd=None,
    root_path="/",
):
    """Atomically read test markers and publish ``result.json`` under ``flock(out_fd, LOCK_EX)``.

    Holding ``LOCK_EX`` on ``out_fd`` across both marker reads and report
    publication serializes ``write-result`` against ``prepare_evidence_dir(...,
    init_run=True)``, ``mark`` (``publish_evidence_bytes(..., subdir="tests")``),
    ``ensure_result_file``, and ``stage_evidence_dir`` so an overlapping reset
    can never leave a passing report synthesized from previous markers. When
    ``run_token`` is supplied, ``.run-token`` must still match it (else
    ``ESTALE``) so a delayed run attempt cannot publish after a reset.

    Returns ``(payload_bytes, overall_passed)``.
    """
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise OSError(errno.EINVAL, f"bad candidate binary digest '{digest}'")
    if not isinstance(accel, str) or not accel:
        raise OSError(errno.EINVAL, "accelerator must be a non-empty string")
    mandatory_tests = spec["mandatory_tests"]
    for name in mandatory_tests:
        if name not in ALLOWED_TEST_FILES:
            raise OSError(errno.EINVAL, f"unexpected test result filename '{name}'")

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
            _verify_expected_run_token(
                out_fd,
                out_path,
                run_token,
                owner_uids,
                reject_unfenced_if_initialized=True,
            )
            tests = {}
            overall = "pass"
            for name in mandatory_tests:
                if all_not_run:
                    status = "not_run"
                else:
                    try:
                        marker_raw = _read_evidence_bytes_from_open_dir(
                            out_fd,
                            out_path,
                            name,
                            subdir="tests",
                            bound=MAX_TEST_MARKER_BYTES,
                            owner_uids=owner_uids,
                        )
                    except EvidenceMissingError:
                        status = "not_run"
                    except EvidenceUnsafeError:
                        status = "fail"
                    else:
                        if re.sub(rb"[ \t\r\n\v\f]+", b"", marker_raw) == b"pass":
                            status = "pass"
                        else:
                            status = "fail"
                if status != "pass":
                    overall = "fail"
                tests[name] = status
            if accel != "kvm":
                overall = "fail"
            payload = _build_result_bytes(
                spec,
                digest=digest,
                accel=accel,
                tests=tests,
                result=overall,
            )
            _publish_evidence_stream(
                out_fd,
                "result.json",
                lambda fd: _write_all_fd(fd, payload),
                mode=file_mode,
            )
            return payload, overall == "pass"
        finally:
            try:
                fcntl.flock(out_fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(out_fd)


def _write_stage_file(dir_fd, name, data, created_log, mode=0o600):
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=dir_fd,
    )
    try:
        fst = os.fstat(fd)
        created_id = (fst.st_dev, fst.st_ino)
        created_log.append((name, created_id))
        _write_all_fd(fd, data)
        remove_xattr_if_present(fd, b"system.posix_acl_access")
        os.fchmod(fd, mode)
        os.fsync(fd)
        return created_id
    finally:
        os.close(fd)


def _open_verified_stage_parent(
    stage_dir, *, session=False, root_fd=None, root_path="/"
):
    _reject_dot_segments(stage_dir, "evidence staging directory")
    abs_stage = os.path.abspath(stage_dir)
    stage_base = os.path.basename(abs_stage)
    stage_parent = os.path.dirname(abs_stage)
    if not stage_base or stage_base in (".", ".."):
        raise EvidenceDirUnsafeError(
            errno.EINVAL, f"invalid evidence staging directory '{stage_dir}'"
        )
    ancestor_uids = _evidence_ancestor_uids(session)
    owner_uids = _evidence_owner_uids(session)
    dir_mode = 0o700 if session else 0o755
    cur_fd, cur_path, _, remaining = walk_existing_prefix(
        stage_parent,
        0,
        {0},
        ancestor_uids,
        check_traversal=False,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
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
            ancestor_uids,
            allow_sticky_writable=False,
            check_traversal=False,
        )
        return cur_fd, cur_path, stage_base
    except Exception:
        os.close(cur_fd)
        raise


def stage_evidence_dir(
    out_dir,
    stage_dir,
    spec,
    *,
    session=False,
    run_token=None,
    run_owner=None,
    root_fd=None,
    root_path="/",
):
    """Copy ONLY verified allowlisted regular files from ``out_dir`` into a fresh ``0700`` ``stage_dir``.

    Requires ``out_dir`` to be verified, checks attempt ownership/token under
    ``LOCK_SH`` whenever ``out_dir`` was initialized by ``run`` (``.run-token``
    present, failing ``ESTALE`` on mismatch or unfenced call so a delayed
    caller cannot stage a newer retry's diagnostics), and requires
    ``result.json`` to exist, pass regular single-link verification, and match
    ``spec`` (passing reports additionally require ``--expect-sha256`` and a
    verified non-empty ``e2e-libvirt.log`` AC16 transcript). Optional
    allowlisted diagnostics and ``tests/*`` markers that are unsafe or
    unreadable (e.g. symlinked, oversized, or write-only ``0200``) are skipped
    with a stderr warning so a valid structured failure report can still be
    published; any non-allowlisted files, symlinks, or subdirectories under
    ``out_dir`` are ignored completely. Keeps the original staging directory
    descriptor and identity through both atomic ``renameat2_noreplace``
    publication and error cleanup (removing only entries created by this
    invocation and stopping on any name, inode, or mount mismatch).
    """
    _reject_dot_segments(out_dir, "evidence directory")
    _reject_dot_segments(stage_dir, "evidence staging directory")
    abs_stage = os.path.abspath(stage_dir)
    owner_uids = _evidence_owner_uids(session)
    out_fd, out_path = _open_verified_evidence_dir(
        out_dir,
        create_missing=False,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        out_prefix = out_path.rstrip("/") + "/"
        if abs_stage == out_path or abs_stage.startswith(out_prefix):
            raise EvidenceDirUnsafeError(
                errno.EINVAL,
                f"evidence staging directory '{stage_dir}' must not be inside '{out_path}'",
            )
        fcntl.flock(out_fd, fcntl.LOCK_SH)
        try:
            _verify_expected_run_token(
                out_fd,
                out_path,
                run_token,
                owner_uids,
                run_owner=run_owner,
                reject_unfenced_if_initialized=True,
            )
            result_data = _read_evidence_bytes_from_open_dir(
                out_fd,
                out_path,
                "result.json",
                bound=MAX_EVIDENCE_READ_BYTES,
                owner_uids=owner_uids,
            )
            if not validate_result_bytes(result_data, **spec, require_pass=False):
                _raise_result_invalid_error(result_data, spec, out_dir)
            result_doc = json.loads(
                result_data.decode("utf-8"), parse_constant=_reject_json_constant
            )
            is_pass = result_doc.get("result") == "pass"

            # Passing verdicts certify AC16 interop and therefore REQUIRE a
            # verified non-empty `e2e-libvirt.log` transcript before staging.
            required_ac16 = None
            if is_pass:
                required_ac16 = _read_evidence_bytes_from_open_dir(
                    out_fd,
                    out_path,
                    "e2e-libvirt.log",
                    bound=MAX_EVIDENCE_STAGE_BYTES,
                    owner_uids=owner_uids,
                )
                if not required_ac16.strip():
                    raise EvidenceInvalidError(
                        errno.EINVAL,
                        f"passing result.json in '{out_dir}' requires non-empty verified 'e2e-libvirt.log'",
                    )

            parent_fd, parent_path, stage_base = _open_verified_stage_parent(
                stage_dir,
                session=session,
                root_fd=root_fd,
                root_path=root_path,
            )
            try:
                parent_st = os.fstat(parent_fd)
                parent_mnt = fd_mnt_id(parent_fd)
                resolved_stage = os.path.join(parent_path, stage_base)
                if resolved_stage == out_path or resolved_stage.startswith(out_prefix):
                    raise EvidenceDirUnsafeError(
                        errno.EINVAL,
                        f"evidence staging directory '{resolved_stage}' must not be inside '{out_path}'",
                    )
                try:
                    os.lstat(stage_base, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
                else:
                    raise FileExistsError(
                        errno.EEXIST,
                        f"evidence staging directory '{resolved_stage}' already exists",
                    )

                tmp_stage = f".qeminga-stage.{os.urandom(8).hex()}"
                os.mkdir(tmp_stage, 0o700, dir_fd=parent_fd)
                published = False
                tmp_verified = False
                tmp_fd = None
                tmp_st = None
                tmp_mnt = None
                st_tests_fd = None
                st_tests_st = None
                created_files = []
                created_tests_files = []
                try:
                    tmp_fd = os.open(tmp_stage, READ_DIR_FLAGS, dir_fd=parent_fd)
                    tmp_st = os.fstat(tmp_fd)
                    tmp_mnt = fd_mnt_id(tmp_fd)
                    if tmp_st.st_dev != parent_st.st_dev or tmp_mnt != parent_mnt:
                        raise OSError(
                            errno.EXDEV,
                            f"staging directory '{os.path.join(parent_path, tmp_stage)}' "
                            "crossed mount boundary",
                        )
                    init_lst = os.lstat(tmp_stage, dir_fd=parent_fd)
                    if (init_lst.st_dev, init_lst.st_ino) != (
                        tmp_st.st_dev,
                        tmp_st.st_ino,
                    ):
                        raise OSError(
                            errno.EXDEV,
                            f"staging directory '{os.path.join(parent_path, tmp_stage)}' "
                            "changed during creation",
                        )
                    tmp_verified = True
                    remove_xattr_if_present(tmp_fd, b"system.posix_acl_default")
                    remove_xattr_if_present(tmp_fd, b"system.posix_acl_access")
                    os.fchmod(tmp_fd, 0o700)

                    _write_stage_file(
                        tmp_fd, "result.json", result_data, created_files, mode=0o600
                    )
                    if required_ac16 is not None:
                        _write_stage_file(
                            tmp_fd,
                            "e2e-libvirt.log",
                            required_ac16,
                            created_files,
                            mode=0o600,
                        )

                    skip_names = (
                        {"result.json", "e2e-libvirt.log"}
                        if required_ac16 is not None
                        else {"result.json"}
                    )
                    for name in sorted(ALLOWED_EVIDENCE_FILES - skip_names):
                        try:
                            data = _read_evidence_bytes_from_open_dir(
                                out_fd,
                                out_path,
                                name,
                                bound=MAX_EVIDENCE_STAGE_BYTES,
                                owner_uids=owner_uids,
                                require_private=(name in PRIVATE_EVIDENCE_FILES),
                            )
                        except EvidenceMissingError:
                            continue
                        except (EvidenceUnsafeError, PermissionError) as exc:
                            msg = exc.strerror if exc.strerror else str(exc)
                            sys.stderr.write(
                                f"libvirt-kvm-smoke: skipping unreadable or unsafe optional evidence file '{name}': {msg}\n"
                            )
                            continue
                        _write_stage_file(
                            tmp_fd, name, data, created_files, mode=0o600
                        )

                    staged_markers = []
                    for tname in sorted(ALLOWED_TEST_FILES):
                        try:
                            mdata = _read_evidence_bytes_from_open_dir(
                                out_fd,
                                out_path,
                                tname,
                                subdir="tests",
                                bound=MAX_TEST_MARKER_BYTES,
                                owner_uids=owner_uids,
                            )
                        except EvidenceMissingError:
                            continue
                        except (EvidenceUnsafeError, PermissionError) as exc:
                            msg = exc.strerror if exc.strerror else str(exc)
                            sys.stderr.write(
                                f"libvirt-kvm-smoke: skipping unreadable or unsafe optional test marker 'tests/{tname}': {msg}\n"
                            )
                            continue
                        staged_markers.append((tname, mdata))

                    if staged_markers:
                        os.mkdir("tests", 0o700, dir_fd=tmp_fd)
                        st_tests_fd = os.open("tests", READ_DIR_FLAGS, dir_fd=tmp_fd)
                        st_tests_st = os.fstat(st_tests_fd)
                        if (
                            st_tests_st.st_dev != tmp_st.st_dev
                            or fd_mnt_id(st_tests_fd) != tmp_mnt
                        ):
                            raise OSError(
                                errno.EXDEV,
                                f"staging tests subdirectory '{os.path.join(parent_path, tmp_stage, 'tests')}' "
                                "crossed mount boundary",
                            )
                        remove_xattr_if_present(
                            st_tests_fd, b"system.posix_acl_default"
                        )
                        remove_xattr_if_present(
                            st_tests_fd, b"system.posix_acl_access"
                        )
                        os.fchmod(st_tests_fd, 0o700)
                        for tname, mdata in staged_markers:
                            _write_stage_file(
                                st_tests_fd,
                                tname,
                                mdata,
                                created_tests_files,
                                mode=0o600,
                            )
                        os.fsync(st_tests_fd)

                    os.fsync(tmp_fd)

                    # Keep original `tmp_fd` (and `st_tests_fd`) open through
                    # publication and verify name, inode, and mount identity
                    # before calling `renameat2_noreplace`.
                    cur_parent_st = os.fstat(parent_fd)
                    if (
                        cur_parent_st.st_dev != parent_st.st_dev
                        or fd_mnt_id(parent_fd) != parent_mnt
                    ):
                        raise OSError(
                            errno.EXDEV,
                            f"staging parent directory '{parent_path}' mount changed before publication",
                        )
                    cur_tmp_st = os.fstat(tmp_fd)
                    if (
                        (cur_tmp_st.st_dev, cur_tmp_st.st_ino)
                        != (tmp_st.st_dev, tmp_st.st_ino)
                        or fd_mnt_id(tmp_fd) != tmp_mnt
                    ):
                        raise OSError(
                            errno.EXDEV,
                            f"staging directory '{os.path.join(parent_path, tmp_stage)}' "
                            "identity changed before publication",
                        )
                    cur_lst = os.lstat(tmp_stage, dir_fd=parent_fd)
                    if (cur_lst.st_dev, cur_lst.st_ino) != (
                        tmp_st.st_dev,
                        tmp_st.st_ino,
                    ):
                        raise OSError(
                            errno.EXDEV,
                            f"staging directory '{os.path.join(parent_path, tmp_stage)}' "
                            "was replaced before publication",
                        )
                    if st_tests_fd is not None and st_tests_st is not None:
                        cur_t_lst = os.lstat("tests", dir_fd=tmp_fd)
                        if (
                            (cur_t_lst.st_dev, cur_t_lst.st_ino)
                            != (st_tests_st.st_dev, st_tests_st.st_ino)
                            or fd_mnt_id(st_tests_fd) != tmp_mnt
                        ):
                            raise OSError(
                                errno.EXDEV,
                                "staging tests subdirectory identity changed before publication",
                            )

                    renameat2_noreplace(parent_fd, tmp_stage, parent_fd, stage_base)
                    published = True
                    os.fsync(parent_fd)
                finally:
                    try:
                        if (
                            not published
                            and tmp_verified
                            and tmp_fd is not None
                            and tmp_st is not None
                        ):
                            try:
                                # Clean ONLY entries created by this invocation through
                                # the original descriptors; stop on any inode or mount mismatch.
                                cur_tmp_st = os.fstat(tmp_fd)
                                if (
                                    (cur_tmp_st.st_dev, cur_tmp_st.st_ino)
                                    == (tmp_st.st_dev, tmp_st.st_ino)
                                    and fd_mnt_id(tmp_fd) == tmp_mnt
                                ):
                                    if st_tests_fd is not None and st_tests_st is not None:
                                        cur_ts = os.fstat(st_tests_fd)
                                        cur_tlst = os.lstat("tests", dir_fd=tmp_fd)
                                        if (
                                            (cur_ts.st_dev, cur_ts.st_ino)
                                            == (st_tests_st.st_dev, st_tests_st.st_ino)
                                            and (cur_tlst.st_dev, cur_tlst.st_ino)
                                            == (st_tests_st.st_dev, st_tests_st.st_ino)
                                            and fd_mnt_id(st_tests_fd) == tmp_mnt
                                        ):
                                            for tname, exp_id in created_tests_files:
                                                try:
                                                    elst = os.lstat(tname, dir_fd=st_tests_fd)
                                                    if (elst.st_dev, elst.st_ino) == exp_id:
                                                        os.unlink(tname, dir_fd=st_tests_fd)
                                                except FileNotFoundError:
                                                    pass
                                            recheck_tlst = os.lstat("tests", dir_fd=tmp_fd)
                                            if (
                                                recheck_tlst.st_dev,
                                                recheck_tlst.st_ino,
                                            ) == (st_tests_st.st_dev, st_tests_st.st_ino):
                                                os.rmdir("tests", dir_fd=tmp_fd)
                                    for fname, exp_id in created_files:
                                        try:
                                            elst = os.lstat(fname, dir_fd=tmp_fd)
                                            if (elst.st_dev, elst.st_ino) == exp_id:
                                                os.unlink(fname, dir_fd=tmp_fd)
                                        except FileNotFoundError:
                                            pass
                                    cur_plst = os.lstat(tmp_stage, dir_fd=parent_fd)
                                    if (
                                        (cur_plst.st_dev, cur_plst.st_ino)
                                        == (tmp_st.st_dev, tmp_st.st_ino)
                                        and fd_mnt_id(parent_fd) == parent_mnt
                                        and fd_mnt_id(tmp_fd) == tmp_mnt
                                    ):
                                        os.rmdir(tmp_stage, dir_fd=parent_fd)
                            except OSError:
                                pass
                    finally:
                        if st_tests_fd is not None:
                            os.close(st_tests_fd)
                        if tmp_fd is not None:
                            os.close(tmp_fd)
            finally:
                os.close(parent_fd)
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
    expected_dir_id=None,
    run_token=None,
    run_owner=None,
    root_fd=None,
    root_path="/",
):
    """Copy ``serial.log`` from a verified run directory into a verified evidence directory."""
    if dest_name != "serial.log":
        raise OSError(errno.EINVAL, f"unexpected serial log filename '{dest_name}'")
    exp_triple = _parse_dir_id(expected_dir_id)
    status, img_fd, rfd, rst, run_mnt, _, resolved_run = _open_verified_run_dir_ro(
        images_dir, run_name, root_fd=root_fd, root_path=root_path
    )
    if status != "present":
        return False
    try:
        if exp_triple is not None and (rst.st_dev, rst.st_ino, run_mnt) != exp_triple:
            raise OSError(
                errno.EXDEV,
                f"run directory '{resolved_run}' identity changed since verification; refusing serial.log collection",
            )
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
            out_fd, out_path = _open_verified_evidence_dir(
                out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
            )
            try:
                fcntl.flock(out_fd, fcntl.LOCK_EX)
                try:
                    _verify_expected_run_token(
                        out_fd,
                        out_path,
                        run_token,
                        _evidence_owner_uids(False),
                        run_owner=run_owner,
                        reject_unfenced_if_initialized=True,
                    )
                    _publish_evidence_stream(
                        out_fd,
                        dest_name,
                        lambda dst: _copy_fd_to_fd(ffd, dst),
                        mode=0o644,
                    )
                finally:
                    try:
                        fcntl.flock(out_fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
            finally:
                os.close(out_fd)
        finally:
            os.close(ffd)
        return True
    finally:
        os.close(rfd)
        os.close(img_fd)


def _open_verified_qemu_log_ro(qlog_path, *, session=False, root_fd=None, root_path="/"):
    """Open a regular nlink==1 QEMU log read-only without following symlinks."""
    abs_qlog = os.path.abspath(qlog_path)
    parent = os.path.dirname(abs_qlog)
    base = os.path.basename(abs_qlog)
    if not base or base in (".", ".."):
        return (None, None, None)
    if session:
        try:
            pfd = os.open(parent, READ_DIR_FLAGS)
        except FileNotFoundError:
            return (None, None, None)
        p_mnt = fd_mnt_id(pfd)
    else:
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
        if remaining:
            os.close(pfd)
            return (None, None, None)
        p_mnt = fd_mnt_id(pfd)
    try:
        try:
            ffd = os.open(
                base, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=pfd
            )
        except FileNotFoundError:
            os.close(pfd)
            return (None, None, None)
        try:
            fst = os.fstat(ffd)
            if not session and fd_mnt_id(ffd) != p_mnt:
                raise OSError(errno.EXDEV, f"refusing cross-mount QEMU log '{base}'")
            if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
                raise OSError(
                    errno.EINVAL,
                    f"refusing unsafe QEMU log '{base}' (must be regular file with nlink == 1)",
                )
        except Exception:
            os.close(ffd)
            raise
        return (pfd, ffd, fst)
    except Exception:
        os.close(pfd)
        raise


def snapshot_qemu_log_cursor(qlog_path, *, session=False, root_fd=None, root_path="/"):
    """Record the current QEMU log inode identity and byte offset before starting a guest."""
    pfd, ffd, fst = _open_verified_qemu_log_ro(
        qlog_path, session=session, root_fd=root_fd, root_path=root_path
    )
    if ffd is None:
        return ("absent", 0, 0, 0)
    try:
        return ("present", fst.st_dev, fst.st_ino, fst.st_size)
    finally:
        os.close(ffd)
        os.close(pfd)


def _read_all_fd(ffd):
    chunks = []
    while True:
        chunk = os.read(ffd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _extract_uuid_launch_blocks(data, expected_uuid, *, require_uuid):
    """Filter QEMU log bytes to launch blocks consistent with ``expected_uuid``.

    Returns ``(out_bytes, first_match_offset, matched_uuid)`` or ``(None, 0, False)``.
    When ``require_uuid`` is True (rotated inode or pinned verified cursor), ONLY
    blocks beginning at a recognized ``starting up`` launch header that explicitly
    declare ``expected_uuid`` (and no conflicting domain UUID) are accepted;
    headerless continuations, unverified, or foreign logs return ``(None, 0, False)``.
    """
    if not data:
        return (None, 0, False)
    exp_bytes = None
    if expected_uuid:
        norm_uuid = expected_uuid.strip().lower()
        if UUID_RE.fullmatch(norm_uuid):
            exp_bytes = norm_uuid.encode("ascii")
    if require_uuid and exp_bytes is None:
        return (None, 0, False)

    blocks = []
    current = []
    cur_start = 0
    cur_has_header = False
    pos = 0
    for line in data.splitlines(keepends=True):
        is_header = bool(QEMU_LOG_LAUNCH_HEADER_RE.match(line))
        if is_header and current:
            blocks.append((cur_start, cur_has_header, b"".join(current)))
            current = [line]
            cur_start = pos
            cur_has_header = True
        else:
            if not current:
                cur_start = pos
                cur_has_header = is_header
            current.append(line)
        pos += len(line)
    if current:
        blocks.append((cur_start, cur_has_header, b"".join(current)))

    verified = []
    unverified = []
    for blk_off, has_header, block in blocks:
        uuids = {m.group(1).lower() for m in QEMU_LOG_UUID_RE.finditer(block)}
        if has_header and exp_bytes is not None and uuids == {exp_bytes}:
            verified.append((blk_off, block))
        elif not require_uuid:
            if exp_bytes is not None and uuids and uuids != {exp_bytes}:
                continue
            unverified.append((blk_off, block))
    if verified:
        return (b"".join(block for _, block in verified), verified[0][0], True)
    if not require_uuid and unverified:
        return (b"".join(block for _, block in unverified), unverified[0][0], False)
    return (None, 0, False)


def _read_verified_qemu_log_segment(
    qlog_path,
    cursor,
    *,
    expected_uuid=None,
    session=False,
    root_fd=None,
    root_path="/",
):
    """Read ONLY bytes belonging to this run's verified launch.

    Returns ``(data, (status, st_dev, st_ino, start_offset))`` or ``(None, None)``.
    If ``cursor`` was ``present`` and the filename rotated to a different inode,
    accepts the replacement ONLY if it carries a verified launch block for
    ``expected_uuid`` and returns a ``verified`` cursor positioned at that
    launch block's exact byte offset so later reads preserve both the byte range
    and strict UUID filtering.
    """
    if cursor is None:
        return (None, None)
    c_status, c_dev, c_ino, c_offset = cursor
    if c_status not in ("absent", "present", "verified"):
        raise OSError(errno.EINVAL, f"invalid QEMU log cursor status '{c_status}'")
    pfd, ffd, fst = _open_verified_qemu_log_ro(
        qlog_path, session=session, root_fd=root_fd, root_path=root_path
    )
    if ffd is None:
        return (None, None)
    try:
        if c_status == "verified":
            if (fst.st_dev, fst.st_ino) == (c_dev, c_ino):
                if fst.st_size <= c_offset:
                    return (None, None)
                os.lseek(ffd, c_offset, os.SEEK_SET)
                base_off = c_offset
            else:
                if fst.st_size == 0:
                    return (None, None)
                base_off = 0
            raw = _read_all_fd(ffd)
            data, first_off, _ = _extract_uuid_launch_blocks(
                raw, expected_uuid, require_uuid=True
            )
            if not data:
                return (None, None)
            return (data, ("verified", fst.st_dev, fst.st_ino, base_off + first_off))
        if c_status == "present" and (fst.st_dev, fst.st_ino) == (c_dev, c_ino):
            if fst.st_size <= c_offset:
                return (None, None)
            os.lseek(ffd, c_offset, os.SEEK_SET)
            raw = _read_all_fd(ffd)
            data, first_off, matched_uuid = _extract_uuid_launch_blocks(
                raw, expected_uuid, require_uuid=False
            )
            if not data:
                return (None, None)
            pin_status = "verified" if matched_uuid else "present"
            return (data, (pin_status, fst.st_dev, fst.st_ino, c_offset + first_off))
        if c_status == "present":
            # Rotated to a new inode: NEVER blindly accept from byte 0; require
            # an explicit launch boundary bound to expected_uuid and preserve
            # both the verified launch offset and strict UUID filtering.
            if fst.st_size == 0:
                return (None, None)
            raw = _read_all_fd(ffd)
            data, first_off, _ = _extract_uuid_launch_blocks(
                raw, expected_uuid, require_uuid=True
            )
            if not data:
                return (None, None)
            return (data, ("verified", fst.st_dev, fst.st_ino, first_off))
        # c_status == "absent": file created after pre-start snapshot.
        if fst.st_size == 0:
            return (None, None)
        raw = _read_all_fd(ffd)
        data, first_off, matched_uuid = _extract_uuid_launch_blocks(
            raw, expected_uuid, require_uuid=False
        )
        if not data:
            return (None, None)
        pin_status = "verified" if matched_uuid else "present"
        return (data, (pin_status, fst.st_dev, fst.st_ino, first_off))
    finally:
        os.close(ffd)
        os.close(pfd)


def pin_qemu_log_cursor(
    qlog_path,
    cursor,
    *,
    expected_uuid=None,
    session=False,
    root_fd=None,
    root_path="/",
):
    """Pin an initially-absent or rotated cursor to the verified launch inode."""
    _, pinned = _read_verified_qemu_log_segment(
        qlog_path,
        cursor,
        expected_uuid=expected_uuid,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    return pinned


def read_qemu_log_segment(
    qlog_path,
    cursor,
    *,
    expected_uuid=None,
    session=False,
    root_fd=None,
    root_path="/",
):
    """Return only the current run's verified QEMU log bytes, or None if unavailable."""
    data, _ = _read_verified_qemu_log_segment(
        qlog_path,
        cursor,
        expected_uuid=expected_uuid,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    return data


def collect_qemu_log(
    qlog_path,
    out_dir,
    dest_name="qemu.log",
    *,
    cursor=None,
    expected_uuid=None,
    session=False,
    run_token=None,
    run_owner=None,
    root_fd=None,
    root_path="/",
):
    """Copy ONLY the current run's verified QEMU log segment into an evidence directory."""
    if dest_name != "qemu.log":
        raise OSError(errno.EINVAL, f"unexpected QEMU log filename '{dest_name}'")
    data, _ = _read_verified_qemu_log_segment(
        qlog_path,
        cursor,
        expected_uuid=expected_uuid,
        session=session,
        root_fd=root_fd,
        root_path=root_path,
    )
    if not data:
        return False
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
            _verify_expected_run_token(
                out_fd,
                out_path,
                run_token,
                _evidence_owner_uids(session),
                run_owner=run_owner,
                reject_unfenced_if_initialized=True,
            )
            _publish_evidence_stream(
                out_fd,
                dest_name,
                lambda dst: _write_all_fd(dst, data),
                mode=0o600 if session else 0o644,
            )
        finally:
            try:
                fcntl.flock(out_fd, fcntl.LOCK_UN)
            except OSError:
                pass
    finally:
        os.close(out_fd)
    return True


def collect_serial_log_session(
    images_dir,
    run_name,
    out_dir,
    dest_name="serial.log",
    *,
    run_token=None,
    run_owner=None,
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
                out_fd, out_path = _open_verified_evidence_dir(
                    out_dir,
                    create_missing=True,
                    session=True,
                    root_fd=root_fd,
                    root_path=root_path,
                )
                try:
                    fcntl.flock(out_fd, fcntl.LOCK_EX)
                    try:
                        _verify_expected_run_token(
                            out_fd,
                            out_path,
                            run_token,
                            _evidence_owner_uids(True),
                            run_owner=run_owner,
                            reject_unfenced_if_initialized=True,
                        )
                        _publish_evidence_stream(
                            out_fd,
                            dest_name,
                            lambda dst: _copy_fd_to_fd(ffd, dst),
                            mode=0o600,
                        )
                    finally:
                        try:
                            fcntl.flock(out_fd, fcntl.LOCK_UN)
                        except OSError:
                            pass
                finally:
                    os.close(out_fd)
            finally:
                os.close(ffd)
            return True
        finally:
            os.close(rfd)
    finally:
        os.close(img_fd)


def verify_cleanup_target(images_dir, run_name, *, root_fd=None, root_path="/"):
    """Read-only verification of image root and run directory before destructive virsh calls.

    Returns ``(status, lexical_run, resolved_run, dir_id)``, where ``dir_id`` is
    ``"<st_dev>:<st_ino>:<mnt_id>"`` when ``status == "present"`` and ``""`` when ``"absent"``.
    """
    status, img_fd, rfd, rst, run_mnt, lexical_run, resolved_run = (
        _open_verified_run_dir_ro(
            images_dir, run_name, root_fd=root_fd, root_path=root_path
        )
    )
    if status != "present":
        return ("absent", lexical_run, resolved_run, "")
    try:
        scan_open_dir_same_mount(rfd, rst.st_dev, run_mnt, resolved_run)
        dir_id = f"{rst.st_dev}:{rst.st_ino}:{run_mnt}"
        return ("present", lexical_run, resolved_run, dir_id)
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

    os_el = root.find("./os")
    nvrams = root.findall("./os/nvram")
    if len(nvrams) > 1:
        raise OSError(
            errno.EACCES,
            f"domain '{expected_name}' defines multiple <os><nvram> elements",
        )
    if os_el is not None and (os_el.attrib.get("firmware") or "").strip() and not nvrams:
        raise OSError(
            errno.EACCES,
            f"domain '{expected_name}' uses auto-selected firmware without a verifiable <nvram> file path",
        )
    if nvrams:
        nvram = nvrams[0]
        nvram_type = (nvram.attrib.get("type") or "").strip()
        if nvram_type not in ("", "file"):
            raise OSError(
                errno.EACCES,
                f"domain '{expected_name}' uses unsupported non-file NVRAM type '{nvram_type}'",
            )
        for child in list(nvram):
            if child.tag != "source":
                raise OSError(
                    errno.EACCES,
                    f"domain '{expected_name}' has unexpected <nvram> child <{child.tag}>",
                )
        nvram_paths = []
        nvram_text = (nvram.text or "").strip()
        if nvram_text:
            nvram_paths.append(nvram_text)
        nvram_sources = nvram.findall("source")
        if len(nvram_sources) > 1:
            raise OSError(
                errno.EACCES,
                f"domain '{expected_name}' has multiple <nvram><source> elements",
            )
        if nvram_sources:
            nvram_src = nvram_sources[0]
            forbidden_src_attrs = set(nvram_src.attrib) & {
                "dev",
                "pool",
                "volume",
                "protocol",
                "name",
                "dir",
                "path",
            }
            if forbidden_src_attrs:
                raise OSError(
                    errno.EACCES,
                    f"domain '{expected_name}' <nvram><source> has unsupported storage attributes {sorted(forbidden_src_attrs)}",
                )
            nvram_file = (nvram_src.attrib.get("file") or "").strip()
            if not nvram_file:
                raise OSError(
                    errno.EACCES,
                    f"domain '{expected_name}' <nvram><source> is missing a file path",
                )
            nvram_paths.append(nvram_file)
        if not nvram_paths:
            raise OSError(
                errno.EACCES,
                f"domain '{expected_name}' <nvram> does not specify a verifiable file path",
            )
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


def cleanup_run_dir(
    images_dir, run_name, *, expected_dir_id=None, root_fd=None, root_path="/"
):
    """Verify ancestor trust, run-dir identity, and same-mount tree before removing."""
    exp_triple = _parse_dir_id(expected_dir_id)
    status, img_fd, rfd, rst, run_mnt, _, resolved_run = _open_verified_run_dir_ro(
        images_dir, run_name, root_fd=root_fd, root_path=root_path
    )
    if status != "present":
        return "absent"
    try:
        if exp_triple is not None and (rst.st_dev, rst.st_ino, run_mnt) != exp_triple:
            raise OSError(
                errno.EXDEV,
                f"run directory '{resolved_run}' identity changed since verification; refusing removal",
            )
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
        if op == "snapshot-qemu-log-cursor-session":
            c_st, c_dev, c_ino, c_off = snapshot_qemu_log_cursor(argv[1], session=True)
            print(f"{c_st}\t{c_dev}\t{c_ino}\t{c_off}")
            return 0
        if op == "pin-qemu-log-cursor-session":
            cursor = (argv[2], int(argv[3]), int(argv[4]), int(argv[5]))
            expected_uuid = argv[6] if len(argv) > 6 and argv[6] else None
            pinned = pin_qemu_log_cursor(
                argv[1], cursor, expected_uuid=expected_uuid, session=True
            )
            if pinned is None:
                return 1
            print(f"{pinned[0]}\t{pinned[1]}\t{pinned[2]}\t{pinned[3]}")
            return 0
        if op == "read-qemu-log-segment-session":
            cursor = (argv[2], int(argv[3]), int(argv[4]), int(argv[5]))
            expected_uuid = argv[6] if len(argv) > 6 and argv[6] else None
            data = read_qemu_log_segment(
                argv[1], cursor, expected_uuid=expected_uuid, session=True
            )
            if data is None:
                return 1
            sys.stdout.buffer.write(data)
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
            dir_id = create_run_dir(
                argv[1],
                argv[2],
                int(argv[3]),
                int(argv[4]),
                {int(x) for x in argv[5].split(",") if x},
                root_fd=root_fd,
                root_path=root_path,
            )
            print(dir_id)
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
            run_owner = argv[3] if len(argv) > 3 and argv[3] else None
            run_token = prepare_evidence_dir(
                argv[1],
                init_run=init_run,
                run_owner=run_owner,
                session=is_session,
                root_fd=root_fd,
                root_path=root_path,
            )
            if run_token is not None:
                print(run_token)
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
            run_token = argv[4] if len(argv) > 4 and argv[4] else None
            run_owner = argv[5] if len(argv) > 5 and argv[5] else None
            data = sys.stdin.buffer.read()
            publish_evidence_bytes(
                argv[1],
                argv[2],
                data,
                subdir=subdir,
                session=is_session,
                run_token=run_token,
                run_owner=run_owner,
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
            run_token = argv[13] if len(argv) > 13 and argv[13] else None
            run_owner = argv[14] if len(argv) > 14 and argv[14] else None
            published = ensure_result_file(
                argv[1],
                spec,
                fallback_bytes,
                session=is_session,
                run_token=run_token,
                run_owner=run_owner,
                root_fd=root_fd,
                root_path=root_path,
            )
            if published:
                if sys.stdout is None:
                    raise OSError(errno.EBADF, "stdout is closed")
                sys.stdout.buffer.write(fallback_bytes)
                sys.stdout.buffer.flush()
        elif op in ("write-result", "write-session-result"):
            is_session = op == "write-session-result"
            spec = _result_spec_from_argv(argv[2:12])
            digest = argv[12]
            accel = argv[13]
            all_not_run = len(argv) > 14 and argv[14] == "1"
            run_token = argv[15] if len(argv) > 15 and argv[15] else None
            payload, passed = write_result_file(
                argv[1],
                spec,
                digest,
                accel,
                all_not_run=all_not_run,
                session=is_session,
                run_token=run_token,
                root_fd=root_fd,
                root_path=root_path,
            )
            if sys.stdout is None:
                raise OSError(errno.EBADF, "stdout is closed")
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()
            return 0 if passed else 1
        elif op in ("stage-evidence", "stage-session-evidence"):
            is_session = op == "stage-session-evidence"
            spec = _result_spec_from_argv(argv[3:13])
            run_token = argv[13] if len(argv) > 13 and argv[13] else None
            run_owner = argv[14] if len(argv) > 14 and argv[14] else None
            stage_evidence_dir(
                argv[1],
                argv[2],
                spec,
                session=is_session,
                run_token=run_token,
                run_owner=run_owner,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-serial-log":
            expected_dir_id = argv[5] if len(argv) > 5 and argv[5] else None
            run_token = argv[6] if len(argv) > 6 and argv[6] else None
            run_owner = argv[7] if len(argv) > 7 and argv[7] else None
            collect_serial_log(
                argv[1],
                argv[2],
                argv[3],
                argv[4] if len(argv) > 4 else "serial.log",
                expected_dir_id=expected_dir_id,
                run_token=run_token,
                run_owner=run_owner,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-serial-log-session":
            run_token = argv[5] if len(argv) > 5 and argv[5] else None
            run_owner = argv[6] if len(argv) > 6 and argv[6] else None
            collect_serial_log_session(
                argv[1],
                argv[2],
                argv[3],
                argv[4] if len(argv) > 4 else "serial.log",
                run_token=run_token,
                run_owner=run_owner,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "snapshot-qemu-log-cursor":
            c_st, c_dev, c_ino, c_off = snapshot_qemu_log_cursor(
                argv[1], session=False, root_fd=root_fd, root_path=root_path
            )
            print(f"{c_st}\t{c_dev}\t{c_ino}\t{c_off}")
        elif op == "pin-qemu-log-cursor":
            cursor = (argv[2], int(argv[3]), int(argv[4]), int(argv[5]))
            expected_uuid = argv[6] if len(argv) > 6 and argv[6] else None
            pinned = pin_qemu_log_cursor(
                argv[1],
                cursor,
                expected_uuid=expected_uuid,
                session=False,
                root_fd=root_fd,
                root_path=root_path,
            )
            if pinned is None:
                return 1
            print(f"{pinned[0]}\t{pinned[1]}\t{pinned[2]}\t{pinned[3]}")
        elif op in ("collect-qemu-log", "collect-qemu-log-session"):
            is_session = op == "collect-qemu-log-session"
            cursor = (argv[4], int(argv[5]), int(argv[6]), int(argv[7]))
            expected_uuid = argv[8] if len(argv) > 8 and argv[8] else None
            run_token = argv[9] if len(argv) > 9 and argv[9] else None
            run_owner = argv[10] if len(argv) > 10 and argv[10] else None
            collect_qemu_log(
                argv[1],
                argv[2],
                argv[3],
                cursor=cursor,
                expected_uuid=expected_uuid,
                session=is_session,
                run_token=run_token,
                run_owner=run_owner,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "read-qemu-log-segment":
            cursor = (argv[2], int(argv[3]), int(argv[4]), int(argv[5]))
            expected_uuid = argv[6] if len(argv) > 6 and argv[6] else None
            data = read_qemu_log_segment(
                argv[1],
                cursor,
                expected_uuid=expected_uuid,
                session=False,
                root_fd=root_fd,
                root_path=root_path,
            )
            if data is None:
                return 1
            sys.stdout.buffer.write(data)
        elif op == "verify-cleanup-target":
            status, lexical_run, resolved_run, dir_id = verify_cleanup_target(
                argv[1], argv[2], root_fd=root_fd, root_path=root_path
            )
            print(f"{status}\t{lexical_run}\t{resolved_run}\t{dir_id}")
        elif op == "cleanup-run-dir":
            expected_dir_id = argv[3] if len(argv) > 3 and argv[3] else None
            status = cleanup_run_dir(
                argv[1],
                argv[2],
                expected_dir_id=expected_dir_id,
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
