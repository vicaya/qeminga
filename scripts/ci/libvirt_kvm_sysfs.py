#!/usr/bin/env python3
"""FD-anchored filesystem operations for the qemu:///system KVM smoke lane.

Extracted from scripts/ci/libvirt-kvm-smoke.sh so both the shell entrypoint
(via ``python3 -IB``) and unprivileged unit tests can invoke the exact same
verified operations without duplicating parsing or mocking host ``/``.
"""

from collections import deque
import ctypes
import errno
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
        raise OSError(
            errno.ENOTDIR, f"path component '{path_label}' is not a directory"
        )
    trusted_owner, is_writable, reason = dir_trust_info(dfd, st, trusted_uids)
    if not trusted_owner:
        raise OSError(
            errno.EACCES,
            f"refusing untrusted ancestor directory '{path_label}' ({reason}); "
            "choose a root-owned non-shared path",
        )
    if is_writable:
        if not (allow_sticky_writable and bool(st.st_mode & stat.S_ISVTX)):
            raise OSError(
                errno.EACCES,
                f"refusing shared writable ancestor directory '{path_label}' ({reason}); "
                "choose a root-owned non-shared path",
            )
    if check_traversal and not can_traverse_fd(dfd, st, qemu_uid, qemu_groups):
        raise OSError(
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
        raise OSError(
            errno.EACCES,
            f"path '{abs_path}' is outside verified root '{norm_root}'",
        )
    return [p for p in abs_path[len(prefix) :].split("/") if p]


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
    norm = os.path.normpath(target)
    if not norm.startswith("/"):
        raise OSError(errno.EINVAL, f"path must be absolute: '{target}'")
    if root_fd is None:
        norm_root = "/"
        parts = [p for p in norm.split("/") if p]
        cur_fd = os.open("/", READ_DIR_FLAGS)
    else:
        norm_root = os.path.normpath(root_path)
        if not norm_root.startswith("/"):
            raise OSError(errno.EINVAL, f"root_path must be absolute: '{root_path}'")
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
                    raise OSError(
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
                    raise OSError(
                        errno.ENOENT,
                        f"dangling symlink encountered while resolving '{target}' at "
                        f"'{os.path.join(cur_path, comp)}'",
                    )
                remaining = [comp] + [p[0] for p in pending]
                break
            if stat.S_ISLNK(lst.st_mode):
                symlinks += 1
                if symlinks > SYMLOOP_MAX:
                    raise OSError(
                        errno.ELOOP, f"too many symbolic links resolving '{target}'"
                    )
                if lst.st_uid not in trusted_uids:
                    raise OSError(
                        errno.EACCES,
                        f"refusing untrusted symlink '{os.path.join(cur_path, comp)}' "
                        f"owned by uid {lst.st_uid}",
                    )
                link_target = os.readlink(comp, dir_fd=cur_fd)
                if not link_target:
                    raise OSError(
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
                            raise OSError(
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
                raise OSError(
                    errno.ENOTDIR,
                    f"path component '{next_path}' is not a directory",
                )
            next_fd = os.open(comp, READ_DIR_FLAGS, dir_fd=cur_fd)
            try:
                nst = os.fstat(next_fd)
                if nst.st_dev != lst.st_dev or nst.st_ino != lst.st_ino:
                    raise OSError(
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
            raise OSError(
                errno.EACCES,
                f"refusing shared writable directory '{cur_path}' ({cur_reason}); "
                "choose a root-owned non-shared path",
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


def _create_public_dir_in_fd(parent_fd, parent_path, comp, trusted_uids):
    tmp_name = f".qeminga-e2e-evinit.{os.urandom(8).hex()}"
    os.mkdir(tmp_name, 0o700, dir_fd=parent_fd)
    published = False
    tfd = None
    try:
        tfd = os.open(tmp_name, READ_DIR_FLAGS, dir_fd=parent_fd)
        if os.geteuid() == 0:
            os.fchown(tfd, 0, 0)
        remove_xattr_if_present(tfd, b"system.posix_acl_default")
        remove_xattr_if_present(tfd, b"system.posix_acl_access")
        os.fchmod(tfd, 0o755)
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
                    trusted_uids,
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
    out_dir, *, create_missing=True, root_fd=None, root_path="/"
):
    abs_out = os.path.abspath(out_dir)
    trusted_uids = trusted_owner_uids()
    cur_fd, cur_path, _, remaining = walk_existing_prefix(
        abs_out,
        0,
        {0},
        trusted_uids,
        check_traversal=False,
        root_fd=root_fd,
        root_path=root_path,
    )
    try:
        if remaining and not create_missing:
            raise OSError(errno.ENOENT, f"evidence directory '{abs_out}' does not exist")
        for comp in remaining:
            next_fd = _create_public_dir_in_fd(cur_fd, cur_path, comp, trusted_uids)
            next_path = os.path.join(cur_path, comp)
            os.close(cur_fd)
            cur_fd, cur_path = next_fd, next_path
        verify_dir_fd(
            cur_fd,
            cur_path,
            0,
            {0},
            trusted_uids,
            allow_sticky_writable=False,
            check_traversal=False,
        )
        return cur_fd, cur_path
    except Exception:
        os.close(cur_fd)
        raise


def _publish_evidence_stream(out_fd, dest_name, write_fn, mode=0o644):
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
        # Atomic replacement unlinks any pre-existing directory entry (including
        # a symlink or hard-linked file) without opening or truncating its inode,
        # and sets permissions exclusively on the newly created file.
        os.replace(tmp_name, dest_name, src_dir_fd=out_fd, dst_dir_fd=out_fd)
        published = True
        os.fsync(out_fd)
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


def prepare_evidence_dir(out_dir, *, init_run=False, root_fd=None, root_path="/"):
    """Validate/create a trusted evidence directory; optionally reset known run outputs."""
    trusted_uids = trusted_owner_uids()
    out_fd, out_path = _open_verified_evidence_dir(
        out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
    )
    try:
        if init_run:
            out_st = os.fstat(out_fd)
            out_mnt = fd_mnt_id(out_fd)
            for name in ALLOWED_EVIDENCE_FILES:
                try:
                    rst = os.lstat(name, dir_fd=out_fd)
                    if not stat.S_ISDIR(rst.st_mode):
                        os.unlink(name, dir_fd=out_fd)
                except FileNotFoundError:
                    pass
            tests_fd = _create_public_dir_in_fd(out_fd, out_path, "tests", trusted_uids)
            try:
                tst = os.fstat(tests_fd)
                if tst.st_dev != out_st.st_dev or fd_mnt_id(tests_fd) != out_mnt:
                    raise OSError(
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
    out_dir, dest_name, data, *, subdir=None, root_fd=None, root_path="/"
):
    trusted_uids = trusted_owner_uids()
    if subdir == "tests":
        if dest_name not in ALLOWED_TEST_FILES:
            raise OSError(errno.EINVAL, f"unexpected test result filename '{dest_name}'")
    elif subdir is None:
        if dest_name not in ALLOWED_EVIDENCE_FILES:
            raise OSError(errno.EINVAL, f"unexpected evidence filename '{dest_name}'")
    else:
        raise OSError(errno.EINVAL, f"unexpected evidence subdirectory '{subdir}'")

    out_fd, out_path = _open_verified_evidence_dir(
        out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
    )
    try:
        if subdir is not None:
            out_st = os.fstat(out_fd)
            out_mnt = fd_mnt_id(out_fd)
            sub_fd = _create_public_dir_in_fd(out_fd, out_path, subdir, trusted_uids)
            try:
                sst = os.fstat(sub_fd)
                if sst.st_dev != out_st.st_dev or fd_mnt_id(sub_fd) != out_mnt:
                    raise OSError(
                        errno.EXDEV,
                        f"refusing cross-mount evidence subdirectory '{os.path.join(out_path, subdir)}'",
                    )
                _publish_evidence_stream(
                    sub_fd, dest_name, lambda fd: _write_all_fd(fd, data), mode=0o644
                )
            finally:
                os.close(sub_fd)
        else:
            _publish_evidence_stream(
                out_fd, dest_name, lambda fd: _write_all_fd(fd, data), mode=0o644
            )
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


def publish_evidence_bytes_session(out_dir, dest_name, data):
    """Atomically publish an allowlisted session diagnostic file with private 0600 mode."""
    if dest_name not in ALLOWED_EVIDENCE_FILES:
        raise OSError(errno.EINVAL, f"unexpected evidence filename '{dest_name}'")
    os.makedirs(out_dir, exist_ok=True)
    out_fd = os.open(out_dir, READ_DIR_FLAGS)
    try:
        _publish_evidence_stream(
            out_fd, dest_name, lambda fd: _write_all_fd(fd, data), mode=0o600
        )
    finally:
        os.close(out_fd)


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
    if session:
        os.makedirs(out_dir, exist_ok=True)
        out_fd = os.open(out_dir, READ_DIR_FLAGS)
    else:
        out_fd, _ = _open_verified_evidence_dir(
            out_dir, create_missing=True, root_fd=root_fd, root_path=root_path
        )
    try:
        _publish_evidence_stream(
            out_fd,
            dest_name,
            lambda dst: _write_all_fd(dst, data),
            mode=0o600 if session else 0o644,
        )
    finally:
        os.close(out_fd)
    return True


def collect_serial_log_session(images_dir, run_name, out_dir, dest_name="serial.log"):
    """Copy ``serial.log`` in unprivileged session mode via O_NOFOLLOW + private 0600 publish."""
    if not RUN_NAME_RE.fullmatch(run_name):
        raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
    if dest_name != "serial.log":
        raise OSError(errno.EINVAL, f"unexpected serial log filename '{dest_name}'")
    try:
        img_fd = os.open(images_dir, READ_DIR_FLAGS)
    except FileNotFoundError:
        return False
    try:
        try:
            rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        except FileNotFoundError:
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
                os.makedirs(out_dir, exist_ok=True)
                out_fd = os.open(out_dir, READ_DIR_FLAGS)
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


def main(argv):
    if not argv:
        sys.stderr.write("libvirt-kvm-smoke: missing sys_fs_ops subcommand\n")
        return 1
    op = argv[0]
    root_fd = None
    try:
        if op == "strip-session-dir-acl":
            strip_session_dir_acl(argv[1])
            return 0
        if op == "publish-evidence-stdin-session":
            data = sys.stdin.buffer.read()
            publish_evidence_bytes_session(argv[1], argv[2], data)
            return 0
        if op == "collect-serial-log-session":
            collect_serial_log_session(
                argv[1], argv[2], argv[3], argv[4] if len(argv) > 4 else "serial.log"
            )
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
        if op == "collect-qemu-log-session":
            cursor = (argv[4], int(argv[5]), int(argv[6]), int(argv[7]))
            expected_uuid = argv[8] if len(argv) > 8 and argv[8] else None
            collect_qemu_log(
                argv[1],
                argv[2],
                argv[3],
                cursor=cursor,
                expected_uuid=expected_uuid,
                session=True,
            )
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
        elif op == "prepare-evidence-dir":
            init_run = len(argv) > 2 and argv[2] == "init-run"
            prepare_evidence_dir(
                argv[1], init_run=init_run, root_fd=root_fd, root_path=root_path
            )
        elif op == "publish-evidence-stdin":
            subdir = argv[3] if len(argv) > 3 and argv[3] else None
            data = sys.stdin.buffer.read()
            publish_evidence_bytes(
                argv[1],
                argv[2],
                data,
                subdir=subdir,
                root_fd=root_fd,
                root_path=root_path,
            )
        elif op == "collect-serial-log":
            expected_dir_id = argv[5] if len(argv) > 5 and argv[5] else None
            collect_serial_log(
                argv[1],
                argv[2],
                argv[3],
                argv[4] if len(argv) > 4 else "serial.log",
                expected_dir_id=expected_dir_id,
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
        elif op == "collect-qemu-log":
            cursor = (argv[4], int(argv[5]), int(argv[6]), int(argv[7]))
            expected_uuid = argv[8] if len(argv) > 8 and argv[8] else None
            collect_qemu_log(
                argv[1],
                argv[2],
                argv[3],
                cursor=cursor,
                expected_uuid=expected_uuid,
                session=False,
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
    except OSError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return 1
    finally:
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
