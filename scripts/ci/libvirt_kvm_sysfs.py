#!/usr/bin/env python3
"""FD-anchored filesystem operations for the qemu:///system KVM smoke lane.

Extracted from scripts/ci/libvirt-kvm-smoke.sh so both the shell entrypoint
(via ``python3 -I``) and unprivileged unit tests can invoke the exact same
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

READ_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
RENAME_NOREPLACE = 1
SYMLOOP_MAX = 40
RUN_NAME_RE = re.compile(r"^qeminga-e2e-[0-9]+-[0-9]+-(x86_64|aarch64)$")

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
            errno.ENOTDIR, f"image root component '{path_label}' is not a directory"
        )
    trusted_owner, is_writable, reason = dir_trust_info(dfd, st, trusted_uids)
    if not trusted_owner:
        raise OSError(
            errno.EACCES,
            f"refusing untrusted ancestor directory '{path_label}' ({reason}); "
            "choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
        )
    if is_writable:
        if not (allow_sticky_writable and bool(st.st_mode & stat.S_ISVTX)):
            raise OSError(
                errno.EACCES,
                f"refusing shared writable ancestor directory '{path_label}' ({reason}); "
                "choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
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
                    f"image root component '{next_path}' is not a directory",
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

        # The deepest existing directory will host newly created components or
        # the per-run directory, so it MUST NOT be writable by other accounts
        # even when the sticky bit is set.
        if cur_writable:
            raise OSError(
                errno.EACCES,
                f"refusing shared writable directory '{cur_path}' ({cur_reason}); "
                "choose a root-owned non-shared QEMINGA_E2E_IMAGES path",
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
        # Complete replacement access ACL:
        #   user::rwx, user:<qemu_uid>:--x, group::---, mask::--x, other::---
        # Replacing the full ACL drops any inherited named user/group entries
        # and pins the mask strictly to search (--x).
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
            try:
                cur_lst = os.lstat(comp, dir_fd=parent_fd)
                if (cur_lst.st_dev, cur_lst.st_ino) == tfd_id:
                    os.rmdir(comp, dir_fd=parent_fd)
            except OSError:
                pass
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
        if root_fd is None:
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
    finally:
        os.close(cur_fd)
    if root_fd is None:
        kernel_verdict_traversal(os.path.normpath(target), qemu_uid, qemu_gid, qemu_groups)


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
    try:
        if remaining:
            raise OSError(errno.ENOENT, f"images root '{images_dir}' does not exist")
        if root_fd is None:
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
        os.close(rfd)
    finally:
        os.close(img_fd)
    if root_fd is None:
        kernel_verdict_traversal(
            os.path.join(os.path.normpath(images_dir), run_name),
            qemu_uid,
            qemu_gid,
            qemu_groups,
        )


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
        rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        try:
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


def _copy_regular_file_from_dir_fd(rfd, filename, dest_path):
    try:
        ffd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=rfd)
    except FileNotFoundError:
        return False
    try:
        fst = os.fstat(ffd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1:
            raise OSError(
                errno.EINVAL,
                f"refusing unsafe diagnostic file '{filename}' "
                "(must be regular file with nlink == 1)",
            )
        out_fd = os.open(
            dest_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o644,
        )
        try:
            while True:
                chunk = os.read(ffd, 65536)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(out_fd, view)
                    view = view[written:]
        finally:
            os.close(out_fd)
    finally:
        os.close(ffd)
    return True


def collect_serial_log(images_dir, run_name, dest_path, *, root_fd=None, root_path="/"):
    """Copy ``serial.log`` only from a trust-verified run directory using O_NOFOLLOW."""
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
    try:
        if remaining:
            return False
        img_st = os.fstat(img_fd)
        try:
            lst = os.lstat(run_name, dir_fd=img_fd)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
            raise OSError(
                errno.ENOTDIR,
                f"refusing non-directory run path '{os.path.join(img_path, run_name)}'",
            )
        rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        try:
            rst = os.fstat(rfd)
            if rst.st_dev != lst.st_dev or rst.st_ino != lst.st_ino:
                raise OSError(
                    errno.EXDEV,
                    f"run directory '{os.path.join(img_path, run_name)}' changed during verification",
                )
            if rst.st_dev != img_st.st_dev:
                raise OSError(
                    errno.EXDEV,
                    f"refusing cross-filesystem run directory '{os.path.join(img_path, run_name)}'",
                )
            verify_dir_fd(
                rfd,
                os.path.join(img_path, run_name),
                0,
                {0},
                trusted_uids,
                allow_sticky_writable=False,
                check_traversal=False,
            )
            return _copy_regular_file_from_dir_fd(rfd, "serial.log", dest_path)
        finally:
            os.close(rfd)
    finally:
        os.close(img_fd)


def collect_serial_log_session(images_dir, run_name, dest_path):
    """Copy ``serial.log`` in unprivileged session mode via O_NOFOLLOW regular-file checks."""
    if not RUN_NAME_RE.fullmatch(run_name):
        raise OSError(errno.EINVAL, f"invalid run dir name '{run_name}'")
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
            return _copy_regular_file_from_dir_fd(rfd, "serial.log", dest_path)
        finally:
            os.close(rfd)
    finally:
        os.close(img_fd)


def _rmtree_verified_fd(dfd, root_dev):
    for entry in os.listdir(dfd):
        est = os.lstat(entry, dir_fd=dfd)
        if stat.S_ISDIR(est.st_mode):
            cfd = os.open(entry, READ_DIR_FLAGS, dir_fd=dfd)
            try:
                cst = os.fstat(cfd)
                if cst.st_dev != root_dev:
                    raise OSError(
                        errno.EXDEV,
                        f"refusing mountpoint '{entry}' inside run directory",
                    )
                _rmtree_verified_fd(cfd, root_dev)
            finally:
                os.close(cfd)
            os.rmdir(entry, dir_fd=dfd)
        else:
            os.unlink(entry, dir_fd=dfd)


def cleanup_run_dir(images_dir, run_name, *, root_fd=None, root_path="/"):
    """Verify ancestor trust and run-directory ownership/identity before removing."""
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
    try:
        if remaining:
            return "absent"
        img_st = os.fstat(img_fd)
        try:
            lst = os.lstat(run_name, dir_fd=img_fd)
        except FileNotFoundError:
            return "absent"
        if stat.S_ISLNK(lst.st_mode) or not stat.S_ISDIR(lst.st_mode):
            raise OSError(
                errno.ENOTDIR,
                f"refusing non-directory run path '{os.path.join(img_path, run_name)}'",
            )
        rfd = os.open(run_name, READ_DIR_FLAGS, dir_fd=img_fd)
        try:
            rst = os.fstat(rfd)
            if rst.st_dev != lst.st_dev or rst.st_ino != lst.st_ino:
                raise OSError(
                    errno.EXDEV,
                    f"run directory '{os.path.join(img_path, run_name)}' changed during verification",
                )
            if rst.st_dev != img_st.st_dev:
                raise OSError(
                    errno.EXDEV,
                    f"refusing cross-filesystem run directory '{os.path.join(img_path, run_name)}'",
                )
            verify_dir_fd(
                rfd,
                os.path.join(img_path, run_name),
                0,
                {0},
                trusted_uids,
                allow_sticky_writable=False,
                check_traversal=False,
            )
            _rmtree_verified_fd(rfd, rst.st_dev)
            # Re-verify identity while `rfd` is still open before unlinking the directory.
            cur_lst = os.lstat(run_name, dir_fd=img_fd)
            if cur_lst.st_dev != rst.st_dev or cur_lst.st_ino != rst.st_ino:
                raise OSError(
                    errno.EXDEV,
                    f"run directory '{os.path.join(img_path, run_name)}' changed before removal",
                )
            os.rmdir(run_name, dir_fd=img_fd)
        finally:
            os.close(rfd)
        return "removed"
    finally:
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
        if op == "collect-serial-log-session":
            collect_serial_log_session(argv[1], argv[2], argv[3])
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
        elif op == "collect-serial-log":
            collect_serial_log(
                argv[1],
                argv[2],
                argv[3],
                root_fd=root_fd,
                root_path=root_path,
            )
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
    except OSError as exc:
        msg = exc.strerror if exc.strerror else str(exc)
        sys.stderr.write(f"libvirt-kvm-smoke: {msg}\n")
        return 1
    finally:
        if root_fd is not None:
            os.close(root_fd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
