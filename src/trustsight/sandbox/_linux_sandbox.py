"""Linux OS confinement for the isolated git worker (A16).

The git worker is the boundary between attacker-authored repository data and
libgit2, which is C this project consumes but does not audit.  Resource limits
and ``PR_SET_NO_NEW_PRIVS`` bound the *spend* of a defect there, but they do
not stop it from executing with the operator's own filesystem and network
access.  This module adds the confinement the old A16 explicitly lacked: a
separate user and network namespace, Landlock over the filesystem, a seccomp
allowlist, and no capabilities.

The worker runs in one of two roles:

``fetch``
    It may reach the AUR, but only through a loopback bridge to a
    parent-owned CONNECT proxy that accepts exactly ``aur.archlinux.org:443``.
    The bridge uses inherited, already-connected Unix socketpairs; the
    seccomp filter permits only ``AF_INET``/``AF_INET6`` socket creation, so
    code execution in the worker cannot open a new Unix socket to a host
    service.  Its network namespace has no route off the machine.  The
    filesystem is restricted to the cache (read/write during fetch) and the
    interpreter/source trees (read-only).

``read``
    No proxy descriptors are passed, loopback is left down and the seccomp
    filter has no socket syscalls.  The worker parses the downloaded
    repository with no network path at all and a read-only cache.

Every protection is applied before the first request is served.  A protection
that cannot be applied is returned to the parent and refuses the worker: a
package analysed with weaker confinement than the design claims is not a
package this tool has vetted (B2).  The Linux kernel is part of the trusted
computing base, as it already was; the point is that a defect in *libgit2*
must not get the operator's filesystem or an arbitrary socket.
"""

from __future__ import annotations

import ctypes
import errno
import os
import resource
import select
import socket
import struct
import sys
import threading
from pathlib import Path

__all__ = ["apply"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_PR_CAPBSET_DROP = 24
_SECCOMP_SET_MODE_FILTER = 1
_SECCOMP_FILTER_FLAG_TSYNC = 1
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000

_CLONE_NEWUSER = 0x10000000
_CLONE_NEWNET = 0x40000000

_LANDLOCK_CREATE_RULESET_VERSION = 1
_LANDLOCK_RULE_PATH_BENEATH = 1

#: (syscall number on x86_64, aarch64) for the two architectures Arch Linux
#: targets.  The architecture is checked in the BPF program itself, so a
#: filter cannot be reused on an unexpected ABI.
_NR = {
    "landlock_create_ruleset": (444, 444),
    "landlock_add_rule": (445, 445),
    "landlock_restrict_self": (446, 446),
    "seccomp": (317, 277),
}

#: audit(4) architecture identifiers.
_AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}

#: Filesystem access rights, by Landlock ABI.
_ACCESS_EXECUTE = 1 << 0
_ACCESS_WRITE_FILE = 1 << 1
_ACCESS_READ_FILE = 1 << 2
_ACCESS_READ_DIR = 1 << 3
_ACCESS_REMOVE_DIR = 1 << 4
_ACCESS_REMOVE_FILE = 1 << 5
_ACCESS_MAKE_CHAR = 1 << 6
_ACCESS_MAKE_DIR = 1 << 7
_ACCESS_MAKE_REG = 1 << 8
_ACCESS_MAKE_SOCK = 1 << 9
_ACCESS_MAKE_FIFO = 1 << 10
_ACCESS_MAKE_BLOCK = 1 << 11
_ACCESS_MAKE_SYM = 1 << 12
_ACCESS_REFER = 1 << 13
_ACCESS_TRUNCATE = 1 << 14
_ACCESS_IOCTL_DEV = 1 << 15

_READ_ONLY = _ACCESS_READ_FILE | _ACCESS_READ_DIR
_WRITABLE = (
    _ACCESS_READ_FILE | _ACCESS_WRITE_FILE | _ACCESS_READ_DIR
    | _ACCESS_REMOVE_DIR | _ACCESS_REMOVE_FILE | _ACCESS_MAKE_DIR
    | _ACCESS_MAKE_REG | _ACCESS_MAKE_SYM | _ACCESS_MAKE_SOCK
    | _ACCESS_MAKE_FIFO | _ACCESS_MAKE_CHAR | _ACCESS_MAKE_BLOCK
    | _ACCESS_REFER | _ACCESS_TRUNCATE
)

_SIOCGIFFLAGS = 0x8913
_SIOCSIFFLAGS = 0x8914
_IFF_UP = 0x1
_IFF_RUNNING = 0x40

_MAX_PROXY_ACCEPT = 16
_RELAY_CHUNK = 65536

# ---------------------------------------------------------------------------
# Syscall allowlist
# ---------------------------------------------------------------------------

#: Names the worker may issue after confinement.  Everything else is killed.
#: The list is deliberately positive: a new syscall is a reviewed change, not
#: a silent grant.  Network names are present because the fetch role's
#: only network endpoint is the loopback bridge; the namespace, not the filter,
#: is what removes the route off the machine.
_ALLOWED_SYSCALLS = frozenset("""
read write readv writev pread64 pwrite64 lseek close stat lstat fstat fstatat newfstatat statx
statfs fstatfs access faccessat faccessat2 openat openat2 getdents64 getcwd
chdir mkdir mkdirat rmdir unlink unlinkat rename renameat renameat2 link linkat
symlink symlinkat readlink readlinkat chmod fchmod fchmodat chown fchown fchownat
ftruncate fallocate fsync
fdatasync flock fcntl ioctl dup dup2 dup3 pipe pipe2 select pselect6 poll ppoll
epoll_create1 epoll_ctl epoll_wait epoll_pwait epoll_pwait2 eventfd eventfd2
futex futex_waitv sched_yield sched_getaffinity getrandom clock_gettime
clock_getres gettimeofday time nanosleep clock_nanosleep restart_syscall rseq
set_robust_list set_tid_address mmap munmap mprotect mremap madvise mlock
mlock2 munlock mlockall munlockall msync brk rt_sigaction rt_sigprocmask
rt_sigreturn sigaltstack sigprocmask getsid getpid getppid gettid getuid geteuid
getgid getegid getpgid getpgrp exit exit_group uname sysinfo
prctl prlimit64 getrlimit setrlimit setitimer getitimer timer_create
timer_settime timer_gettime timer_getoverrun timer_delete timerfd_create
timerfd_settime timerfd_gettime capget capset clone clone3 wait4 waitid umask
utimensat getrusage membarrier mincore fadvise64 sync syncfs truncate close_range
copy_file_range sendfile splice tee
""".split())

#: Network syscalls the fetch role may issue.  The read role gets none: a
#: repository walk has no legitimate socket, and refusing them closes the
#: path-based Unix-socket escape Landlock does not mediate.
_NETWORK_SYSCALLS = frozenset("""
socket bind listen accept accept4 connect getsockname getpeername
sendto recvfrom sendmsg recvmsg shutdown getsockopt setsockopt
""".split())


#: x86_64 numbers for :data:`_ALLOWED_SYSCALLS`.  Kept as one table so a
#: reviewer can diff it against ``asm/unistd_64.h``.
_X86_64 = {
    "read": 0, "write": 1, "openat": 257, "openat2": 437, "close": 3,
    "mmap": 9, "mprotect": 10, "munmap": 11, "mremap": 25, "brk": 12,
    "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15, "ioctl": 16,
    "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20, "access": 21,
    "faccessat": 269, "faccessat2": 439, "dup": 32, "dup2": 33, "dup3": 292,
    "pipe": 22, "pipe2": 293, "select": 23, "pselect6": 270, "poll": 7,
    "ppoll": 271, "epoll_create1": 291, "epoll_ctl": 233, "epoll_wait": 232,
    "epoll_pwait": 281, "epoll_pwait2": 441, "eventfd": 284,
    "eventfd2": 290, "futex": 202, "futex_waitv": 449, "sched_yield": 24,
    "madvise": 28, "sched_getaffinity": 204, "getrandom": 318, "clock_gettime": 228,
    "clock_getres": 229, "gettimeofday": 96, "time": 201, "nanosleep": 35,
    "clock_nanosleep": 230, "restart_syscall": 219, "rseq": 334,
    "set_robust_list": 273, "set_tid_address": 218, "mlock": 149,
    "mlock2": 325, "munlock": 150, "mlockall": 151, "munlockall": 152,
    "msync": 26, "sigaltstack": 131, "sigprocmask": 14, "getsid": 124,
    "getpid": 39, "getppid": 110, "gettid": 186, "getuid": 102,
    "geteuid": 107, "getgid": 104, "getegid": 108, "getpgid": 121,
    "getpgrp": 111, "tgkill": 234, "kill": 62, "tkill": 200, "exit": 60,
    "exit_group": 231, "uname": 63, "sysinfo": 99, "prctl": 157,
    "prlimit64": 302, "getrlimit": 97, "setrlimit": 160, "setitimer": 38,
    "getitimer": 36, "timer_create": 222, "timer_settime": 223,
    "timer_gettime": 224, "timer_getoverrun": 225, "timer_delete": 226,
    "timerfd_create": 283, "timerfd_settime": 286, "timerfd_gettime": 287,
    "capget": 125, "capset": 126, "socket": 41, "socketpair": 53,
    "bind": 49, "listen": 50, "accept": 43, "accept4": 288, "connect": 42,
    "getsockname": 51, "getpeername": 52, "sendto": 44, "recvfrom": 45,
    "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "getsockopt": 55,
    "setsockopt": 54, "clone": 56, "clone3": 435, "fork": 57, "vfork": 58,
    "wait4": 61, "waitid": 247, "umask": 95, "utimensat": 280,
    "getrusage": 98, "membarrier": 324, "mincore": 27, "fadvise64": 221,
    "sync": 162, "syncfs": 306, "truncate": 76, "close_range": 436,
    "copy_file_range": 326, "sendfile": 40, "splice": 275, "tee": 276,
    "stat": 4, "lstat": 6, "fstat": 5, "fstatat": 262,
    "newfstatat": 262, "statx": 332, "statfs": 137,
    "fstatfs": 138, "getdents64": 217, "getcwd": 79, "chdir": 80,
    "mkdir": 83, "mkdirat": 258, "rmdir": 84, "unlink": 87, "unlinkat": 263,
    "rename": 82, "renameat": 264, "renameat2": 316, "link": 86, "linkat": 265,
    "symlink": 88, "symlinkat": 266, "readlink": 89, "readlinkat": 267,
    "chmod": 90, "fchmod": 91,
    "fchmodat": 268, "chown": 92, "fchown": 93, "fchownat": 260,
    "ftruncate": 77, "utime": 132, "utimes": 235, "futimesat": 261,
    "fallocate": 285, "fsync": 74, "fdatasync": 75, "flock": 73,
    "fcntl": 72, "lseek": 8,
}

#: aarch64 is the asm-generic table, with the legacy aliases filled in where
#: the generic table uses a 3264-prefixed name.
_AARCH64 = {
    "read": 63, "write": 64, "openat": 56, "openat2": 437, "close": 57,
    "mmap": 222, "mprotect": 226, "munmap": 215, "mremap": 216, "brk": 214,
    "rt_sigaction": 134, "rt_sigprocmask": 135, "rt_sigreturn": 139,
    "ioctl": 29, "pread64": 67, "pwrite64": 68, "readv": 65, "writev": 66,
    "access": 48, "faccessat": 48, "faccessat2": 439, "dup": 23, "dup2": 24,
    "dup3": 24, "pipe": 59, "pipe2": 59, "select": 72, "pselect6": 72,
    "poll": 73, "ppoll": 73, "epoll_create1": 20, "epoll_ctl": 21,
    "epoll_wait": 22, "epoll_pwait": 22, "epoll_pwait2": 441,
    "eventfd": 19, "eventfd2": 19, "futex": 98, "futex_waitv": 449,
    "sched_yield": 124, "madvise": 233, "sched_getaffinity": 123, "getrandom": 278,
    "clock_gettime": 113, "clock_getres": 114, "gettimeofday": 169,
    "time": 169, "nanosleep": 101, "clock_nanosleep": 115,
    "restart_syscall": 128, "rseq": 293, "set_robust_list": 99,
    "set_tid_address": 96, "mlock": 228, "mlock2": 284, "munlock": 229,
    "mlockall": 230, "munlockall": 231, "msync": 227, "sigaltstack": 132,
    "sigprocmask": 135, "getsid": 156, "getpid": 172, "getppid": 173,
    "gettid": 178, "getuid": 174, "geteuid": 175, "getgid": 176,
    "getegid": 177, "getpgid": 155, "getpgrp": 155, "tgkill": 131,
    "kill": 129, "tkill": 130, "exit": 93, "exit_group": 94, "uname": 160,
    "sysinfo": 179, "prctl": 167, "prlimit64": 261, "getrlimit": 163,
    "setrlimit": 164, "setitimer": 103, "getitimer": 102,
    "timer_create": 107, "timer_settime": 110, "timer_gettime": 108,
    "timer_getoverrun": 109, "timer_delete": 111, "timerfd_create": 85,
    "timerfd_settime": 86, "timerfd_gettime": 87, "capget": 90,
    "capset": 91, "socket": 198, "socketpair": 199, "bind": 200,
    "listen": 201, "accept": 202, "accept4": 242, "connect": 203,
    "getsockname": 204, "getpeername": 205, "sendto": 206, "recvfrom": 207,
    "sendmsg": 211, "recvmsg": 212, "shutdown": 210, "getsockopt": 209,
    "setsockopt": 208, "clone": 220, "clone3": 435, "fork": 220,
    "vfork": 58, "wait4": 260, "waitid": 95, "umask": 166,
    "utimensat": 88, "getrusage": 165, "membarrier": 283, "mincore": 232,
    "fadvise64": 223, "sync": 81, "syncfs": 267, "truncate": 45,
    "close_range": 436, "copy_file_range": 285, "sendfile": 71,
    "splice": 76, "tee": 77, "stat": 79, "lstat": 79, "fstat": 80,
    "fstatat": 79, "newfstatat": 79, "statx": 291,
    "statfs": 43, "fstatfs": 44, "getdents64": 61, "getcwd": 17,
    "chdir": 49, "mkdir": 34, "mkdirat": 34, "rmdir": 35, "unlink": 35,
    "unlinkat": 35, "rename": 38, "renameat": 38, "renameat2": 276,
    "link": 37, "linkat": 37, "symlink": 36, "symlinkat": 36,
    "readlink": 78, "readlinkat": 78, "chmod": 53, "fchmod": 52,
    "fchmodat": 53, "chown": 54, "fchown": 55, "fchownat": 54,
    "ftruncate": 46, "utime": 88, "utimes": 88, "futimesat": 88,
    "fallocate": 47, "fsync": 82, "fdatasync": 83, "flock": 32,
    "fcntl": 25, "lseek": 62,
}


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _syscall_number(name: str) -> int:
    architecture = os.uname().machine
    if architecture not in _AUDIT_ARCH:
        raise OSError(errno.ENOSYS, f"unsupported architecture {architecture}")
    return _NR[name][0 if architecture == "x86_64" else 1]


# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------


def _write_proc(path: str, value: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CLOEXEC)
    try:
        os.write(fd, value.encode("ascii"))
    finally:
        os.close(fd)


def _enter_user_namespace(uid: int, gid: int) -> None:
    """Create a user namespace mapping only the current uid/gid.

    This is what lets an unprivileged process create a network namespace.  It
    grants no privilege on the host: the mapped identity is the operator's own
    unprivileged one, and the worker drops every capability afterwards.
    """
    libc = _libc()
    if libc.unshare(_CLONE_NEWUSER) != 0:
        raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWUSER) failed")
    try:
        _write_proc("/proc/self/setgroups", "deny")
    except OSError:
        # Older kernels do not expose setgroups; gid_map still applies.
        pass
    _write_proc("/proc/self/uid_map", f"0 {uid} 1")
    _write_proc("/proc/self/gid_map", f"0 {gid} 1")


def _enter_network_namespace() -> None:
    libc = _libc()
    if libc.unshare(_CLONE_NEWNET) != 0:
        raise OSError(ctypes.get_errno(), "unshare(CLONE_NEWNET) failed")


def _loopback_up() -> None:
    """Bring ``lo`` up inside the worker's own, otherwise empty, netns."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        request = bytearray(struct.pack("16sH", b"lo", 0).ljust(40, b"\0"))
        import fcntl

        fcntl.ioctl(sock.fileno(), _SIOCGIFFLAGS, request)
        flags = struct.unpack_from("H", request, 16)[0]
        struct.pack_into("H", request, 16, flags | _IFF_UP | _IFF_RUNNING)
        fcntl.ioctl(sock.fileno(), _SIOCSIFFLAGS, request)


# ---------------------------------------------------------------------------
# Fetch bridge: loopback TCP -> parent Unix-socket proxy
# ---------------------------------------------------------------------------


def _relay(left: socket.socket, right: socket.socket) -> None:
    try:
        while True:
            readable, _, _ = select.select([left, right], [], [], 0.2)
            for source in readable:
                target = right if source is left else left
                try:
                    chunk = source.recv(_RELAY_CHUNK)
                except OSError:
                    return
                if not chunk:
                    try:
                        target.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                try:
                    target.sendall(chunk)
                except OSError:
                    return
    finally:
        for sock in (left, right):
            try:
                sock.close()
            except OSError:
                pass


def _bridge(client: socket.socket, upstream: socket.socket) -> None:
    _relay(client, upstream)


def _start_fetch_bridge(proxy_fds) -> str:
    """Listen on the worker's loopback and forward each connection.

    Returns the proxy URL libgit2 should use.  The listener exists only in
    the worker's private network namespace, so nothing on the host can reach
    it, and libgit2 can reach nothing else.  Each accepted connection takes
    one inherited, already-connected proxy socketpair; no new Unix socket is
    created after seccomp.
    """
    pool = [socket.socket(fileno=fd) for fd in proxy_fds]
    for upstream in pool:
        upstream.setblocking(True)
    free = list(pool)
    lock = threading.Lock()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(_MAX_PROXY_ACCEPT)
    port = server.getsockname()[1]

    def serve() -> None:
        while True:
            try:
                client, _ = server.accept()
            except OSError:
                return
            with lock:
                upstream = free.pop() if free else None
            if upstream is None:
                try:
                    client.close()
                except OSError:
                    pass
                continue
            threading.Thread(
                target=_bridge, args=(client, upstream), daemon=True
            ).start()

    threading.Thread(target=serve, daemon=True).start()
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Landlock
# ---------------------------------------------------------------------------


class _RulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _PathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


def _landlock_abi(libc) -> int:
    libc.syscall.restype = ctypes.c_long
    abi = libc.syscall(_syscall_number("landlock_create_ruleset"),
                       None, 0, _LANDLOCK_CREATE_RULESET_VERSION)
    if abi < 0:
        raise OSError(ctypes.get_errno(), "landlock is unavailable")
    return abi


def _is_directory(fd: int) -> bool:
    return (os.fstat(fd).st_mode & 0o170000) == 0o040000


def _add_landlock_rule(libc, ruleset: int, path: str, access: int) -> None:
    try:
        fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except FileNotFoundError:
        return
    except OSError as exc:
        if exc.errno in (errno.ENOTDIR,):
            return
        raise
    try:
        # Directory-only rights (READ_DIR, MAKE_DIR, REMOVE_DIR, ...) are
        # invalid for a regular file, and a rule carrying them is refused
        # with EINVAL.  Files get only the file-shaped rights.
        if not _is_directory(fd):
            access &= (
                _ACCESS_EXECUTE | _ACCESS_WRITE_FILE | _ACCESS_READ_FILE
                | _ACCESS_TRUNCATE | _ACCESS_IOCTL_DEV
            )
            if access == 0:
                return
        attr = _PathBeneathAttr(access, fd)
        if libc.syscall(_syscall_number("landlock_add_rule"), ruleset,
                        _LANDLOCK_RULE_PATH_BENEATH,
                        ctypes.byref(attr), 0) != 0:
            raise OSError(ctypes.get_errno(),
                          f"landlock_add_rule({path}) failed")
    finally:
        os.close(fd)


def _read_paths() -> list[str]:
    """Trusted read-only code and data the interpreter already relies on."""
    paths: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        resolved = str(Path(entry).resolve())
        if resolved != "/" and os.path.exists(resolved):
            paths.append(resolved)
    paths.extend([
        sys.base_prefix, sys.exec_prefix,
        "/usr", "/usr/local", "/lib", "/lib64", "/bin", "/sbin",
        "/etc/ssl", "/etc/ca-certificates", "/etc/pki", "/etc/ld.so.cache",
        "/etc/localtime", "/etc/hosts", "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
    ])
    unique: list[str] = []
    for path in paths:
        if path not in unique:
            unique.append(path)
    return unique


def _apply_landlock(libc, cache_dir: str, home_dir: str,
                    cache_is_writable: bool) -> None:
    abi = _landlock_abi(libc)
    # The parser hardening design requires the strongest kernel floor, not
    # a best-effort fallback.  ABI 6 (Linux 6.12+) carries the IPC/signal
    # scoping and the later filesystem rights this policy was reviewed
    # against; an older kernel refuses the worker instead of quietly
    # providing a weaker sandbox than the verdict claims.
    if abi < 6:
        raise OSError(errno.ENOSYS, "landlock ABI 6 or newer is required")

    handled = (
        _ACCESS_EXECUTE | _ACCESS_WRITE_FILE | _ACCESS_READ_FILE
        | _ACCESS_READ_DIR | _ACCESS_REMOVE_DIR | _ACCESS_REMOVE_FILE
        | _ACCESS_MAKE_CHAR | _ACCESS_MAKE_DIR | _ACCESS_MAKE_REG
        | _ACCESS_MAKE_SOCK | _ACCESS_MAKE_FIFO | _ACCESS_MAKE_BLOCK
        | _ACCESS_MAKE_SYM
    )
    if abi >= 2:
        handled |= _ACCESS_REFER
    if abi >= 3:
        handled |= _ACCESS_TRUNCATE
    if abi >= 5:
        handled |= _ACCESS_IOCTL_DEV

    attributes = _RulesetAttr(handled, 0)
    ruleset = libc.syscall(_syscall_number("landlock_create_ruleset"),
                           ctypes.byref(attributes),
                           ctypes.sizeof(attributes), 0)
    if ruleset < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    try:
        for path in _read_paths():
            _add_landlock_rule(libc, ruleset, path, _READ_ONLY)
        if cache_dir:
            _add_landlock_rule(
                libc, ruleset, cache_dir,
                _WRITABLE if cache_is_writable else _READ_ONLY)
        if home_dir:
            _add_landlock_rule(libc, ruleset, home_dir, _WRITABLE)
        if libc.syscall(_syscall_number("landlock_restrict_self"),
                        ruleset, 0) != 0:
            raise OSError(ctypes.get_errno(),
                          "landlock_restrict_self failed")
    finally:
        os.close(ruleset)


# ---------------------------------------------------------------------------
# seccomp
# ---------------------------------------------------------------------------


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_JMP_JSET_K = 0x45
_BPF_RET_K = 0x06
_SECCOMP_DATA_ARGS = 16
_CLONE_THREAD = 0x00010000
_AF_INET = 2
_AF_INET6 = 10


def _syscall_table(role: str) -> dict[str, int]:
    architecture = os.uname().machine
    if architecture == "x86_64":
        table = _X86_64
    elif architecture == "aarch64":
        table = _AARCH64
    else:
        raise OSError(errno.ENOSYS,
                      f"unsupported architecture {architecture}")
    names = set(_ALLOWED_SYSCALLS)
    if role == "fetch":
        names |= _NETWORK_SYSCALLS
    missing = sorted(name for name in names if name not in table)
    if missing:
        # A name listed as allowed but absent from the table would be
        # *denied*, and the worker would die on a legitimate call.  Refuse
        # the sandbox instead of shipping a filter that silently disagrees
        # with its own source of truth.
        raise OSError(errno.ENOSYS,
                      f"missing syscall numbers for {', '.join(missing)}")
    return {name: table[name] for name in names}


def _install_seccomp(libc, role: str) -> None:
    architecture = os.uname().machine
    if architecture not in _AUDIT_ARCH:
        raise OSError(errno.ENOSYS,
                      f"unsupported architecture {architecture}")
    table = _syscall_table(role)
    numbers = set(table.values())

    instructions = [
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 4),  # seccomp_data.arch
        _SockFilter(_BPF_JMP_JEQ_K, 1, 0, _AUDIT_ARCH[architecture]),
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        _SockFilter(_BPF_LD_W_ABS, 0, 0, 0),  # seccomp_data.nr
    ]

    # Thread creation needs clone/clone3, but a process-creating clone would
    # let a defect multiply itself.  clone3 is answered ENOSYS so glibc falls
    # back to clone, and clone is allowed only with CLONE_THREAD set.  fork
    # and vfork are not in the table at all.
    clone3 = table.get("clone3")
    clone = table.get("clone")
    if clone3 is not None:
        instructions.extend([
            _SockFilter(_BPF_JMP_JEQ_K, 0, 1, clone3),
            _SockFilter(_BPF_RET_K, 0, 0,
                        _SECCOMP_RET_ERRNO | errno.ENOSYS),
        ])
        numbers.discard(clone3)
    if clone is not None:
        instructions.extend([
            _SockFilter(_BPF_JMP_JEQ_K, 0, 4, clone),
            _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARGS),
            _SockFilter(_BPF_JMP_JSET_K, 0, 1, _CLONE_THREAD),
            _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
            _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        ])
        numbers.discard(clone)

    # The fetch role is the only one with sockets.  Even there, only AF_INET
    # and AF_INET6 may be created: the inherited proxy tunnels are already
    # connected AF_UNIX descriptors, but a new AF_UNIX socket could connect
    # to a host service (Landlock does not mediate connect).
    socket_number = table.get("socket")
    if socket_number is not None:
        instructions.extend([
            _SockFilter(_BPF_JMP_JEQ_K, 0, 6, socket_number),
            _SockFilter(_BPF_LD_W_ABS, 0, 0, _SECCOMP_DATA_ARGS),
            _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_INET),
            _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
            _SockFilter(_BPF_JMP_JEQ_K, 0, 1, _AF_INET6),
            _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
            _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        ])
        numbers.discard(socket_number)

    for number in sorted(numbers):
        instructions.append(_SockFilter(_BPF_JMP_JEQ_K, 0, 1, number))
        instructions.append(_SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW))
    instructions.append(
        _SockFilter(_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS))

    array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), array)
    if libc.syscall(_syscall_number("seccomp"),
                    _SECCOMP_SET_MODE_FILTER,
                    _SECCOMP_FILTER_FLAG_TSYNC,
                    ctypes.byref(program)) != 0:
        raise OSError(ctypes.get_errno(),
                      "seccomp(SECCOMP_SET_MODE_FILTER, TSYNC) failed")


# ---------------------------------------------------------------------------
# Capabilities and resource limits
# ---------------------------------------------------------------------------


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32),
                ("inheritable", ctypes.c_uint32)]


def _drop_capabilities(libc) -> None:
    header = _CapHeader(0x20080522, 0)
    data = (_CapData * 2)()
    if libc.capset(ctypes.byref(header), ctypes.byref(data)) != 0:
        raise OSError(ctypes.get_errno(), "capset could not drop capabilities")
    for capability in range(64):
        libc.prctl(_PR_CAPBSET_DROP, capability, 0, 0, 0)


def _apply_secondary_limits() -> list[str]:
    """A core-dump ceiling; a loss is reported but not fatal."""
    failures: list[str] = []
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as exc:
        failures.append(f"RLIMIT_CORE not applied: {type(exc).__name__}")
    return failures


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def apply(role: str, cache_dir: str, home_dir: str = "",
          proxy_fds=()) -> tuple[list[str], str]:
    """Confine the calling process; return ``(failures, proxy_url)``.

    Any entry in *failures* is fatal for the worker: the caller refuses to
    serve rather than analyse with a protection the design claims and the
    kernel did not provide.  *proxy_url* is non-empty only for the ``fetch``
    role, and only when the loopback bridge started.
    """
    if not sys.platform.startswith("linux"):
        return [f"OS sandbox not applied: unsupported platform "
                f"{sys.platform}"], ""

    failures = _apply_secondary_limits()
    proxy_url = ""
    try:
        uid, gid = os.getuid(), os.getgid()
        _enter_user_namespace(uid, gid)
    except OSError as exc:
        return failures + [
            f"OS sandbox not applied: user namespace unavailable "
            f"({exc.strerror})"], ""
    try:
        _enter_network_namespace()
    except OSError as exc:
        return failures + [
            f"OS sandbox not applied: network namespace unavailable "
            f"({exc.strerror})"], ""

    libc = _libc()
    try:
        if role == "fetch":
            if not proxy_fds:
                raise OSError(errno.EINVAL, "no parent proxy descriptors")
            _loopback_up()
            proxy_url = _start_fetch_bridge(proxy_fds)
        _apply_landlock(
            libc, str(Path(cache_dir).resolve()), home_dir,
            cache_is_writable=role == "fetch",
        )
        _install_seccomp(libc, role)
        _drop_capabilities(libc)
    except OSError as exc:
        return failures + [
            f"OS sandbox not applied: {exc.strerror or exc}"], ""
    return failures, proxy_url
