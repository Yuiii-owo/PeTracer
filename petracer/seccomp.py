"""Tiny classic-BPF seccomp generator (no libseccomp dependency).

The filter allows everything except a denylist of syscalls that a Windows
malware sample has no legitimate reason to issue through Wine: namespace
manipulation, kernel module loading, tracing, BPF, mount, etc.  Denied calls
return EPERM so Wine can surface a normal error instead of crashing.
"""
from __future__ import annotations

import ctypes
import os
import struct
import tempfile

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_I386 = 0x40000003

BPF_LD_W_ABS = 0x20
BPF_JMP_JEQ_K = 0x15
BPF_RET_K = 0x06
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000

SECCOMP_SET_MODE_FILTER = 1

# x86_64 syscall numbers.  Kept deliberately conservative: anything Wine
# itself needs (clone, mmap, prctl, ptrace is NOT needed, etc.) must stay.
DENYLIST = {
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "chroot": 161,
    "ptrace": 101,
    "kexec_load": 246,
    "kexec_file_load": 320,
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
    "bpf": 321,
    "perf_event_open": 298,
    "userfaultfd": 323,
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    "open_by_handle_at": 304,
    "name_to_handle_at": 303,
    "unshare": 272,
    "setns": 308,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "acct": 163,
    "syslog": 103,
    "iopl": 172,
    "ioperm": 173,
    "quotactl": 179,
    "fanotify_init": 300,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
    "seccomp": 317,
}

ERRNO_EPERM = 1


def _stmt(code: int, k: int) -> bytes:
    return struct.pack("<HBBI", code, 0, 0, k)


def _jump(code: int, k: int, jt: int, jf: int) -> bytes:
    return struct.pack("<HBBI", code, jt, jf, k)


def build_filter(denylist: dict[str, int] | None = None) -> bytes:
    denylist = DENYLIST if denylist is None else denylist
    prog = bytearray()
    prog += _stmt(BPF_LD_W_ABS, 4)  # A = arch
    prog += _jump(BPF_JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0)
    prog += _stmt(BPF_RET_K, SECCOMP_RET_ALLOW)  # non-x86_64: allow (i386 Wine path)
    prog += _stmt(BPF_LD_W_ABS, 0)  # A = syscall nr
    for nr in sorted(set(denylist.values())):
        prog += _jump(BPF_JMP_JEQ_K, nr, 0, 1)
        prog += _stmt(BPF_RET_K, SECCOMP_RET_ERRNO | ERRNO_EPERM)
    prog += _stmt(BPF_RET_K, SECCOMP_RET_ALLOW)
    return bytes(prog)


def write_filter_file(path: str | None = None) -> str:
    path = path or tempfile.mktemp(prefix="petracer-seccomp-", suffix=".bpf")
    with open(path, "wb") as fh:
        fh.write(build_filter())
    return path


def install_current_process(denylist: dict[str, int] | None = None) -> None:
    """Install the filter on the calling process (used by tests only)."""
    libc = ctypes.CDLL(None, use_errno=True)
    prog = build_filter(denylist)
    buf = ctypes.create_string_buffer(prog, len(prog))

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]

    fprog = SockFprog(len(prog) // 8, ctypes.cast(buf, ctypes.c_void_p))
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    rc = libc.syscall(317, SECCOMP_SET_MODE_FILTER, 0, ctypes.byref(fprog))
    if rc != 0:
        raise OSError(ctypes.get_errno(), "seccomp install failed")


def open_filter_fd(denylist: dict[str, int] | None = None) -> int:
    """Return an fd holding the raw BPF program for `bwrap --seccomp`."""
    data = build_filter(denylist)
    if hasattr(os, "memfd_create"):
        fd = os.memfd_create("petracer-seccomp", flags=0)
    else:  # pragma: no cover
        tmp = tempfile.TemporaryFile()
        fd = os.dup(tmp.fileno())
    os.write(fd, data)
    os.lseek(fd, 0, os.SEEK_SET)
    return fd
