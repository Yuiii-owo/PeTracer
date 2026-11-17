"""Sandbox lifecycle: Wine prefix management, bubblewrap isolation, collection."""
from __future__ import annotations

import fcntl
import glob
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import build, seccomp, winedebug
from .events import Event, basename, load_agent_events, write_events
from .pe import PEInfo, parse_pe

CACHE_DIR = Path(os.environ.get("PETRACER_CACHE", Path.home() / ".cache" / "petracer"))
DEFAULT_PREFIX = CACHE_DIR / "prefix"
DEFAULT_RUNTIME_DIR = CACHE_DIR / "runtime"

WINEDEBUG_DEFAULT = "err,loaddll,process"
WINEDEBUG_VERBOSE = "err,loaddll,process,file,reg"
WINEDEBUG_SYSCALL = "err,loaddll,process,syscall,timestamp"


class SandboxError(RuntimeError):
    pass


@dataclass
class SandboxConfig:
    sample: Path
    args: list[str] = field(default_factory=list)
    out_dir: Path = Path("petracer-out")
    timeout: float = 30.0
    wine_trace: bool = False
    wine_syscall: bool = False
    wine_syscall_filter: bool = False
    no_agent: bool = False
    no_bwrap: bool = False
    use_seccomp: bool = True
    keep_work: bool = False
    prefix: Path | None = None
    runtime_dirs: list[Path] = field(default_factory=list)
    verbose: bool = True
    trace_imports: bool = False
    on_agent_event: object | None = None
    on_wine_syscall: object | None = None


@dataclass
class RunResult:
    out_dir: Path
    exit_code: int | None
    timed_out: bool
    duration: float
    events: list[Event]
    pe: PEInfo
    meta: dict
    artifacts: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def agent_ready(self) -> bool:
        return any(e.type == "agent.ready" for e in self.events)


def wine_version() -> str:
    try:
        proc = subprocess.run(["wine", "--version"], capture_output=True, text=True, timeout=20)
        return proc.stdout.strip() or proc.stderr.strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def ensure_prefix(prefix: Path | None = None, force: bool = False, verbose: bool = True) -> Path:
    prefix = Path(prefix) if prefix else DEFAULT_PREFIX
    marker = prefix / "system.reg"
    if marker.exists() and (prefix / "drive_c").is_dir() and not force:
        return prefix

    prefix.parent.mkdir(parents=True, exist_ok=True)
    lock_path = prefix.parent / ".petracer-init.lock"
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if marker.exists() and (prefix / "drive_c").is_dir() and not force:
            return prefix
        if verbose:
            print(f"[petracer] creating Wine prefix at {prefix} (one-time, no ISO needed)")
        if prefix.exists():
            shutil.rmtree(prefix)
        env = os.environ.copy()
        env.update(
            WINEPREFIX=str(prefix),
            WINEDEBUG="-all",
            WINEDLLOVERRIDES="winemenubuilder.exe=d",
            WINEDEBUG_NO_COLOR="1",
        )
        env.pop("DISPLAY", None)
        try:
            # wineboot returns before the wineserver has finished installing
            # the prefix updates; wait for it and run a second (no-op) pass.
            proc = subprocess.run(
                ["wineboot", "-u"],
                env=env,
                capture_output=True,
                text=True,
                timeout=600,
            )
            subprocess.run(["wineserver", "-w"], env=env, capture_output=True, timeout=120)
            subprocess.run(
                ["wineboot", "-u"],
                env=env,
                capture_output=True,
                timeout=120,
            )
            subprocess.run(["wineserver", "-w"], env=env, capture_output=True, timeout=120)
        except FileNotFoundError as exc:
            raise SandboxError(
                "wineboot not found: install wine (e.g. pacman -S wine) before using PeTracer"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxError("wineboot timed out after 600s") from exc
        if not marker.exists():
            raise SandboxError(
                "Wine prefix initialization failed:\n"
                + (proc.stdout or "")[-2000:]
                + (proc.stderr or "")[-2000:]
            )
        (prefix / ".petracer-template").write_text(
            json.dumps({"wine": wine_version(), "created": int(time.time())}, indent=2)
        )
    return prefix


def _sha256(path: Path, limit: int = 256 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        remaining = limit
        while remaining > 0:
            chunk = fh.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def _pick_arch(pe: PEInfo) -> str:
    if pe.machine == 0x8664:
        return "x64"
    if pe.machine == 0x014C:
        return "x86"
    return "x64"


def _wine_path(path: Path) -> str:
    return "Z:" + str(path).replace("/", "\\")


def _dir_has_dlls(directory: Path) -> bool:
    try:
        return any(p.is_file() and p.suffix.lower() == ".dll" for p in directory.iterdir())
    except OSError:
        return False


def _wine_dll_roots() -> list[Path]:
    roots: list[Path] = []
    for entry in os.environ.get("WINEDLLPATH", "").split(os.pathsep):
        if entry:
            roots.append(Path(entry))
    wine = shutil.which("wine")
    if wine:
        install_root = Path(wine).resolve().parent.parent
        roots += [install_root / "lib" / "wine", install_root / "lib64" / "wine"]
    roots += [Path("/usr/lib/wine"), Path("/usr/lib64/wine")]
    for pattern in ("/usr/lib/*/wine", "/usr/lib/*/*/wine"):
        roots += [Path(p) for p in glob.glob(pattern)]
    return list(dict.fromkeys(roots))


def _known_dlls(prefix: Path, arch: str) -> set[str]:
    """DLL names already provided by Wine or the cached prefix."""
    sub = "x86_64-windows" if arch == "x64" else "i386-windows"
    names: set[str] = set()
    for root in _wine_dll_roots():
        directory = root / sub
        if directory.is_dir():
            names.update(
                p.name.lower()
                for p in directory.iterdir()
                if p.is_file() and p.suffix.lower() == ".dll"
            )
    subdirs = ("system32",) if arch == "x64" else ("syswow64",)
    for subdir in subdirs:
        directory = prefix / "drive_c" / "windows" / subdir
        if directory.is_dir():
            names.update(
                p.name.lower()
                for p in directory.iterdir()
                if p.is_file() and p.suffix.lower() == ".dll"
            )
    return names


def _runtime_dlls(
    imported: list[str], dirs: list[Path], known: set[str]
) -> tuple[dict[str, Path], list[Path]]:
    """Pick imported DLLs absent from Wine/prefix from the runtime directories."""
    wanted = {
        name.lower()
        for name in imported
        if name.lower().endswith(".dll") and name.lower() not in known
    }
    found: dict[str, Path] = {}
    missing_dirs: list[Path] = []
    for directory in dirs:
        if not directory.is_dir():
            missing_dirs.append(directory)
            continue
        for entry in sorted(directory.iterdir()):
            if not entry.is_file() or entry.suffix.lower() != ".dll":
                continue
            key = entry.name.lower()
            if key in wanted:
                found[key] = entry
    return found, missing_dirs


def _target_tids(events: list[Event], sample_name: str) -> set[int]:
    """Thread IDs that belong to the target process."""
    tids: set[int] = set()
    loaded: set[int] = set()
    wanted = sample_name.lower()
    for e in events:
        if e.source == "agent" and e.tid:
            tids.add(int(e.tid))
        elif e.type in ("wine.process", "wine.process_id"):
            image = e.get("image") or e.get("ntpath") or e.get("cmdline") or ""
            if basename(image).lower() == wanted:
                child = e.get("child_tid")
                if child:
                    tids.add(int(child))
        elif e.type == "wine.loaddll" and e.tid:
            if basename(e.get("path")).lower() == wanted:
                loaded.add(int(e.tid))
    return tids or loaded


def _filter_syscall_log(
    path: Path, tids: set[int]
) -> tuple[dict[str, int], Path, int]:
    counts: dict[str, int] = {}
    out_path = path.with_name("syscalls.sample.log")
    matched = 0
    with path.open("r", encoding="utf-8", errors="replace") as src, out_path.open(
        "w", encoding="utf-8"
    ) as dst:
        for line in src:
            m = re.match(r"^(?:\d+\.\d+:)?([0-9a-fA-F]+):(SysCall|SysRet)\b", line)
            if not m or int(m.group(1), 16) not in tids:
                continue
            dst.write(line)
            matched += 1
            if m.group(2) == "SysCall":
                ev = winedebug.parse_line(line.rstrip("\n"))
                if ev is not None and ev.type == "nt.syscall":
                    counts[ev.api] = counts.get(ev.api, 0) + 1
    return counts, out_path, matched


def _write_wrapper(
    path: Path,
    wine_cmd: str,
    agent: bool,
    runtime: bool = False,
) -> None:
    runtime_block = ""
    if runtime:
        runtime_block = (
            'if [ -d /tmp/runtime ]; then\n'
            '  mkdir -p "$PREFIX/drive_c/windows/system32"\n'
            '  cp -f /tmp/runtime/*.dll "$PREFIX/drive_c/windows/system32/"\n'
            'fi\n'
        )
    script = f"""#!/bin/sh
ulimit -c 0 2>/dev/null
ulimit -f 524288 2>/dev/null
OUT="${{PETRACER_OUT:-/tmp/petracer-out}}"
PREFIX="${{PETRACER_PREFIX:-/tmp/prefix}}"
cd "${{PETRACER_SAMPLE:-/tmp/sample}}" || exit 111
{runtime_block}stamp=/tmp/.petracer.stamp
: > "$stamp"
{wine_cmd}
rc=$?
if [ -d "$PREFIX/drive_c" ]; then
  mkdir -p "$OUT/artifacts"
  budget=/tmp/.petracer-budget
  echo 0 > "$budget"
  find "$PREFIX/drive_c" -newer "$stamp" -type f 2>/dev/null | head -n 500 | while IFS= read -r f; do
    sz=$(stat -c %s "$f" 2>/dev/null || echo 0)
    [ "$sz" -gt 67108864 ] && continue
    total=$(cat "$budget" 2>/dev/null || echo 0)
    [ $((total + sz)) -gt 268435456 ] && continue
    echo $((total + sz)) > "$budget"
    rel="${{f#$PREFIX/drive_c/}}"
    dest="$OUT/artifacts/$rel"
    mkdir -p "$(dirname "$dest")" 2>/dev/null || continue
    cp -p "$f" "$dest" 2>/dev/null
  done
fi
exit $rc
"""
    path.write_text(script)
    path.chmod(0o755)


def _build_bwrap_cmd(
    cfg: SandboxConfig,
    prefix: Path,
    sample_dir: Path,
    script_dir: Path,
    ready_name: str,
    seccomp_fd: int | None,
    runtime_stage: Path | None = None,
) -> list[str]:
    cmd = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--ro-bind",
        "/",
        "/",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--tmpfs",
        "/run",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/dev/shm",
        "--dir",
        "/tmp/prefix",
        "--overlay-src",
        str(prefix),
        "--tmp-overlay",
        "/tmp/prefix",
        "--bind",
        str(cfg.out_dir),
        "/tmp/petracer-out",
        "--bind",
        str(sample_dir),
        "/tmp/sample",
        "--bind",
        str(script_dir),
        "/tmp/pscript",
    ]
    if runtime_stage is not None:
        cmd += ["--ro-bind", str(runtime_stage), "/tmp/runtime"]
    cmd += [
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "WINEPREFIX",
        "/tmp/prefix",
        "--setenv",
        "WINEDEBUG",
        WINEDEBUG_SYSCALL
        if cfg.wine_syscall
        else (WINEDEBUG_VERBOSE if cfg.wine_trace else WINEDEBUG_DEFAULT),
        "--setenv",
        "WINEDLLOVERRIDES",
        "winemenubuilder.exe=d",
        "--setenv",
        "PETRACER_EVENT_LOG",
        "Z:\\tmp\\petracer-out\\agent.jsonl",
        "--setenv",
        "PETRACER_READY_EVENT",
        ready_name,
        "--setenv",
        "PETRACER_OUT",
        "/tmp/petracer-out",
        "--setenv",
        "PETRACER_PREFIX",
        "/tmp/prefix",
        "--setenv",
        "PETRACER_SAMPLE",
        "/tmp/sample",
    ]
    if cfg.trace_imports:
        cmd += ["--setenv", "PETRACER_TRACE_IMPORTS", "1"]
    if seccomp_fd is not None:
        cmd += ["--seccomp", str(seccomp_fd)]
    cmd += ["/bin/sh", "/tmp/pscript/wrap.sh"]
    return cmd


def _collect_artifacts(out_dir: Path) -> list[dict]:
    root = out_dir / "artifacts"
    items: list[dict] = []
    if not root.is_dir():
        return items
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            st = p.stat()
        except OSError:
            continue
        rel = str(p.relative_to(root))
        entry = {"path": rel, "size": st.st_size}
        if st.st_size <= 64 * 1024 * 1024:
            entry["sha256"] = _sha256(p)
        items.append(entry)
        if len(items) >= 2000:
            break
    return items


def _tail_jsonl(path: Path, callback, stop: threading.Event) -> None:
    """Tail a growing JSONL file and invoke `callback(obj)` for complete lines."""
    fh = None
    buf = b""
    while True:
        if fh is None:
            try:
                fh = path.open("rb")
            except FileNotFoundError:
                fh = None
        chunk = b""
        if fh is not None:
            chunk = fh.read()
            if chunk:
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        callback(json.loads(line.decode("utf-8", "replace")))
                    except Exception:  # noqa: BLE001 - tracing must never break a run
                        continue
        if stop.is_set():
            time.sleep(0.05)
            if fh is not None:
                chunk = fh.read()
                if chunk:
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            callback(json.loads(line.decode("utf-8", "replace")))
                        except Exception:  # noqa: BLE001
                            continue
                continue
            break
        time.sleep(0.02)


def run_sample(cfg: SandboxConfig) -> RunResult:
    cfg.sample = Path(cfg.sample).resolve()
    cfg.out_dir = Path(cfg.out_dir).resolve()
    if not cfg.sample.is_file():
        raise SandboxError(f"sample not found: {cfg.sample}")
    if shutil.which("wine") is None:
        raise SandboxError("wine not found in PATH")

    warnings: list[str] = []
    pe = parse_pe(cfg.sample)
    if (pe.syscall_count or pe.sysenter_count or pe.int2e_count) and not cfg.wine_syscall:
        warnings.append(
            "static direct-syscall opcodes found; ntdll hooks may miss them "
            "(use --wine-syscall for syscall-level coverage)"
        )
    arch = _pick_arch(pe)
    try:
        binaries = build.ensure_binaries(verbose=cfg.verbose)
    except build.BuildError as exc:
        if cfg.no_agent:
            binaries = {}
            warnings.append(f"agent build failed: {exc}")
        else:
            raise SandboxError(f"cannot build the PeTracer agent: {exc}") from exc
    if arch not in binaries:
        if cfg.no_agent:
            binaries = {}
        else:
            raise SandboxError(
                "32-bit sample requested but the i686 mingw compiler is not installed"
            )
    use_agent = bool(binaries) and not cfg.no_agent

    prefix = ensure_prefix(cfg.prefix, verbose=cfg.verbose)

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    (cfg.out_dir / "artifacts").mkdir(exist_ok=True)
    for stale in (
        "agent.jsonl",
        "events.jsonl",
        "stdout.log",
        "stderr.log",
        "syscalls.sample.log",
    ):
        with (cfg.out_dir / stale).open("w") as fh:
            fh.write("")

    live_tids: set[int] = set()
    tail_stop = threading.Event()
    tail_thread = None
    if cfg.on_agent_event is not None or cfg.on_wine_syscall is not None:
        def emit_agent(obj):
            tid = obj.get("tid")
            if tid:
                live_tids.add(int(tid))
            if cfg.on_agent_event is not None:
                cfg.on_agent_event(obj)

        tail_thread = threading.Thread(
            target=_tail_jsonl,
            args=(cfg.out_dir / "agent.jsonl", emit_agent, tail_stop),
            daemon=True,
        )
        tail_thread.start()

    work = Path(tempfile.mkdtemp(prefix="petracer-run-", dir=os.environ.get("PETRACER_RUN_ROOT", "/tmp")))
    sample_dir = work / "sample"
    script_dir = work / "scripts"
    sample_dir.mkdir()
    script_dir.mkdir()

    # keep the original name when it is safe: some samples inspect their own
    # filename, and self-delete rules compare against it.
    safe = "".join(c if (c.isalnum() or c in "._-") else "_" for c in cfg.sample.name)
    if not safe.lower().endswith(".exe"):
        safe = (safe or "sample") + ".exe"
    sample_name = safe
    shutil.copy2(cfg.sample, sample_dir / sample_name)

    runtime_dirs = [Path(p) for p in cfg.runtime_dirs]
    if not runtime_dirs and _dir_has_dlls(DEFAULT_RUNTIME_DIR):
        runtime_dirs = [DEFAULT_RUNTIME_DIR]
    runtime_dlls: dict[str, Path] = {}
    runtime_stage: Path | None = None
    if runtime_dirs:
        runtime_dlls, missing_runtime_dirs = _runtime_dlls(
            pe.imported_dlls, runtime_dirs, _known_dlls(prefix, arch)
        )
        for directory in missing_runtime_dirs:
            warnings.append(f"runtime DLL directory not found: {directory}")
        if not runtime_dlls and not missing_runtime_dirs and cfg.runtime_dirs:
            warnings.append(
                "no missing imported DLLs were found in the runtime directory/directories"
            )
        if runtime_dlls and cfg.no_bwrap:
            # no overlay to write into: fall back to app-local deployment
            for dll in runtime_dlls.values():
                shutil.copy2(dll, sample_dir / dll.name)
            warnings.append(
                "runtime DLLs are copied next to the sample because --no-bwrap is active"
            )
        elif runtime_dlls:
            runtime_stage = work / "runtime"
            runtime_stage.mkdir()
            for dll in runtime_dlls.values():
                shutil.copy2(dll, runtime_stage / dll.name)

    if cfg.no_bwrap:
        wine_sample = _wine_path(sample_dir / sample_name)
    else:
        wine_sample = "Z:\\tmp\\sample\\" + sample_name
    wine_agent = ""
    wine_launcher = ""
    if use_agent:
        agent_path = sample_dir / "petracer_agent.dll"
        launcher_path = sample_dir / "petracer_launch.exe"
        shutil.copy2(binaries[arch]["agent"], agent_path)
        shutil.copy2(binaries[arch]["launcher"], launcher_path)
        if cfg.no_bwrap:
            wine_agent = _wine_path(agent_path)
            wine_launcher = str(launcher_path)
        else:
            wine_agent = "Z:\\tmp\\sample\\petracer_agent.dll"
            wine_launcher = "/tmp/sample/petracer_launch.exe"

    ready_name = f"petracer-ready-{uuid.uuid4().hex}"
    args = " ".join(shlex.quote(a) for a in cfg.args)
    if use_agent:
        wine_cmd = (
            f"/usr/bin/wine {wine_launcher} {shlex.quote(wine_agent)} "
            f"{shlex.quote(wine_sample)} {args}".rstrip()
        )
    else:
        wine_cmd = f"/usr/bin/wine {shlex.quote(wine_sample)} {args}".rstrip()
    _write_wrapper(
        script_dir / "wrap.sh", wine_cmd, use_agent, runtime=runtime_stage is not None
    )

    seccomp_fd = None
    if cfg.use_seccomp and not cfg.no_bwrap:
        seccomp_fd = seccomp.open_filter_fd()

    meta: dict = {
        "sample": str(cfg.sample),
        "sample_name": cfg.sample.name,
        "sha256": pe.sha256,
        "size": pe.size,
        "arch": arch,
        "machine": hex(pe.machine),
        "args": cfg.args,
        "timeout": cfg.timeout,
        "agent": use_agent,
        "seccomp": bool(seccomp_fd is not None),
        "trace_imports": cfg.trace_imports,
        "runtime_dirs": [str(p) for p in runtime_dirs],
        "runtime_dlls": sorted(runtime_dlls),
        "bwrap": not cfg.no_bwrap,
        "wine": wine_version(),
        "kernel": platform.release(),
        "started": time.time(),
        "warnings": warnings,
    }

    stdout_path = cfg.out_dir / "stdout.log"
    stderr_path = cfg.out_dir / "stderr.log"
    wine_events: list[Event] = []
    crash_events: list[Event] = []
    loader_errors: list[str] = []
    nt_counts: dict[str, int] = {}
    nt_sampled: dict[str, int] = {}
    nt_interesting = {
        "NtCreateFile", "NtOpenFile", "NtWriteFile", "NtDeleteFile", "NtSetInformationFile",
        "NtCreateKey", "NtOpenKey", "NtOpenKeyEx", "NtSetValueKey", "NtDeleteKey",
        "NtDeleteValueKey", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
        "NtWriteVirtualMemory", "NtMapViewOfSection", "NtCreateThread", "NtCreateThreadEx",
        "NtCreateUserProcess", "NtLoadDriver", "NtDelayExecution", "NtQueryInformationProcess",
    }

    def pump(stream, path: Path, parse: bool) -> None:
        with path.open("wb") as fh:
            for raw in iter(stream.readline, b""):
                fh.write(raw)
                fh.flush()
                if parse:
                    raw_text = raw.decode("utf-8", "replace").rstrip("\n")
                    try:
                        ev = winedebug.parse_line(raw_text)
                    except Exception:  # noqa: BLE001
                        ev = None
                    if "err:module:import_dll" in raw_text or "err:module:loader_init" in raw_text:
                        loader_errors.append(raw_text)
                    if "Unhandled page fault" in raw_text or "Unhandled exception" in raw_text:
                        if "starting debugger" in raw_text or "page fault" in raw_text:
                            crash_events.append(
                                Event.sandbox("sandbox.crash", message=raw_text[:300])
                            )
                    if ev:
                        if ev.type == "wine.process_id":
                            ntpath = ev.get("ntpath") or ""
                            if basename(ntpath).lower() == sample_name.lower():
                                child = ev.get("child_tid")
                                if child:
                                    live_tids.add(int(child))
                        elif ev.type == "wine.loaddll" and not use_agent:
                            path = ev.get("path") or ""
                            if basename(path).lower() == sample_name.lower() and ev.tid:
                                live_tids.add(int(ev.tid))
                        if ev.type == "nt.syscall":
                            if cfg.on_wine_syscall is not None and ev.tid in live_tids:
                                cfg.on_wine_syscall(ev)
                            nt_counts[ev.api] = nt_counts.get(ev.api, 0) + 1
                            if ev.api not in nt_interesting:
                                continue
                            if nt_sampled.get(ev.api, 0) >= 200:
                                continue
                            nt_sampled[ev.api] = nt_sampled.get(ev.api, 0) + 1
                        wine_events.append(ev)
        stream.close()

    if cfg.no_bwrap:
        env = os.environ.copy()
        env.update(
            WINEPREFIX=str(prefix),
            WINEDEBUG=WINEDEBUG_SYSCALL
            if cfg.wine_syscall
            else (WINEDEBUG_VERBOSE if cfg.wine_trace else WINEDEBUG_DEFAULT),
            WINEDLLOVERRIDES="winemenubuilder.exe=d",
            PETRACER_EVENT_LOG="Z:" + str(cfg.out_dir).replace("/", "\\") + "\\agent.jsonl",
            PETRACER_READY_EVENT=ready_name,
            PETRACER_OUT=str(cfg.out_dir),
            PETRACER_PREFIX=str(prefix),
            PETRACER_SAMPLE=str(sample_dir),
            PETRACER_TRACE_IMPORTS="1" if cfg.trace_imports else "0",
            HOME=str(work),
        )
        cmd = ["/bin/sh", str(script_dir / "wrap.sh")]
        warnings.append("running without bubblewrap: filesystem/network isolation disabled")
    else:
        env = os.environ.copy()
        cmd = _build_bwrap_cmd(
            cfg, prefix, sample_dir, script_dir, ready_name, seccomp_fd, runtime_stage
        )
        # bind the out dir inside the sandbox: paths inside are /tmp/...
        # rewrite PETRACER_EVENT_LOG to the sandbox path (host path differs)
        env.pop("PETRACER_EVENT_LOG", None)

    started = time.time()
    proc = subprocess.Popen(
        cmd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        pass_fds=(seccomp_fd,) if seccomp_fd is not None else (),
    )
    if seccomp_fd is not None:
        os.close(seccomp_fd)

    t_out = threading.Thread(target=pump, args=(proc.stdout, stdout_path, False), daemon=True)
    t_err = threading.Thread(target=pump, args=(proc.stderr, stderr_path, True), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        exit_code = proc.wait(timeout=cfg.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            exit_code = None
    duration = time.time() - started
    t_out.join(timeout=5)
    t_err.join(timeout=5)
    tail_stop.set()
    if tail_thread is not None:
        tail_thread.join(timeout=5)

    agent_events = load_agent_events(cfg.out_dir / "agent.jsonl")
    sandbox_events = [
        Event.sandbox(
            "sandbox.start",
            bwrap=not cfg.no_bwrap,
            agent=use_agent,
            sample_sha256=pe.sha256,
        )
    ]
    if timed_out:
        sandbox_events.append(Event.sandbox("sandbox.timeout", timeout=cfg.timeout))
    sandbox_events.append(
        Event.sandbox("sandbox.exit", code=exit_code, duration=round(duration, 3))
    )

    nt_counts_all = dict(nt_counts)
    if cfg.wine_syscall_filter:
        if cfg.wine_syscall:
            sample_tids = _target_tids(agent_events + wine_events, sample_name)
            if sample_tids:
                sample_counts, sample_log, matched = _filter_syscall_log(
                    stderr_path, sample_tids
                )
                wine_events = [
                    e
                    for e in wine_events
                    if e.type != "nt.syscall" or e.tid in sample_tids
                ]
                nt_counts = sample_counts
                meta["syscall_filter"] = True
                meta["sample_tids"] = sorted(sample_tids)
                meta["nt_syscall_counts_all"] = nt_counts_all
                meta["syscall_sample_log"] = str(sample_log)
                if matched == 0:
                    warnings.append(
                        "syscall filter matched no sample syscalls; see stderr.log"
                    )
            else:
                warnings.append(
                    "could not determine target-process thread IDs; "
                    "--wine-syscall-filter disabled"
                )
        else:
            warnings.append("--wine-syscall-filter ignored without --wine-syscall")

    events = sorted(
        agent_events + wine_events + sandbox_events + crash_events, key=lambda e: e.ts
    )
    if loader_errors:
        missing = sorted({
            m.group(1)
            for line in loader_errors
            for m in [re.search(r"Library (\S+?)(?:\s|$)", line)]
            if m
        })
        if missing:
            warnings.append(
                "Wine could not load the sample's DLL dependencies: "
                + ", ".join(missing)
                + " (Debug build or missing redistributable DLLs?)"
            )
        else:
            warnings.append(
                "Wine failed to initialise the sample's DLL imports; see stderr.log"
            )
    if use_agent and not any(e.type == "agent.ready" for e in events):
        warnings.append(
            "agent did not report ready; API-level events may be missing (WINEDEBUG layer only)"
        )

    write_events(cfg.out_dir / "events.jsonl", events)
    artifacts = _collect_artifacts(cfg.out_dir)

    meta.update(
        {
            "exit_code": exit_code,
            "timed_out": timed_out,
            "duration": round(duration, 3),
            "finished": time.time(),
            "agent_ready": any(e.type == "agent.ready" for e in events),
            "nt_syscall_counts": nt_counts,
            "artifacts": artifacts,
        }
    )
    (cfg.out_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    (cfg.out_dir / "sample.info.json").write_text(json.dumps(pe.to_dict(), indent=2))

    if not cfg.keep_work:
        shutil.rmtree(work, ignore_errors=True)

    return RunResult(
        out_dir=cfg.out_dir,
        exit_code=exit_code,
        timed_out=timed_out,
        duration=duration,
        events=events,
        pe=pe,
        meta=meta,
        artifacts=artifacts,
        warnings=warnings,
    )
