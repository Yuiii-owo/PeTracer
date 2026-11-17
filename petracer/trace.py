"""Live terminal tracer: print imported-function calls and NT syscalls in order.

`petracer <target.exe>` (or `petracer trace ...`) runs the sample through the
same sandbox as `run`, but enables IAT import tracing in the agent and streams
the agent JSONL to the terminal as it is produced.
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Any

from .detect.rules import analyze
from .report import build_report, write_report
from .sandbox import SandboxConfig, SandboxError, run_sample

CRT_MARKERS = ("ucrt", "msvcrt", "api-ms-win-crt", "libgcc", "libstdc++")

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
CYAN = "\033[36m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
RED = "\033[31m"

SYS_FIELDS = {
    "file.": ["path", "access", "disposition", "size"],
    "reg.": ["path", "name", "value_type", "size"],
    "mem.": ["target_pid", "base", "size", "protect"],
    "thread.": ["target_pid", "start", "class"],
    "process.": ["image", "target_pid", "exit_code"],
    "net.": ["address", "port", "host"],
    "sleep": ["ms"],
    "proc.query": ["class"],
    "sys.query": ["class", "length"],
    "thread.setinfo": ["class"],
    "driver.load": ["path"],
}


def _sys_detail(obj: dict[str, Any]) -> str:
    t = obj.get("type", "")
    keys = SYS_FIELDS.get(t)
    if keys is None:
        for prefix, candidate in SYS_FIELDS.items():
            if t.startswith(prefix):
                keys = candidate
                break
    if keys is None:
        keys = ["path", "size", "target_pid"]
    parts = []
    for key in keys:
        value = obj.get(key)
        if value in (None, ""):
            continue
        parts.append(f"{key}={value}")
    return " ".join(parts)


class TraceClock:
    """Shared relative-time origin for agent and Wine trace lines."""

    def __init__(self) -> None:
        self.t0: float | None = None
        self.lock = threading.Lock()

    def rel(self, ts: float) -> float:
        with self.lock:
            if self.t0 is None:
                self.t0 = ts
            return max(0.0, ts - self.t0)


class TracePrinter:
    def __init__(
        self,
        show_imports: bool = True,
        show_syscalls: bool = True,
        show_all: bool = False,
        no_crt: bool = False,
        show_agent_syscalls: bool = True,
        limit: int = 5000,
        color: bool = True,
        t0: float | None = None,
        clock: TraceClock | None = None,
    ) -> None:
        self.show_imports = show_imports
        self.show_syscalls = show_syscalls
        self.show_all = show_all
        self.no_crt = no_crt
        self.show_agent_syscalls = show_agent_syscalls
        self.limit = limit
        self.color = color
        self.t0: float | None = t0
        self.clock = clock
        self.lines = 0
        self.import_calls = 0
        self.syscalls = 0
        self.other = 0
        self.lock = threading.Lock()

    def _label(self, text: str, code: str) -> str:
        return f"{code}{text}{RESET}" if self.color else text

    def _rel(self, obj: dict[str, Any]) -> float:
        ts = float(obj.get("ts") or 0) / 1000.0
        if self.clock is not None:
            return self.clock.rel(ts)
        if self.t0 is None:
            self.t0 = ts
        return max(0.0, ts - self.t0)

    def __call__(self, obj: dict[str, Any]) -> None:
        with self.lock:
            if self.limit and self.lines >= self.limit:
                return
            type_ = str(obj.get("type") or "")
            api = str(obj.get("api") or "")
            is_import = type_ == "import.call"
            is_syscall = api.startswith(("Nt", "Zw")) and type_ != "import.call"
            is_net = api in ("connect", "WSAConnect", "getaddrinfo") and type_ != "import.call"

            if type_ == "agent.ready":
                rel = self._rel(obj)
                imported = obj.get("imports", 0)
                text = (
                    f"[{rel:7.3f}s] "
                    + self._label("AGENT  ", BOLD)
                    + f"ready hooks={obj.get('hooks', 0)} imports={imported} "
                    + f"image={obj.get('image', '?')}"
                )
                print(text)
                self.lines += 1
                return

            if is_import:
                if not self.show_imports:
                    return
                dll = str(obj.get("dll") or "").lower()
                if self.no_crt and any(marker in dll for marker in CRT_MARKERS):
                    return
            elif is_syscall:
                if not self.show_syscalls or not self.show_agent_syscalls:
                    return
            elif is_net:
                if not (self.show_syscalls or self.show_all):
                    return
            else:
                if not self.show_all:
                    return

            rel = self._rel(obj)
            if is_import:
                args = " ".join(
                    f"a{i}={obj.get(f'a{i}')}" for i in range(1, 5) if obj.get(f"a{i}") is not None
                )
                label = self._label("IMPORT ", CYAN)
                text = f"[{rel:7.3f}s] {label} {api:<28} {args}"
                self.import_calls += 1
            elif is_syscall:
                label = self._label("SYSCALL", YELLOW)
                text = f"[{rel:7.3f}s] {label} {api:<28} {_sys_detail(obj)}"
                self.syscalls += 1
            elif is_net:
                label = self._label("NET    ", GREEN)
                text = f"[{rel:7.3f}s] {label} {api:<28} {_sys_detail(obj)}"
                self.other += 1
            else:
                label = self._label("EVENT  ", DIM)
                text = f"[{rel:7.3f}s] {label} {type_:<28} {_sys_detail(obj)}"
                self.other += 1
            print(text)
            self.lines += 1
            if self.limit and self.lines == self.limit:
                print(f"{DIM}... trace limit {self.limit} reached (use --limit 0 for unlimited){RESET}"
                      if self.color else f"... trace limit {self.limit} reached (use --limit 0 for unlimited)")


def _wine_syscall_detail(api: str, args: str) -> str:
    parts = args.split(",")
    if api == "NtQuerySystemInformation" and len(parts) >= 3:
        try:
            return f"class=0x{int(parts[0], 16):x} length={int(parts[2], 16)}"
        except ValueError:
            pass
    if api == "NtQuerySystemInformationEx" and len(parts) >= 5:
        try:
            return f"class=0x{int(parts[0], 16):x} length={int(parts[4], 16)}"
        except ValueError:
            pass
    return f"args={args.strip()[:200]}"


class WineSyscallPrinter:
    """Print sample-process NT syscalls parsed from Wine's +syscall log."""

    def __init__(
        self,
        color: bool = True,
        limit: int = 0,
        t0: float | None = None,
        clock: TraceClock | None = None,
    ) -> None:
        self.color = color
        self.limit = limit
        self.t0: float | None = t0
        self.clock = clock
        self.calls = 0
        self.lines = 0
        self.lock = threading.Lock()

    def __call__(self, ev: Any) -> None:
        with self.lock:
            if self.limit and self.lines >= self.limit:
                return
            api = str(ev.api or "")
            args = str(ev.get("args") or "")
            ts = float(ev.ts or 0.0)
            if self.clock is not None:
                rel = self.clock.rel(ts)
            else:
                if self.t0 is None:
                    self.t0 = ts
                rel = max(0.0, ts - self.t0)
            label = f"{YELLOW}SYSCALL{RESET}" if self.color else "SYSCALL"
            print(f"[{rel:7.3f}s] {label} {api:<28} {_wine_syscall_detail(api, args)}")
            self.calls += 1
            self.lines += 1


def trace_sample(
    sample: Path,
    sample_args: list[str],
    out_dir: Path,
    timeout: float,
    printer: TracePrinter,
    keep_work: bool = False,
    runtime_dirs: list[Path] | None = None,
    wine_syscall: bool = False,
    wine_syscall_filter: bool = False,
    on_wine_syscall: object | None = None,
    no_agent: bool = False,
):
    cfg = SandboxConfig(
        sample=Path(sample),
        args=list(sample_args),
        out_dir=Path(out_dir),
        timeout=timeout,
        trace_imports=True,
        on_agent_event=printer,
        keep_work=keep_work,
        runtime_dirs=list(runtime_dirs or []),
        wine_syscall=wine_syscall or wine_syscall_filter,
        wine_syscall_filter=wine_syscall_filter,
        on_wine_syscall=on_wine_syscall,
        no_agent=no_agent,
        verbose=False,
    )
    result = run_sample(cfg)
    analysis = analyze(result.events, result.pe, result.meta)
    report = build_report(result.meta, result.pe.to_dict(), analysis, result.events, result.artifacts)
    write_report(result.out_dir, report)
    return result, analysis


def print_anomalies(result) -> None:
    for event in result.events:
        if event.type == "sandbox.crash":
            print(f"[crash] {event.get('message')}")
        if event.type == "sandbox.timeout":
            print(f"[timeout] sample exceeded {event.get('timeout')}s")
