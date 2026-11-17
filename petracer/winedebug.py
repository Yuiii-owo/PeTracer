"""Parser for Wine's WINEDEBUG trace channels.

Enabled channels (default): +err,+loaddll,+process.  They provide zero-instrumentation
visibility into loader failures, module loads and child processes, which complements
the API hook layer inside the sample process.
"""
from __future__ import annotations

import re
import time

from .events import Event, normalize_path

RE_WINE_TS = re.compile(r"^(?P<ts>\d+\.\d+):")
RE_TID = re.compile(r"^(?:\d+\.\d+:)?([0-9a-fA-F]+):")
RE_LOADDLL = re.compile(
    r":trace:loaddll:[^\s]+ Loaded L\"(?P<path>.*?)\" at (?P<base>[0-9a-fA-F]+): (?P<kind>\w+)"
)
RE_NTCREATEPROCESS = re.compile(
    r":trace:process:NtCreateUserProcess L\"(?P<ntpath>.*?)\" image L\"(?P<image>.*?)\""
    r" cmdline L\"(?P<cmdline>.*?)\""
)
RE_NTCREATEPROCESS_ID = re.compile(
    r":trace:process:NtCreateUserProcess L\"(?P<ntpath>.*?)\" pid (?P<pid>[0-9a-fA-F]+)"
    r" tid (?P<child_tid>[0-9a-fA-F]+)"
)
RE_CREATEPROCESS = re.compile(
    r":trace:process:CreateProcessInternalW .*?cmdline L\"(?P<cmdline>.*?)\""
)
RE_NTCREATE_KEY = re.compile(r":trace:(?:reg|ntdll):.*?L\"(?P<path>\\\\Registry\\\\.*?)\"")
RE_FILE = re.compile(r":trace:file:(?P<fn>\w+) L\"(?P<path>.*?)\"")
RE_TID_PID = re.compile(r"pid ([0-9a-fA-F]+) tid ([0-9a-fA-F]+)")
RE_SYSCALL = re.compile(r":SysCall\s+(?P<name>\w+)\((?P<args>.*)\)\s*$")


def parse_line(line: str, ts: float | None = None) -> Event | None:
    if ":trace:" not in line and ":SysCall" not in line:
        return None
    if ts is None:
        m_ts = RE_WINE_TS.match(line)
        if m_ts:
            # Wine's +timestamp is seconds since boot (CLOCK_MONOTONIC).
            ts = float(m_ts.group("ts")) + (time.time() - time.monotonic())
    ts = ts if ts is not None else time.time()
    tid = None
    m = RE_TID.match(line)
    if m:
        try:
            tid = int(m.group(1), 16)
        except ValueError:
            tid = None

    m = RE_LOADDLL.search(line)
    if m:
        path = normalize_path(m.group("path").replace("\\\\", "\\"))
        try:
            base = int(m.group("base"), 16)
        except ValueError:
            base = 0
        return Event(
            ts=ts,
            source="wine",
            type="wine.loaddll",
            tid=tid,
            data={"path": path, "base": hex(base), "kind": m.group("kind")},
            raw=line,
        )

    m = RE_NTCREATEPROCESS.search(line)
    if m:
        data = {
            "image": normalize_path(m.group("image").replace("\\\\", "\\")),
            "cmdline": m.group("cmdline").replace("\\\\", "\\"),
        }
        pm = RE_TID_PID.search(line)
        if pm:
            try:
                data["pid"] = int(pm.group(1), 16)
                data["child_tid"] = int(pm.group(2), 16)
            except ValueError:
                pass
        return Event(ts=ts, source="wine", type="wine.process", tid=tid, data=data, raw=line)

    m = RE_NTCREATEPROCESS_ID.search(line)
    if m:
        data = {
            "ntpath": normalize_path(m.group("ntpath").replace("\\\\", "\\")),
            "pid": int(m.group("pid"), 16),
            "child_tid": int(m.group("child_tid"), 16),
        }
        return Event(
            ts=ts, source="wine", type="wine.process_id", tid=tid, data=data, raw=line
        )

    m = RE_CREATEPROCESS.search(line)
    if m:
        return Event(
            ts=ts,
            source="wine",
            type="wine.process",
            tid=tid,
            data={"cmdline": m.group("cmdline").replace("\\\\", "\\")},
            raw=line,
        )

    m = RE_SYSCALL.search(line)
    if m:
        return Event(
            ts=ts,
            source="wine",
            type="nt.syscall",
            api=m.group("name"),
            tid=tid,
            data={"args": m.group("args")[:400]},
            raw=line,
        )

    m = RE_NTCREATE_KEY.search(line)
    if m:
        return Event(
            ts=ts,
            source="wine",
            type="reg.open",
            tid=tid,
            data={"path": m.group("path").replace("\\\\", "\\")},
            raw=line,
        )

    m = RE_FILE.search(line)
    if m:
        return Event(
            ts=ts,
            source="wine",
            type="file." + m.group("fn").lower(),
            tid=tid,
            data={"path": normalize_path(m.group("path").replace("\\\\", "\\"))},
            raw=line,
        )
    return None


def parse_text(text: str, base_ts: float | None = None) -> list[Event]:
    out: list[Event] = []
    base = base_ts if base_ts is not None else time.time()
    for i, line in enumerate(text.splitlines()):
        ev = parse_line(line, ts=base + i * 1e-6)
        if ev:
            out.append(ev)
    return out
