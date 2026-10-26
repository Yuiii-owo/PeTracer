"""Unified event model shared by the Windows agent and the host-side parsers."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

BASE_FIELDS = {"ts", "pid", "tid", "type", "api", "caller", "origin"}


def normalize_path(path: str | None) -> str | None:
    if not path:
        return path
    p = path
    if p.startswith("\\\\?\\"):
        p = p[4:]
    elif p.startswith("\\??\\"):
        p = p[4:]
    elif p.startswith("\\\\??\\"):
        p = p[5:]
    if p.lower().startswith("unc\\"):
        p = "\\\\" + p[4:]
    if p.startswith("\\\\?\\UNC\\"):
        p = "\\\\" + p[8:]
    return p


def path_key(path: str | None) -> str:
    return (normalize_path(path) or "").lower().replace("/", "\\")


def basename(path: str | None) -> str:
    if not path:
        return ""
    p = normalize_path(path) or ""
    return p.rstrip("\\").rsplit("\\", 1)[-1]


@dataclass
class Event:
    ts: float
    source: str  # agent | wine | sandbox
    type: str
    api: str = ""
    pid: int | None = None
    tid: int | None = None
    caller: str = ""
    origin: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    raw: str = ""

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ts": round(self.ts, 3),
            "source": self.source,
            "type": self.type,
        }
        if self.pid is not None:
            out["pid"] = self.pid
        if self.tid is not None:
            out["tid"] = self.tid
        if self.api:
            out["api"] = self.api
        if self.caller:
            out["caller"] = self.caller
        if self.origin:
            out["origin"] = self.origin
        out.update(self.data)
        return out

    @classmethod
    def from_agent(cls, obj: dict[str, Any]) -> "Event":
        ts = obj.get("ts")
        try:
            ts = float(ts) / 1000.0
        except (TypeError, ValueError):
            ts = time.time()
        data = {k: v for k, v in obj.items() if k not in BASE_FIELDS}
        if "path" in data:
            data["path"] = normalize_path(data["path"])
        if "image" in data:
            data["image"] = normalize_path(data["image"])
        return cls(
            ts=ts,
            source="agent",
            type=str(obj.get("type") or "unknown"),
            api=str(obj.get("api") or ""),
            pid=obj.get("pid"),
            tid=obj.get("tid"),
            caller=str(obj.get("caller") or ""),
            origin=str(obj.get("origin") or ""),
            data=data,
        )

    @classmethod
    def sandbox(cls, type_: str, **data: Any) -> "Event":
        return cls(ts=time.time(), source="sandbox", type=type_, data=data)


def load_agent_events(path: str | Path) -> list[Event]:
    events: list[Event] = []
    p = Path(path)
    if not p.exists():
        return events
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "agent.debug":
                continue
            events.append(Event.from_agent(obj))
    return events


def write_events(path: str | Path, events: Iterable[Event]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")


def summarize(events: Iterable[Event]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for ev in events:
        counts[ev.type] = counts.get(ev.type, 0) + 1
    return dict(sorted(counts.items()))
