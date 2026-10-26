"""JSON + Markdown report generation."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .detect.rules import Analysis
from .events import Event, basename

INFRA_PROCESSES = {
    "wineboot.exe",
    "winemenubuilder.exe",
    "services.exe",
    "winedevice.exe",
    "plugplay.exe",
    "svchost.exe",
    "rpcss.exe",
    "explorer.exe",
    "conhost.exe",
    "start.exe",
    "tabtip.exe",
    "winedbg.exe",
    "winedbg",
}


def _is_infra(ev: Event) -> bool:
    raw = (ev.get("image") or ev.get("cmdline") or "").strip()
    if raw.startswith('"'):
        raw = raw[1:].split('"', 1)[0]
    else:
        raw = raw.split(" ", 1)[0]
    return basename(raw).lower() in INFRA_PROCESSES


TIMELINE_TYPES = {
    "file.create",
    "file.delete",
    "file.rename",
    "reg.create",
    "reg.setvalue",
    "reg.delete",
    "process.create",
    "process.open",
    "thread.create",
    "thread.apc",
    "mem.write",
    "mem.protect",
    "mem.alloc",
    "net.connect",
    "net.dns",
    "driver.load",
    "sleep",
    "wine.process",
}


def _short(value: Any, limit: int = 90) -> str:
    text = str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _event_line(ev: Event) -> str:
    bits = [ev.type]
    for key in ("path", "new_path", "image", "cmdline", "name", "address", "host", "target_pid", "size", "protect", "ms"):
        value = ev.get(key)
        if value not in (None, ""):
            bits.append(f"{key}={_short(value, 70)}")
    return " ".join(bits)


def build_report(
    meta: dict,
    pe_info: dict,
    analysis: Analysis,
    events: list[Event],
    artifacts: list[dict],
) -> dict:
    timeline = [
        {
            "ts": round(ev.ts, 3),
            "type": ev.type,
            "origin": ev.origin,
            "detail": _event_line(ev),
        }
        for ev in events
        if ev.type in TIMELINE_TYPES
        and (ev.origin in ("", "sample") or ev.type.startswith("wine."))
        and not _is_infra(ev)
    ][:120]
    return {
        "verdict": analysis.verdict,
        "score": analysis.score,
        "sample": {
            "name": meta.get("sample_name"),
            "path": meta.get("sample"),
            "sha256": meta.get("sha256"),
            "size": meta.get("size"),
            "arch": meta.get("arch"),
            "pe": pe_info,
        },
        "execution": {
            "exit_code": meta.get("exit_code"),
            "timed_out": meta.get("timed_out"),
            "duration": meta.get("duration"),
            "agent": meta.get("agent"),
            "agent_ready": meta.get("agent_ready"),
            "bwrap": meta.get("bwrap"),
            "seccomp": meta.get("seccomp"),
            "wine": meta.get("wine"),
            "kernel": meta.get("kernel"),
        },
        "findings": [f.to_dict() for f in analysis.findings],
        "stats": analysis.stats,
        "timeline": timeline,
        "artifacts": artifacts,
        "warnings": meta.get("warnings", []),
    }


def render_markdown(report: dict) -> str:
    verdict = report["verdict"]
    emoji = {"malicious": "🔴", "suspicious": "🟠", "clean": "🟢"}.get(verdict, "⚪")
    sample = report["sample"]
    execution = report["execution"]
    lines: list[str] = []
    lines.append(f"# PeTracer report: {sample.get('name')}")
    lines.append("")
    lines.append(f"## {emoji} Verdict: **{verdict.upper()}** (score {report['score']}/100)")
    lines.append("")
    lines.append("| field | value |")
    lines.append("| --- | --- |")
    lines.append(f"| SHA256 | `{sample.get('sha256')}` |")
    lines.append(f"| Size | {sample.get('size')} bytes |")
    lines.append(f"| Architecture | {sample.get('arch')} |")
    lines.append(f"| Exit code | {execution.get('exit_code')} |")
    lines.append(f"| Timed out | {execution.get('timed_out')} |")
    lines.append(f"| Duration | {execution.get('duration')} s |")
    lines.append(f"| Agent | {execution.get('agent')} (ready={execution.get('agent_ready')}) |")
    lines.append(f"| bwrap / seccomp | {execution.get('bwrap')} / {execution.get('seccomp')} |")
    lines.append(f"| Wine / kernel | {execution.get('wine')} / {execution.get('kernel')} |")
    lines.append("")

    findings = report.get("findings", [])
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No detection rule matched.")
    else:
        lines.append("| severity | rule | ATT&CK | weight | detail |")
        lines.append("| --- | --- | --- | --- | --- |")
        for f in findings:
            lines.append(
                f"| {f['severity']} | {f['title']} (`{f['rule_id']}`) | {f['technique']} "
                f"| {f['weight']} | {_short(f.get('detail'), 80)} |"
            )
        lines.append("")
        for f in findings:
            lines.append(f"**{f['title']}** — {f['description']}")
            lines.append("")
    lines.append("## Key timeline")
    lines.append("")
    if report["timeline"]:
        lines.append("```text")
        for item in report["timeline"]:
            lines.append(item["detail"])
        lines.append("```")
    else:
        lines.append("No behaviour events were recorded.")
    lines.append("")

    stats = report.get("stats", {})
    lines.append("## Behaviour summary")
    lines.append("")
    counts = stats.get("event_counts", {})
    if counts:
        lines.append("| event | count |")
        lines.append("| --- | --- |")
        for key, value in counts.items():
            lines.append(f"| {key} | {value} |")
    lines.append("")
    nt = stats.get("nt_syscalls") or {}
    if nt:
        lines.append("### NT syscalls (WINEDEBUG +syscall)")
        lines.append("")
        lines.append("| syscall | count |")
        lines.append("| --- | --- |")
        for name, count in list(nt.items())[:30]:
            lines.append(f"| {name} | {count} |")
        lines.append("")
    for label, key in (("Files", "files"), ("Registry", "registry_keys"), ("Network", "network"), ("Processes", "processes")):
        values = stats.get(key, [])
        lines.append(f"### {label}")
        lines.append("")
        if values:
            for value in values[:40]:
                lines.append(f"- `{_short(value, 140)}`")
        else:
            lines.append("_none_")
        lines.append("")

    artifacts = report.get("artifacts", [])
    lines.append("## Artifacts")
    lines.append("")
    if artifacts:
        lines.append("| path | size | sha256 |")
        lines.append("| --- | --- | --- |")
        for a in artifacts[:100]:
            lines.append(f"| `{a['path']}` | {a['size']} | `{(a.get('sha256') or '')[:16]}` |")
    else:
        lines.append("No files were dropped outside the disposable prefix overlay.")
    lines.append("")

    if report.get("warnings"):
        lines.append("## Warnings")
        lines.append("")
        for w in report["warnings"]:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("- Windows API events come from an INT3/VEH hook agent injected into the sample process;")
    lines.append("  file/registry paths are resolved from NT object attributes and handle correlation.")
    lines.append("- Wine's own startup noise is filtered by the `origin` field where possible; `system`")
    lines.append("  events are kept for context.")
    lines.append("- Direct syscalls are detected statically (inline `syscall`/`sysenter` bytes); a sample")
    lines.append("  that resolves ntdll dynamically can still issue them at runtime.")
    lines.append("- Network is unshared by default, so connections are recorded but cannot leave the host.")
    return "\n".join(lines) + "\n"


def write_report(out_dir: Path, report: dict) -> tuple[Path, Path]:
    json_path = out_dir / "report.json"
    md_path = out_dir / "report.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False))
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


def load_report_inputs(out_dir: Path) -> tuple[dict, dict, list[Event], list[dict]]:
    meta = json.loads((out_dir / "meta.json").read_text())
    pe_info = {}
    if (out_dir / "sample.info.json").exists():
        pe_info = json.loads((out_dir / "sample.info.json").read_text())
    events: list[Event] = []
    if (out_dir / "events.jsonl").exists():
        for line in (out_dir / "events.jsonl").read_text().splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            ev = Event(
                ts=obj.get("ts", 0),
                source=obj.get("source", ""),
                type=obj.get("type", ""),
                api=obj.get("api", ""),
                pid=obj.get("pid"),
                tid=obj.get("tid"),
                caller=obj.get("caller", ""),
                origin=obj.get("origin", ""),
                data={
                    k: v
                    for k, v in obj.items()
                    if k not in ("ts", "source", "type", "api", "pid", "tid", "caller", "origin")
                },
            )
            events.append(ev)
    artifacts = meta.get("artifacts", [])
    return meta, pe_info, events, artifacts
