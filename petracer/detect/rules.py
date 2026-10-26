"""Behaviour rules and scoring.

Each rule produces evidence-backed findings.  Rules are deliberately explicit
(no YARA, no external deps) so the detection logic stays auditable.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from ..events import Event, basename, path_key
from ..pe import PEInfo

EXEC_EXT = {".exe", ".dll", ".scr", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".lnk"}
USER_WRITABLE = (
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\$recycle.bin\\",
)
RANSOM_EXT = {".locked", ".encrypted", ".crypt", ".enc", ".ransom", ".wncry", ".lockbit"}
INFRA_PROC = {
    "wineboot", "winemenubuilder", "services", "winedevice", "plugplay",
    "svchost", "rpcss", "explorer", "winedbg", "conhost", "start",
}


def _proc_name(value: str | None) -> str:
    if not value:
        return ""
    first = value.strip().split(" ")[0].strip('"')
    name = first.rsplit("\\", 1)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    weight: int
    description: str
    technique: str
    evidence: list[int] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "weight": self.weight,
            "description": self.description,
            "technique": self.technique,
            "evidence": self.evidence,
            "detail": self.detail,
        }


@dataclass
class Analysis:
    findings: list[Finding]
    score: int
    verdict: str
    stats: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "findings": [f.to_dict() for f in self.findings],
            "stats": self.stats,
        }


def _hexint(value: Any) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.lower().startswith("0x") else int(value)
        except ValueError:
            return 0
    return 0


def _evidence(events: list[Event], pred: Callable[[Event], bool], limit: int = 20) -> list[int]:
    out = []
    for i, ev in enumerate(events):
        if pred(ev):
            out.append(i)
            if len(out) >= limit:
                break
    return out


def _is_remote(ev: Event) -> bool:
    pid = ev.get("pid") if ev.get("pid") is not None else ev.pid
    target = ev.get("target_pid")
    if not target:
        return False
    try:
        return int(target) not in (0, int(pid or 0))
    except (TypeError, ValueError):
        return False


def _in_user_writable(path: str) -> bool:
    p = path_key(path)
    return any(marker in p for marker in USER_WRITABLE) or p.startswith("c:\\") and p.count("\\") == 2


def analyze(events: list[Event], pe: PEInfo, meta: dict | None = None) -> Analysis:
    meta = meta or {}
    findings: list[Finding] = []
    analyzed = [e for e in events if e.type not in ("agent.ready", "sandbox.exit", "sandbox.start")]

    # --- process injection -------------------------------------------------
    injection_ev = [
        e
        for e in analyzed
        if e.type in ("mem.write", "thread.create", "mem.protect", "mem.alloc", "thread.apc")
        and _is_remote(e)
    ]
    if injection_ev:
        kinds = {e.type for e in injection_ev}
        strong = bool(kinds & {"thread.create", "mem.write", "thread.apc"})
        if strong or ({"mem.alloc", "mem.protect"} <= kinds):
            findings.append(
                Finding(
                    rule_id="process_injection",
                    title="Cross-process memory manipulation / remote thread",
                    severity="high",
                    weight=55,
                    description=(
                        "The sample opened another process and wrote/allocated/executed memory "
                        "inside it, the canonical process-injection pattern."
                    ),
                    technique="T1055",
                    evidence=_evidence(analyzed, lambda e: e in injection_ev),
                    detail=", ".join(sorted(kinds)),
                )
            )

    remote_rwx = [
        e
        for e in analyzed
        if e.type in ("mem.alloc", "mem.protect")
        and _is_remote(e)
        and (_hexint(e.get("protect")) & 0xF0)
    ]
    if remote_rwx:
        findings.append(
            Finding(
                rule_id="remote_rwx",
                title="Executable memory in a remote process",
                severity="high",
                weight=30,
                description="A remote allocation/protection was made executable (RWX/RX).",
                technique="T1055.002",
                evidence=_evidence(analyzed, lambda e: e in remote_rwx),
                detail=f"{len(remote_rwx)} event(s)",
            )
        )

    # --- local RWX / shellcode staging ------------------------------------
    private_exec = [
        e
        for e in analyzed
        if e.type == "mem.protect"
        and not _is_remote(e)
        and _hexint(e.get("protect")) & 0xF0
        and e.get("base")
        and _hexint(e.get("base")) < 0x10000000
        and 64 <= int(e.get("size") or 0) <= 0x10000
        and e.origin == "sample"
    ]
    if private_exec:
        findings.append(
            Finding(
                rule_id="private_rwx",
                title="Private memory made executable",
                severity="medium",
                weight=25,
                description=(
                    "A non-image allocation was switched to executable permissions, "
                    "consistent with shellcode staging or unpacking."
                ),
                technique="T1055.009",
                evidence=_evidence(analyzed, lambda e: e in private_exec),
                detail=f"{len(private_exec)} event(s)",
            )
        )

    # --- shellcode execution ------------------------------------------------
    crashes = [e for e in analyzed if e.type == "sandbox.crash"]
    if private_exec:
        first = private_exec[0]
        children = [
            e
            for e in analyzed
            if e.type in ("wine.process", "process.create")
            and e.ts >= first.ts
            and "\\windows\\" not in path_key(e.get("image") or e.get("cmdline"))
            and path_key(e.get("image") or e.get("cmdline")).split("\\")[-1].split(" ")[0]
            not in ("wineboot.exe", "winemenubuilder.exe", "services.exe", "winedevice.exe",
                    "plugplay.exe", "svchost.exe", "rpcss.exe", "explorer.exe")
        ]
        if crashes or children:
            ev = private_exec + crashes[:2] + children[:5]
            findings.append(
                Finding(
                    rule_id="shellcode_execution",
                    title="Shellcode staged on private memory and executed",
                    severity="high",
                    weight=40,
                    description=(
                        "A small private allocation was made executable and the run then either "
                        "crashed in ntdll or spawned a child process, which is the signature of "
                        "a loader transferring control to embedded shellcode."
                    ),
                    technique="T1055.009",
                    evidence=_evidence(analyzed, lambda e: e in ev),
                    detail=(
                        (basename(children[0].get("image") or children[0].get("cmdline")) if children else "crash")
                    ),
                )
            )
    if crashes:
        findings.append(
            Finding(
                rule_id="execution_crash",
                title="Crash while executing the sample",
                severity="low",
                weight=10,
                description=(
                    "Wine reported an unhandled page fault/exception. Under a user-mode sandbox "
                    "this often means the payload executed but assumed real Windows internals."
                ),
                technique="T1497.001",
                evidence=_evidence(analyzed, lambda e: e in crashes),
                detail=(crashes[0].get("message") or "")[:160],
            )
        )

    # --- persistence -------------------------------------------------------
    run_keys = [
        e
        for e in analyzed
        if e.type in ("reg.create", "reg.setvalue")
        and any(k in path_key(e.get("path")) for k in ("\\currentversion\\run", "\\currentversion\\runonce"))
    ]
    if run_keys:
        findings.append(
            Finding(
                rule_id="persistence_run_key",
                title="Run/RunOnce autostart registry write",
                severity="high",
                weight=35,
                description="The sample configured itself or a payload to start at logon.",
                technique="T1547.001",
                evidence=_evidence(analyzed, lambda e: e in run_keys),
                detail=basename(run_keys[0].get("path") or "") or "Run",
            )
        )

    service_keys = [
        e
        for e in analyzed
        if e.type in ("reg.create", "reg.setvalue")
        and "\\currentcontrolset\\services\\" in path_key(e.get("path"))
    ]
    if service_keys:
        findings.append(
            Finding(
                rule_id="persistence_service",
                title="Windows service installation",
                severity="high",
                weight=35,
                description="A service registry key was created or configured.",
                technique="T1543.003",
                evidence=_evidence(analyzed, lambda e: e in service_keys),
            )
        )

    startup_files = [
        e
        for e in analyzed
        if e.type == "file.create" and "\\start menu\\programs\\startup\\" in path_key(e.get("path"))
    ]
    if startup_files:
        findings.append(
            Finding(
                rule_id="persistence_startup_folder",
                title="Executable dropped into the Startup folder",
                severity="high",
                weight=30,
                description="A file was created in a Start Menu Startup directory.",
                technique="T1547.001",
                evidence=_evidence(analyzed, lambda e: e in startup_files),
            )
        )

    # --- dropper -----------------------------------------------------------
    dropped = [
        e
        for e in analyzed
        if e.type == "file.create"
        and _in_user_writable(e.get("path") or "")
        and any((e.get("path") or "").lower().endswith(x) for x in EXEC_EXT)
    ]
    created_keys = {path_key(e.get("path")) for e in analyzed if e.type == "file.create"}
    executed = [
        e
        for e in analyzed
        if e.type in ("process.create", "wine.process")
        and path_key(e.get("image") or "") in created_keys
    ]
    if dropped or executed:
        ev = [e for e in analyzed if e in dropped or e in executed]
        findings.append(
            Finding(
                rule_id="dropper",
                title="Executable dropped and/or launched from a writable directory",
                severity="high",
                weight=35,
                description="A PE/script was written to a user-writable path and executed.",
                technique="T1105",
                evidence=_evidence(analyzed, lambda e: e in ev),
                detail=(basename(dropped[0].get("path")) if dropped else basename(executed[0].get("image") or "")),
            )
        )

    # --- defense tampering --------------------------------------------------
    tamper = [
        e
        for e in analyzed
        if e.type in ("reg.create", "reg.setvalue", "reg.delete", "file.create", "file.delete")
        and any(
            marker in path_key(e.get("path"))
            for marker in (
                "windows defender",
                "disableantispyware",
                "disableantivirus",
                "security center",
                "\\currentcontrolset\\services\\sharedaccess",
                "windows\\system32\\",
                "disabletaskmgr",
                "disableuac",
            )
        )
    ]
    if tamper:
        findings.append(
            Finding(
                rule_id="defense_tampering",
                title="Security/OS configuration tampering",
                severity="high",
                weight=40,
                description="Security-relevant registry keys or system files were modified.",
                technique="T1562.001",
                evidence=_evidence(analyzed, lambda e: e in tamper),
            )
        )

    # --- ransomware-like mass writes --------------------------------------
    writes = [e for e in analyzed if e.type in ("file.write", "file.rename")]
    uniq_paths = {path_key(e.get("path") or e.get("new_path")) for e in writes}
    ransom_ext = [
        e for e in writes if any((e.get("new_path") or e.get("path") or "").lower().endswith(x) for x in RANSOM_EXT)
    ]
    if len(uniq_paths) >= 10 or ransom_ext:
        findings.append(
            Finding(
                rule_id="mass_file_modification",
                title="Mass file modification / ransomware-like encryption",
                severity="high",
                weight=45,
                description="Many files were rewritten or renamed with encryption-style extensions.",
                technique="T1486",
                evidence=_evidence(analyzed, lambda e: e in writes),
                detail=f"{len(uniq_paths)} unique path(s)",
            )
        )

    # --- anti-debug / sandbox evasion --------------------------------------
    anti = [
        e
        for e in analyzed
        if e.origin == "sample"
        and (
            (e.type == "proc.query" and _hexint(e.get("class")) in (7, 0x1E, 0x1F, 30, 31, 0x22))
            or (e.type == "thread.setinfo" and _hexint(e.get("class")) == 0x11)
        )
    ]
    static_anti = [x for x in pe.imports if x.lower() in ("isdebuggerpresent", "checkremotedebuggerpresent", "outputdebugstringa")]
    if anti or (static_anti and not pe.parse_error):
        findings.append(
            Finding(
                rule_id="anti_debug",
                title="Debugger / analysis environment probing",
                severity="low",
                weight=20,
                description="The sample queried debugger state or hid threads from debuggers.",
                technique="T1622",
                evidence=_evidence(analyzed, lambda e: e in anti),
                detail=", ".join(sorted({e.type + ":" + str(e.get("class")) for e in anti})) or ", ".join(static_anti),
            )
        )

    long_sleep = [e for e in analyzed if e.type == "sleep" and int(e.get("ms") or 0) >= 60000]
    if long_sleep:
        findings.append(
            Finding(
                rule_id="long_sleep",
                title="Long sleep (sandbox timeout evasion)",
                severity="low",
                weight=10,
                description="The sample sleeps for more than a minute, a common sandbox-evasion trick.",
                technique="T1497.003",
                evidence=_evidence(analyzed, lambda e: e in long_sleep),
                detail=f"{int(long_sleep[0].get('ms') or 0)} ms",
            )
        )

    # --- network ------------------------------------------------------------
    net = [e for e in analyzed if e.type in ("net.connect", "net.dns")]
    if net:
        endpoints = []
        for e in net:
            if e.type == "net.connect":
                endpoints.append(f"{e.get('address')}:{e.get('port')}")
            else:
                endpoints.append(str(e.get("host")))
        findings.append(
            Finding(
                rule_id="network_activity",
                title="Outbound network activity",
                severity="medium",
                weight=20,
                description="The sample attempted to connect to or resolve a remote endpoint.",
                technique="T1071",
                evidence=_evidence(analyzed, lambda e: e in net),
                detail=", ".join(dict.fromkeys(endpoints))[:200],
            )
        )

    # --- direct syscalls ----------------------------------------------------
    if pe.syscall_count > 0 or pe.sysenter_count > 0 or pe.int2e_count > 0:
        findings.append(
            Finding(
                rule_id="direct_syscall",
                title="Direct system-call instructions in the image",
                severity="medium",
                weight=30,
                description=(
                    "The executable contains inline syscall/sysenter/int 2e instructions, "
                    "which bypass ntdll and defeat user-mode API hooks."
                ),
                technique="T1106",
                evidence=[],
                detail=(
                    f"syscall={pe.syscall_count} sysenter={pe.sysenter_count} int2e={pe.int2e_count}"
                ),
            )
        )

    # --- driver -------------------------------------------------------------
    drivers = [e for e in analyzed if e.type == "driver.load"]
    if drivers:
        findings.append(
            Finding(
                rule_id="driver_load",
                title="Kernel driver load attempt",
                severity="high",
                weight=60,
                description="NtLoadDriver was invoked with a service path.",
                technique="T1543.003",
                evidence=_evidence(analyzed, lambda e: e in drivers),
            )
        )

    # --- self delete --------------------------------------------------------
    sample_name = (meta.get("sample_name") or basename(pe.path)).lower()
    self_del = [
        e
        for e in analyzed
        if e.type in ("file.delete", "file.rename")
        and basename(e.get("path") or e.get("new_path") or "").lower() == sample_name
    ]
    if self_del:
        findings.append(
            Finding(
                rule_id="self_delete",
                title="Self-deletion",
                severity="medium",
                weight=20,
                description="The sample deleted or renamed its own executable.",
                technique="T1070.004",
                evidence=_evidence(analyzed, lambda e: e in self_del),
            )
        )

    # --- side-loaded module -------------------------------------------------
    side = [
        e
        for e in analyzed
        if e.type == "wine.loaddll"
        and (e.get("path") or "").lower().endswith(".dll")
        and "\\windows\\" not in path_key(e.get("path"))
        and "petracer" not in path_key(e.get("path"))
        and path_key(e.get("path")) != "z:\\tmp\\sample\\" + sample_name
    ]
    if side:
        findings.append(
            Finding(
                rule_id="side_loaded_module",
                title="DLL loaded from a non-system path",
                severity="low",
                weight=10,
                description="A module was loaded from outside C:\\windows, a common sideloading pattern.",
                technique="T1129",
                evidence=_evidence(analyzed, lambda e: e in side),
                detail=basename(side[0].get("path") or ""),
            )
        )

    # --- scoring ------------------------------------------------------------
    seen: set[str] = set()
    uniq: list[Finding] = []
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        uniq.append(f)
    score = min(100, sum(f.weight for f in uniq))
    verdict = "malicious" if score >= 60 else "suspicious" if score >= 20 else "clean"

    stats = _stats(analyzed, meta)
    return Analysis(findings=uniq, score=score, verdict=verdict, stats=stats)


def _stats(events: Iterable[Event], meta: dict | None = None) -> dict[str, Any]:
    counts: dict[str, int] = {}
    files: set[str] = set()
    regs: set[str] = set()
    nets: set[str] = set()
    procs: set[str] = set()
    ntsys: dict[str, int] = {}
    for e in events:
        counts[e.type] = counts.get(e.type, 0) + 1
        if e.type.startswith("file.") and e.get("path"):
            files.add(e.get("path"))
        if e.type.startswith("reg.") and e.get("path"):
            regs.add(e.get("path"))
        if e.type == "net.connect":
            nets.add(f"{e.get('address')}:{e.get('port')}")
        elif e.type == "net.dns":
            nets.add(str(e.get("host")))
        if e.type in ("process.create", "wine.process"):
            name = e.get("image") or e.get("cmdline") or ""
            if _proc_name(name) not in INFRA_PROC:
                procs.add(name)
        if e.type == "nt.syscall" and e.api:
            ntsys[e.api] = ntsys.get(e.api, 0) + 1
    return {
        "event_counts": dict(sorted(counts.items())),
        "files": sorted(files)[:200],
        "registry_keys": sorted(regs)[:200],
        "network": sorted(n for n in nets if n)[:100],
        "processes": sorted(p for p in procs if p)[:100],
        "nt_syscalls": dict(
            sorted(
                ((meta or {}).get("nt_syscall_counts") or ntsys).items(),
                key=lambda kv: -kv[1],
            )[:50]
        ),
    }
