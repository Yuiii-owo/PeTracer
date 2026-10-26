"""PeTracer command line interface."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__, build
from .detect.rules import Analysis, analyze
from .events import load_agent_events, summarize, write_events
from .events import Event
from .pe import parse_pe
from .report import build_report, load_report_inputs, write_report
from .sandbox import SandboxConfig, SandboxError, ensure_prefix, run_sample, wine_version
from .trace import TracePrinter, print_anomalies, trace_sample

GREEN, RED, ORANGE, RESET, DIM = "\033[32m", "\033[31m", "\033[33m", "\033[0m", "\033[2m"


def _color(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled and sys.stdout.isatty() else text


def _print_summary(result, analysis: Analysis, report_path: Path, quiet: bool) -> None:
    if quiet:
        print(json.dumps({"verdict": analysis.verdict, "score": analysis.score, "report": str(report_path)}))
        return
    color = {"clean": GREEN, "suspicious": ORANGE, "malicious": RED}.get(analysis.verdict, "")
    print()
    print(f"verdict : {_color(analysis.verdict.upper(), color, True)}  score={analysis.score}/100")
    print(f"events  : {len(result.events)}  agent={'yes' if result.agent_ready else 'no'}  "
          f"duration={result.duration:.2f}s  exit={result.exit_code}"
          + ("  TIMEOUT" if result.timed_out else ""))
    if analysis.findings:
        print("findings:")
        for f in analysis.findings:
            print(f"  - [{f.severity}] {f.title} ({f.technique}, +{f.weight})")
    else:
        print("findings: none")
    print(f"report  : {report_path}")
    print(f"events  : {result.out_dir / 'events.jsonl'}")
    for w in result.warnings:
        print(f"warning : {w}", file=sys.stderr)


def cmd_init(args: argparse.Namespace) -> int:
    try:
        prefix = ensure_prefix(Path(args.prefix) if args.prefix else None, force=args.force)
    except SandboxError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Wine prefix ready: {prefix}")
    try:
        bins = build.ensure_binaries(force=args.force)
        for arch, paths in bins.items():
            print(f"agent[{arch}]: {paths['agent']}  launcher: {paths['launcher']}")
    except build.BuildError as exc:
        print(f"warning: {exc}", file=sys.stderr)
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    out_dir = Path(args.out) if args.out else Path("petracer-out") / (
        f"{Path(args.sample).stem}-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    cfg = SandboxConfig(
        sample=Path(args.sample),
        args=list(args.sample_args),
        out_dir=out_dir,
        timeout=args.timeout,
        wine_trace=args.wine_trace,
        wine_syscall=args.wine_syscall,
        no_agent=args.no_agent,
        no_bwrap=args.no_bwrap,
        use_seccomp=not args.no_seccomp,
        keep_work=args.keep_work,
        prefix=Path(args.prefix) if args.prefix else None,
        verbose=not args.quiet,
    )
    try:
        result = run_sample(cfg)
    except (SandboxError, build.BuildError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    analysis = analyze(result.events, result.pe, result.meta)
    report = build_report(result.meta, result.pe.to_dict(), analysis, result.events, result.artifacts)
    json_path, md_path = write_report(result.out_dir, report)
    _print_summary(result, analysis, md_path, args.quiet)
    if args.fail_on_malicious and analysis.verdict == "malicious":
        return 3
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    out_dir = Path(args.out_dir)
    if not (out_dir / "meta.json").exists():
        print(f"error: {out_dir} does not look like a PeTracer run directory", file=sys.stderr)
        return 2
    meta, pe_info, events, artifacts = load_report_inputs(out_dir)
    sample_path = Path(meta.get("sample", ""))
    if sample_path.is_file():
        pe = parse_pe(sample_path)
    else:
        from .pe import PEInfo

        info = pe_info or {}
        pe = PEInfo(
            path=str(sample_path),
            size=int(info.get("size") or 0),
            sha256=str(info.get("sha256") or ""),
            machine=int(str(info.get("machine") or "0"), 16) if str(info.get("machine", "")).startswith("0x") else 0,
            arch=str(info.get("arch") or "unknown"),
            subsystem=0,
            subsystem_name=str(info.get("subsystem") or "unknown"),
            timestamp=int(info.get("timestamp") or 0),
            entrypoint=0,
            image_base=0,
            imports=list(info.get("imports") or []),
            imported_dlls=list(info.get("imported_dlls") or []),
            syscall_count=int(info.get("syscall_insns") or 0),
            sysenter_count=int(info.get("sysenter_insns") or 0),
            int2e_count=int(info.get("int2e_insns") or 0),
        )
    analysis = analyze(events, pe, meta)
    report = build_report(meta, pe_info or pe.to_dict(), analysis, events, artifacts)
    json_path, md_path = write_report(out_dir, report)
    print(f"verdict={analysis.verdict} score={analysis.score} findings={len(analysis.findings)}")
    print(f"wrote {md_path}")
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"error: target not found: {target}", file=sys.stderr)
        return 2
    out_dir = Path(args.out) if args.out else Path("petracer-out") / (
        f"trace-{target.stem}-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    printer = TracePrinter(
        show_imports=not args.syscalls_only,
        show_syscalls=not args.imports_only,
        show_all=args.all,
        no_crt=args.no_crt,
        limit=args.limit,
        color=not args.no_color and sys.stdout.isatty(),
    )
    print(f"PeTracer trace: {target}")
    print(f"  timeout={args.timeout}s  imports={'on' if printer.show_imports else 'off'}  "
          f"syscalls={'on' if printer.show_syscalls else 'off'}")
    print(f"  out={out_dir}")
    print()
    try:
        result, analysis = trace_sample(
            target, list(args.target_args), out_dir, args.timeout, printer, args.keep_work
        )
    except (SandboxError, build.BuildError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print_anomalies(result)
    print()
    print(
        f"summary: imports={printer.import_calls} syscalls={printer.syscalls} "
        f"events={printer.lines} exit={result.exit_code} duration={result.duration:.2f}s"
        + (" TIMEOUT" if result.timed_out else "")
    )
    if not result.agent_ready:
        print("warning: agent did not become ready; import/syscall tracing unavailable", file=sys.stderr)
    print(f"verdict: {analysis.verdict} ({analysis.score}/100)")
    print(f"report : {out_dir / 'report.md'}")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    repo = Path(__file__).resolve().parent.parent
    samples_dir = Path(args.samples) if args.samples else repo / "samples"
    out_root = Path(args.out) if args.out else repo / "build" / "selftest"
    out_root.mkdir(parents=True, exist_ok=True)
    print(f"building agent + samples from {samples_dir}")
    try:
        build.ensure_binaries(verbose=True)
        built = build.build_samples(samples_dir, out_root / "bin", verbose=False)
    except build.BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    expectations: dict[str, set[str]] = {
        "hello": set(),
        "persist": {"persistence_run_key"},
        "dropper": {"dropper"},
        "inject": {"process_injection"},
        "rwx": {"private_rwx"},
        "antidebug": {"anti_debug"},
        "netprobe": {"network_activity"},
        "directsyscall": {"direct_syscall"},
        "probe": {"persistence_run_key", "network_activity", "private_rwx", "remote_rwx"},
    }
    only = set(args.only.split(",")) if args.only else None
    failures = 0
    rows = []
    for name, expected in expectations.items():
        if only and name not in only:
            continue
        if name not in built:
            rows.append((name, "SKIP", "sample binary not built"))
            continue
        out_dir = out_root / name
        cfg = SandboxConfig(
            sample=built[name],
            out_dir=out_dir,
            timeout=args.timeout,
            verbose=False,
        )
        try:
            result = run_sample(cfg)
        except Exception as exc:  # noqa: BLE001
            rows.append((name, "ERROR", str(exc)))
            failures += 1
            continue
        analysis = analyze(result.events, result.pe, result.meta)
        report = build_report(result.meta, result.pe.to_dict(), analysis, result.events, result.artifacts)
        write_report(out_dir, report)
        got = {f.rule_id for f in analysis.findings}
        missing = expected - got
        if name == "hello":
            ok = analysis.verdict == "clean" and not analysis.findings
        else:
            ok = not missing and analysis.verdict in ("suspicious", "malicious")
        if not ok:
            failures += 1
            rows.append((name, "FAIL", f"verdict={analysis.verdict} missing={sorted(missing)} got={sorted(got)}"))
        else:
            rows.append((name, "PASS", f"verdict={analysis.verdict} score={analysis.score} rules={sorted(got)}"))

    print()
    print(f"{'sample':<14}{'result':<8}detail")
    for name, status, detail in rows:
        print(f"{name:<14}{status:<8}{detail}")
    print()
    if failures:
        print(f"{failures} selftest(s) failed; reports under {out_root}")
        return 1
    print(f"all selftests passed; reports under {out_root}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="petracer",
        description="Lightweight Windows malware behaviour sandbox (Wine + bubblewrap + API hooks).",
    )
    parser.add_argument("--version", action="version", version=f"petracer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="create the cached Wine prefix and build the agent")
    p_init.add_argument("--prefix", help="override prefix path")
    p_init.add_argument("--force", action="store_true", help="rebuild prefix and binaries")
    p_init.set_defaults(func=cmd_init)

    p_run = sub.add_parser("run", help="run a sample in the sandbox and report")
    p_run.add_argument("sample")
    p_run.add_argument("sample_args", nargs=argparse.REMAINDER, help="arguments passed to the sample")
    p_run.add_argument("-o", "--out", help="output directory")
    p_run.add_argument("-t", "--timeout", type=float, default=30.0, help="wall-clock timeout (seconds)")
    p_run.add_argument("--wine-trace", action="store_true", help="also enable WINEDEBUG +file,+reg")
    p_run.add_argument("--wine-syscall", action="store_true", help="enable WINEDEBUG +syscall (NT syscall boundary, heavy)")
    p_run.add_argument("--no-agent", action="store_true", help="disable the API hook agent")
    p_run.add_argument("--no-bwrap", action="store_true", help="run without bubblewrap (UNSAFE, debugging)")
    p_run.add_argument("--no-seccomp", action="store_true", help="disable the seccomp denylist")
    p_run.add_argument("--keep-work", action="store_true", help="keep the temporary run directory")
    p_run.add_argument("--prefix", help="override the Wine prefix")
    p_run.add_argument("--quiet", action="store_true", help="print a single JSON line")
    p_run.add_argument("--fail-on-malicious", action="store_true", help="exit 3 when the verdict is malicious")
    p_run.set_defaults(func=cmd_run)

    p_tr = sub.add_parser("trace", help="trace imported function calls and NT syscalls")
    p_tr.add_argument("target")
    p_tr.add_argument("target_args", nargs=argparse.REMAINDER, help="arguments passed to the sample")
    p_tr.add_argument("-t", "--timeout", type=float, default=30.0, help="wall-clock timeout (seconds)")
    p_tr.add_argument("-o", "--out", help="output directory")
    group = p_tr.add_mutually_exclusive_group()
    group.add_argument("--imports-only", action="store_true", help="only show imported function calls")
    group.add_argument("--syscalls-only", action="store_true", help="only show NT syscalls")
    p_tr.add_argument("--no-crt", action="store_true", help="hide ucrt/msvcrt/libgcc imports")
    p_tr.add_argument("--all", action="store_true", help="also show non-syscall agent events")
    p_tr.add_argument("--limit", type=int, default=5000, help="max printed lines (0 = unlimited)")
    p_tr.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p_tr.add_argument("--keep-work", action="store_true", help="keep the temporary run directory")
    p_tr.set_defaults(func=cmd_trace)

    p_rep = sub.add_parser("report", help="regenerate report.json/report.md for a run directory")
    p_rep.add_argument("out_dir")
    p_rep.set_defaults(func=cmd_report)

    p_self = sub.add_parser("selftest", help="build the bundled samples and verify detection")
    p_self.add_argument("--samples", help="samples source directory")
    p_self.add_argument("--out", help="output directory for selftest runs")
    p_self.add_argument("--timeout", type=float, default=25.0)
    p_self.add_argument("--only", help="comma separated sample names")
    p_self.set_defaults(func=cmd_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"init", "run", "report", "selftest", "trace"}
    # `petracer <target.exe>` is shorthand for `petracer trace <target.exe>`
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        argv = ["trace"] + argv
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
