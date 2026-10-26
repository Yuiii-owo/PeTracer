"""Build the Windows-side agent / launcher and the test samples with mingw."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
AGENT_SRC = PKG_DIR / "agent" / "petracer_agent.c"
LAUNCH_SRC = PKG_DIR / "agent" / "petracer_launch.c"
CACHE_DIR = Path(os.environ.get("PETRACER_CACHE", Path.home() / ".cache" / "petracer"))
BIN_DIR = CACHE_DIR / "bin"

CC64 = "x86_64-w64-mingw32-gcc"
CC32 = "i686-w64-mingw32-gcc"


class BuildError(RuntimeError):
    pass


def _run(cmd: list[str], verbose: bool = True) -> None:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise BuildError(
            f"build failed: {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}"
        )
    if verbose and proc.stderr.strip():
        print(proc.stderr.strip())


def _needs_build(out: Path, sources: list[Path]) -> bool:
    if not out.exists():
        return True
    out_mtime = out.stat().st_mtime
    return any(s.stat().st_mtime > out_mtime for s in sources)


def _build_one(cc: str, kind: str, out: Path, verbose: bool) -> None:
    if kind == "agent":
        cmd = [cc, "-shared", "-O2", "-s", "-static", "-static-libgcc", "-o", str(out), str(AGENT_SRC)]
    else:
        cmd = [cc, "-municode", "-O2", "-s", "-static", "-static-libgcc", "-o", str(out), str(LAUNCH_SRC)]
    _run(cmd, verbose=verbose)


def ensure_binaries(force: bool = False, verbose: bool = True) -> dict[str, dict[str, Path]]:
    """Build (if needed) and return {'x64': {...}, 'x86': {...}}."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    result: dict[str, dict[str, Path]] = {}

    if shutil.which(CC64) is None:
        raise BuildError(
            f"{CC64} not found. Install mingw-w64 (Arch: pacman -S mingw-w64-gcc)."
        )

    x64 = {
        "agent": BIN_DIR / "petracer_agent64.dll",
        "launcher": BIN_DIR / "petracer_launch64.exe",
    }
    for kind, out in x64.items():
        if force or _needs_build(out, [AGENT_SRC if kind == "agent" else LAUNCH_SRC]):
            _build_one(CC64, kind, out, verbose)
    result["x64"] = x64

    if shutil.which(CC32):
        x86 = {
            "agent": BIN_DIR / "petracer_agent32.dll",
            "launcher": BIN_DIR / "petracer_launch32.exe",
        }
        for kind, out in x86.items():
            if force or _needs_build(out, [AGENT_SRC if kind == "agent" else LAUNCH_SRC]):
                _build_one(CC32, kind, out, verbose)
        result["x86"] = x86
    return result


def build_samples(samples_dir: Path, out_dir: Path, verbose: bool = True) -> dict[str, Path]:
    """Compile every samples/*.c for x64; hello32.c additionally for i386."""
    out_dir.mkdir(parents=True, exist_ok=True)
    built: dict[str, Path] = {}
    if shutil.which(CC64) is None:
        raise BuildError(f"{CC64} not found")
    for src in sorted(samples_dir.glob("*.c")):
        name = f"{src.stem}64.exe"
        out = out_dir / name
        _run(
            [CC64, "-O2", "-s", "-static", "-o", str(out), str(src), "-lws2_32"],
            verbose=verbose,
        )
        built[src.stem] = out
    if shutil.which(CC32):
        src = samples_dir / "hello32.c"
        if src.exists():
            out = out_dir / "hello32.exe"
            _run([CC32, "-O2", "-s", "-static", "-o", str(out), str(src)], verbose=verbose)
            built["hello32"] = out
    return built
