"""Minimal, dependency-free PE parser used for static triage."""
from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass, field
from pathlib import Path

MACHINES = {
    0x014C: "i386",
    0x8664: "x86_64",
    0x01C0: "arm",
    0xAA64: "arm64",
}

SUBSYSTEMS = {
    1: "native",
    2: "gui",
    3: "console",
    9: "windows_ce",
    10: "efi",
}

DATA_DIR_IMPORT = 1
DATA_DIR_COM = 14

SCN_MEM_EXECUTE = 0x20000000
SCN_CNT_CODE = 0x00000020


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    characteristics: int

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_EXECUTE) or bool(
            self.characteristics & SCN_CNT_CODE
        )


@dataclass
class PEInfo:
    path: str
    size: int
    sha256: str
    machine: int
    arch: str
    subsystem: int
    subsystem_name: str
    timestamp: int
    entrypoint: int
    image_base: int
    sections: list[Section] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    imported_dlls: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    is_dotnet: bool = False
    overlay_size: int = 0
    syscall_count: int = 0
    sysenter_count: int = 0
    int2e_count: int = 0
    packer: str | None = None
    parse_error: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "machine": hex(self.machine),
            "arch": self.arch,
            "subsystem": self.subsystem_name,
            "timestamp": self.timestamp,
            "entrypoint": hex(self.entrypoint),
            "image_base": hex(self.image_base),
            "is_dotnet": self.is_dotnet,
            "overlay_size": self.overlay_size,
            "sections": [
                {
                    "name": s.name,
                    "va": hex(s.virtual_address),
                    "vsize": s.virtual_size,
                    "raw": s.raw_size,
                    "executable": s.executable,
                }
                for s in self.sections
            ],
            "imports": self.imports,
            "imported_dlls": self.imported_dlls,
            "exports": self.exports[:64],
            "syscall_insns": self.syscall_count,
            "sysenter_insns": self.sysenter_count,
            "int2e_insns": self.int2e_count,
            "packer": self.packer,
            "parse_error": self.parse_error,
        }


PACKER_NAMES = {
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".themida": "Themida",
    ".vmp0": "VMProtect",
    ".vmp1": "VMProtect",
    ".enigma1": "Enigma",
    ".enigma2": "Enigma",
    ".mpress1": "MPRESS",
    ".mpress2": "MPRESS",
}


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _rva_to_offset(sections: list[Section], rva: int) -> int | None:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            delta = rva - s.virtual_address
            if delta >= s.raw_size:
                return None
            return s.raw_offset + delta
    return None


def _read_cstr(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("ascii", "replace")


def parse_pe(path: str | Path) -> PEInfo:
    p = Path(path)
    data = p.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    info = PEInfo(
        path=str(p),
        size=len(data),
        sha256=sha,
        machine=0,
        arch="unknown",
        subsystem=0,
        subsystem_name="unknown",
        timestamp=0,
        entrypoint=0,
        image_base=0,
    )
    try:
        if data[:2] != b"MZ":
            raise ValueError("not a PE file (missing MZ)")
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        coff = e_lfanew + 4
        machine, nsec, timestamp = struct.unpack_from("<HHI", data, coff)
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        is64 = magic == 0x20B
        if not is64 and magic != 0x10B:
            raise ValueError(f"unknown optional header magic 0x{magic:x}")
        entrypoint = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q" if is64 else "<I", data, opt + 24)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dd_off = opt + (112 if is64 else 96)
        num_dirs = struct.unpack_from("<I", data, dd_off - 4)[0]
        data_dirs = []
        for i in range(min(num_dirs, 16)):
            data_dirs.append(struct.unpack_from("<II", data, dd_off + i * 8))

        info.machine = machine
        info.arch = MACHINES.get(machine, f"0x{machine:04x}")
        info.subsystem = subsystem
        info.subsystem_name = SUBSYSTEMS.get(subsystem, str(subsystem))
        info.timestamp = timestamp
        info.entrypoint = entrypoint
        info.image_base = image_base

        sec_off = opt + opt_size
        for i in range(nsec):
            off = sec_off + i * 40
            name = data[off : off + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize, va, raw_size, raw_off = struct.unpack_from("<IIII", data, off + 8)
            chars = struct.unpack_from("<I", data, off + 36)[0]
            info.sections.append(Section(name, va, vsize, raw_size, raw_off, chars))
            if name.lower() in PACKER_NAMES:
                info.packer = PACKER_NAMES[name.lower()]

        # overlay = bytes after the last section's raw data
        end = max((s.raw_offset + s.raw_size for s in info.sections), default=0)
        info.overlay_size = max(0, len(data) - end)

        if len(data_dirs) > DATA_DIR_COM and data_dirs[DATA_DIR_COM][0]:
            info.is_dotnet = True

        if len(data_dirs) > DATA_DIR_IMPORT and data_dirs[DATA_DIR_IMPORT][1]:
            _parse_imports(data, info, data_dirs[DATA_DIR_IMPORT], is64)

        # syscall / int 2e instruction scan in executable sections
        for s in info.sections:
            if not s.executable or not s.raw_size:
                continue
            blob = data[s.raw_offset : s.raw_offset + s.raw_size]
            info.syscall_count += blob.count(b"\x0f\x05")
            info.sysenter_count += blob.count(b"\x0f\x34")
            info.int2e_count += blob.count(b"\xcd\x2e")
    except Exception as exc:  # noqa: BLE001 - triage must never crash the runner
        info.parse_error = str(exc)
    return info


def _parse_imports(data: bytes, info: PEInfo, entry: tuple[int, int], is64: bool) -> None:
    rva, size = entry
    off = _rva_to_offset(info.sections, rva)
    if off is None:
        return
    thunk_size = 8 if is64 else 4
    fmt = "<Q" if is64 else "<I"
    ordinal_flag = 1 << (63 if is64 else 31)
    seen = set()
    index = 0
    while index < 512:
        desc = off + index * 20
        if desc + 20 > len(data):
            break
        ilt, _ts, _fc, name_rva, iat = struct.unpack_from("<IIIII", data, desc)
        if not name_rva and not ilt and not iat:
            break
        dll = _read_cstr(data, _rva_to_offset(info.sections, name_rva) or -1, 64)
        if dll:
            info.imported_dlls.append(dll.lower())
        thunk_rva = ilt or iat
        toff = _rva_to_offset(info.sections, thunk_rva)
        if toff is not None:
            j = 0
            while j < 4096:
                try:
                    value = struct.unpack_from(fmt, data, toff + j * thunk_size)[0]
                except struct.error:
                    break
                if not value:
                    break
                if value & ordinal_flag:
                    name = f"#{value & 0xFFFF}"
                else:
                    hint_off = _rva_to_offset(info.sections, value & 0x7FFFFFFF)
                    name = _read_cstr(data, (hint_off or 0) + 2, 128) if hint_off is not None else ""
                if name and name not in seen:
                    seen.add(name)
                    info.imports.append(name)
                j += 1
        index += 1


def file_entropy(path: str | Path) -> float:
    return round(_entropy(Path(path).read_bytes()), 3)
