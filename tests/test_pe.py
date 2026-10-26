import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from petracer import build
from petracer.pe import parse_pe

ROOT = Path(__file__).resolve().parent.parent


@unittest.skipUnless(shutil.which(build.CC64), "mingw-w64 not installed")
class PEParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bins = build.ensure_binaries(verbose=False)
        cls.agent = cls.bins["x64"]["agent"]

    def test_parses_agent_dll(self):
        info = parse_pe(self.agent)
        self.assertIsNone(info.parse_error)
        self.assertEqual(info.machine, 0x8664)
        self.assertEqual(info.arch, "x86_64")
        self.assertGreater(len(info.sections), 0)
        self.assertEqual(len(info.sha256), 64)
        self.assertIn("kernel32.dll", [d.lower() for d in info.imported_dlls])

    def test_rejects_non_pe(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"not a pe file")
            path = fh.name
        info = parse_pe(path)
        self.assertIsNotNone(info.parse_error)
        self.assertEqual(info.arch, "unknown")

    def test_direct_syscall_scan(self):
        with tempfile.TemporaryDirectory() as td:
            src = ROOT / "samples" / "directsyscall.c"
            out = Path(td) / "ds.exe"
            build._run([build.CC64, "-O2", "-s", "-o", str(out), str(src), "-lws2_32"], verbose=False)
            info = parse_pe(out)
            self.assertIsNone(info.parse_error)
            self.assertGreaterEqual(info.syscall_count, 1)

    def test_hello_is_clean_pe(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "hello.exe"
            build._run([build.CC64, "-O2", "-s", "-o", str(out), str(ROOT / "samples" / "hello.c")], verbose=False)
            info = parse_pe(out)
            self.assertEqual(info.arch, "x86_64")
            self.assertEqual(info.subsystem_name, "console")
            jsonable = info.to_dict()
            self.assertIn("sections", jsonable)


if __name__ == "__main__":
    unittest.main()
