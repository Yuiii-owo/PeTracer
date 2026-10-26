import contextlib
import io
import unittest

from petracer.trace import TracePrinter

EVENTS = [
    {"seq": 1, "ts": 1000, "type": "agent.ready", "hooks": 29, "imports": 49, "image": "x.exe"},
    {"seq": 2, "ts": 1001, "type": "import.call", "api": "CreateFileW",
     "dll": "KERNEL32.dll", "a1": "0x1", "a2": "0x2", "a3": "0x3", "a4": "0x4"},
    {"seq": 3, "ts": 1002, "type": "file.create", "api": "NtCreateFile",
     "path": "C:\\x.txt", "access": "0x40100080", "disposition": 5},
    {"seq": 4, "ts": 1003, "type": "import.call", "api": "memcpy",
     "dll": "api-ms-win-crt-string-l1-1-0.dll"},
]


class TracePrinterTests(unittest.TestCase):
    def render(self, **kwargs):
        printer = TracePrinter(color=False, **kwargs)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for ev in EVENTS:
                printer(ev)
        return printer, buf.getvalue()

    def test_import_then_syscall(self):
        printer, out = self.render()
        self.assertIn("IMPORT  CreateFileW", out)
        self.assertIn("SYSCALL NtCreateFile", out)
        self.assertLess(out.index("IMPORT  CreateFileW"), out.index("SYSCALL NtCreateFile"))
        self.assertEqual(printer.import_calls, 2)
        self.assertEqual(printer.syscalls, 1)

    def test_no_crt(self):
        _, out = self.render(no_crt=True)
        self.assertNotIn("memcpy", out)
        self.assertIn("CreateFileW", out)

    def test_syscalls_only(self):
        _, out = self.render(show_imports=False)
        self.assertNotIn("IMPORT", out)
        self.assertIn("SYSCALL", out)

    def test_limit(self):
        printer, out = self.render(limit=2)
        self.assertEqual(printer.lines, 2)
        self.assertIn("trace limit 2 reached", out)


if __name__ == "__main__":
    unittest.main()
