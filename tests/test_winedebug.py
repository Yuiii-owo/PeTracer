import unittest

from petracer.winedebug import parse_line


class WineDebugParserTests(unittest.TestCase):
    def test_loaddll(self):
        line = (
            '0024:trace:loaddll:build_module Loaded L"Z:\\\\tmp\\\\sample\\\\sample.exe" '
            'at 0000000140000000: native'
        )
        ev = parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.type, "wine.loaddll")
        self.assertEqual(ev.data["path"], "Z:\\tmp\\sample\\sample.exe")
        self.assertEqual(ev.data["base"], "0x140000000")

    def test_ntcreateuserprocess(self):
        line = (
            '0024:trace:process:NtCreateUserProcess L"\\\\??\\\\C:\\\\windows\\\\system32\\\\cmd.exe" '
            'image L"C:\\\\windows\\\\system32\\\\cmd.exe" cmdline L"C:\\\\windows\\\\system32\\\\cmd.exe /c echo x"'
            ' parent (nil) machine 8664'
        )
        ev = parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.type, "wine.process")
        self.assertEqual(ev.data["image"], "C:\\windows\\system32\\cmd.exe")
        self.assertIn("echo x", ev.data["cmdline"])

    def test_ntcreateuserprocess_ids(self):
        line = (
            '0024:trace:process:NtCreateUserProcess L"\\\\??\\\\Z:\\\\tmp\\\\sample\\\\x.exe" '
            'pid 00d8 tid 00dc handles 0x44/0x48'
        )
        ev = parse_line(line)
        self.assertIsNotNone(ev)
        self.assertEqual(ev.type, "wine.process_id")
        self.assertEqual(ev.data["ntpath"], "Z:\\tmp\\sample\\x.exe")
        self.assertEqual(ev.data["pid"], 0xD8)
        self.assertEqual(ev.data["child_tid"], 0xDC)

    def test_timestamped_syscall(self):
        ev = parse_line('7474.552:002c:SysCall  NtOpenFile(1,2,3,4,5,6)')
        self.assertIsNotNone(ev)
        self.assertEqual(ev.type, "nt.syscall")
        self.assertEqual(ev.api, "NtOpenFile")
        self.assertEqual(ev.tid, 0x2C)
        self.assertGreater(ev.ts, 0)

    def test_ignores_noise(self):
        self.assertIsNone(parse_line("MESA-EGL: warning: something"))
        self.assertIsNone(parse_line("0024:trace:seh:something"))


if __name__ == "__main__":
    unittest.main()
