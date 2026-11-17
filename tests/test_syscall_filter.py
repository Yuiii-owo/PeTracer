import tempfile
import unittest
from pathlib import Path

from petracer.events import Event
from petracer.sandbox import _filter_syscall_log, _target_tids


class SyscallFilterTest(unittest.TestCase):
    def test_target_tids_from_agent_and_process(self):
        events = [
            Event(ts=1.0, source="agent", type="file.write", tid=0xDC),
            Event(
                ts=1.0,
                source="wine",
                type="wine.process_id",
                tid=0x24,
                data={
                    "ntpath": "Z:\\tmp\\sample\\x.exe",
                    "pid": 0xD8,
                    "child_tid": 0xE4,
                },
            ),
            Event(
                ts=1.0,
                source="wine",
                type="wine.process_id",
                tid=0x24,
                data={"ntpath": "C:\\windows\\system32\\cmd.exe", "child_tid": 0x100},
            ),
        ]

        self.assertEqual(_target_tids(events, "x.exe"), {0xDC, 0xE4})

    def test_target_tids_falls_back_to_loader_thread(self):
        events = [
            Event(
                ts=1.0,
                source="wine",
                type="wine.loaddll",
                tid=0x24,
                data={"path": "Z:\\tmp\\sample\\x.exe"},
            )
        ]
        self.assertEqual(_target_tids(events, "x.exe"), {0x24})

    def test_filter_log_keeps_only_matching_tids(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log = root / "stderr.log"
            log.write_text(
                "00e4:SysCall  NtQuerySystemInformation(0000000b,0,0,0)\n"
                "1234.567:00e4:SysCall  NtQuerySystemInformation(0000000b,0,0,0)\n"
                "00e4:SysRet   NtQuerySystemInformation() retval=00000000\n"
                "00e0:SysCall  NtOpenKey(0,1,2)\n"
                "00e4:SysCall  NtClose(1)\n",
                encoding="utf-8",
            )

            counts, out_path, matched = _filter_syscall_log(log, {0xE4})

            self.assertEqual(counts, {"NtQuerySystemInformation": 2, "NtClose": 1})
            self.assertEqual(matched, 4)
            self.assertTrue(out_path.exists())
            lines = out_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 4)
            self.assertIn("NtQuerySystemInformation", lines[0])
            self.assertNotIn("NtOpenKey", "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
