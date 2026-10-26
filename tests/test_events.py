import unittest

from petracer.events import Event, normalize_path, path_key, basename


class PathTests(unittest.TestCase):
    def test_nt_prefixes(self):
        self.assertEqual(normalize_path("\\??\\C:\\Windows\\x.dll"), "C:\\Windows\\x.dll")
        self.assertEqual(normalize_path("\\??\\C:\\x"), "C:\\x")
        self.assertEqual(normalize_path("\\\\?\\C:\\x"), "C:\\x")
        self.assertEqual(normalize_path("\\??\\UNC\\server\\share\\x"), "\\\\server\\share\\x")

    def test_key_and_basename(self):
        self.assertEqual(path_key("C:\\Windows\\System32\\A.DLL"), "c:\\windows\\system32\\a.dll")
        self.assertEqual(basename("C:\\Windows\\x.dll"), "x.dll")
        self.assertEqual(basename("C:\\Windows\\"), "Windows")


class EventTests(unittest.TestCase):
    def test_from_agent(self):
        ev = Event.from_agent(
            {
                "ts": 1_700_000_000_500,
                "pid": 10,
                "tid": 11,
                "type": "file.create",
                "api": "NtCreateFile",
                "caller": "kernelbase.dll",
                "origin": "sample",
                "path": "\\??\\C:\\x.txt",
                "disposition": 5,
            }
        )
        self.assertAlmostEqual(ev.ts, 1_700_000_000.5)
        self.assertEqual(ev.data["path"], "C:\\x.txt")
        self.assertEqual(ev.origin, "sample")
        self.assertEqual(ev.to_dict()["type"], "file.create")


if __name__ == "__main__":
    unittest.main()
