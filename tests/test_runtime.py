import tempfile
import unittest
from pathlib import Path

from petracer.sandbox import _runtime_dlls


class RuntimeDllTest(unittest.TestCase):
    def test_selects_only_missing_imported_dlls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("VCRUNTIME140D.DLL", "ucrtbased.dll", "kernel32.dll", "readme.txt"):
                (root / name).write_bytes(b"x")

            found, missing = _runtime_dlls(
                ["kernel32.dll", "ucrtbased.dll", "vcruntime140d.dll"],
                [root],
                known={"kernel32.dll"},
            )

            self.assertEqual(sorted(found), ["ucrtbased.dll", "vcruntime140d.dll"])
            self.assertEqual(missing, [])

    def test_later_directory_wins(self):
        with tempfile.TemporaryDirectory() as one, tempfile.TemporaryDirectory() as two:
            first, second = Path(one), Path(two)
            (first / "vcruntime140d.dll").write_bytes(b"first")
            (second / "vcruntime140d.dll").write_bytes(b"second")

            found, _ = _runtime_dlls(
                ["vcruntime140d.dll"],
                [first, second],
                known=set(),
            )

            self.assertEqual(found["vcruntime140d.dll"], second / "vcruntime140d.dll")

    def test_missing_directory_is_reported(self):
        absent = Path("/nonexistent/petracer-runtime")

        found, missing = _runtime_dlls(["vcruntime140d.dll"], [absent], known=set())

        self.assertEqual(found, {})
        self.assertEqual(missing, [absent])


if __name__ == "__main__":
    unittest.main()
