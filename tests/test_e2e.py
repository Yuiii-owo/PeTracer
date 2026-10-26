import contextlib
import io
import os
import shutil
import unittest
from pathlib import Path

from petracer import build
from petracer.detect.rules import analyze
from petracer.sandbox import SandboxConfig, run_sample
from petracer.trace import TracePrinter

ROOT = Path(__file__).resolve().parent.parent
E2E = os.environ.get("PETRACER_E2E") == "1"


@unittest.skipUnless(E2E, "set PETRACER_E2E=1 to run the Wine sandbox end-to-end")
@unittest.skipUnless(shutil.which("wine") and shutil.which("bwrap") and shutil.which(build.CC64),
                     "wine/bwrap/mingw required")
class EndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = ROOT / "build" / "e2e"
        cls.out.mkdir(parents=True, exist_ok=True)
        cls.samples = build.build_samples(ROOT / "samples", cls.out / "bin", verbose=False)

    def test_hello_clean(self):
        result = run_sample(
            SandboxConfig(sample=self.samples["hello"], out_dir=self.out / "hello", timeout=20, verbose=False)
        )
        self.assertTrue(result.agent_ready)
        analysis = analyze(result.events, result.pe, result.meta)
        self.assertEqual(analysis.verdict, "clean")

    def test_trace_hello(self):
        printer = TracePrinter(color=False, no_crt=True)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = run_sample(
                SandboxConfig(
                    sample=self.samples["hello"],
                    out_dir=self.out / "trace",
                    timeout=20,
                    trace_imports=True,
                    on_agent_event=printer,
                    verbose=False,
                )
            )
        self.assertTrue(result.agent_ready)
        out = buf.getvalue()
        self.assertIn("IMPORT  CreateFileW", out)
        self.assertIn("SYSCALL NtCreateFile", out)
        self.assertLess(out.index("IMPORT  CreateFileW"), out.index("SYSCALL NtCreateFile"))

    def test_inject_detected(self):
        result = run_sample(
            SandboxConfig(sample=self.samples["inject"], out_dir=self.out / "inject", timeout=25, verbose=False)
        )
        analysis = analyze(result.events, result.pe, result.meta)
        self.assertIn("process_injection", {f.rule_id for f in analysis.findings})


if __name__ == "__main__":
    unittest.main()
