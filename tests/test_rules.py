import unittest

from petracer.detect.rules import analyze
from petracer.events import Event
from petracer.pe import PEInfo


def pe(**kw):
    base = dict(
        path="sample.exe",
        size=1234,
        sha256="0" * 64,
        machine=0x8664,
        arch="x86_64",
        subsystem=3,
        subsystem_name="console",
        timestamp=0,
        entrypoint=0x1000,
        image_base=0x140000000,
    )
    base.update(kw)
    return PEInfo(**base)


def ev(type_, pid=100, origin="sample", **data):
    return Event(ts=1.0, source="agent", type=type_, pid=pid, origin=origin, data=data)


class RuleTests(unittest.TestCase):
    def test_clean_sample(self):
        events = [
            ev("file.create", path="C:\\sandbox_hello.txt"),
            ev("file.write", path="C:\\sandbox_hello.txt", size=5),
            ev("sleep", ms=500),
            Event.sandbox("sandbox.exit", code=0),
        ]
        result = analyze(events, pe())
        self.assertEqual(result.verdict, "clean")
        self.assertEqual(result.findings, [])

    def test_process_injection(self):
        events = [
            ev("process.open", target_pid=200, access="0x1fffff"),
            ev("mem.alloc", target_pid=200, base="0x0", size=4096, protect="0x40"),
            ev("mem.write", target_pid=200, base="0xaf0000", size=512),
            ev("thread.create", target_pid=200, start="0xaf0000"),
        ]
        result = analyze(events, pe())
        ids = {f.rule_id for f in result.findings}
        self.assertIn("process_injection", ids)
        self.assertIn("remote_rwx", ids)
        self.assertEqual(result.verdict, "malicious")

    def test_persistence(self):
        events = [
            ev("reg.setvalue",
               path="\\REGISTRY\\User\\S-1-5-21-0-0-0-1000\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
               name="x", value_type=1, size=20)
        ]
        result = analyze(events, pe())
        self.assertEqual([f.rule_id for f in result.findings], ["persistence_run_key"])
        self.assertEqual(result.verdict, "suspicious")

    def test_dropper(self):
        events = [
            ev("file.create", path="C:\\users\\user\\Temp\\payload.exe"),
            ev("process.create", image="C:\\users\\user\\Temp\\payload.exe", cmdline="payload.exe"),
        ]
        result = analyze(events, pe())
        self.assertIn("dropper", {f.rule_id for f in result.findings})

    def test_network(self):
        result = analyze([ev("net.connect", address="1.2.3.4", port=80)], pe())
        self.assertIn("network_activity", {f.rule_id for f in result.findings})
        self.assertEqual(result.verdict, "suspicious")

    def test_direct_syscall_static(self):
        result = analyze([], pe(syscall_count=3))
        self.assertIn("direct_syscall", {f.rule_id for f in result.findings})
        self.assertEqual(result.verdict, "suspicious")

    def test_anti_debug_and_long_sleep(self):
        events = [
            ev("proc.query", class_=7),
            ev("thread.setinfo", class_=0x11),
            ev("sleep", ms=90000),
        ]
        # "class" is a JSON key; build the event data directly
        events[0].data = {"class": 7}
        events[1].data = {"class": 17}
        result = analyze(events, pe())
        ids = {f.rule_id for f in result.findings}
        self.assertIn("anti_debug", ids)
        self.assertIn("long_sleep", ids)

    def test_driver_load(self):
        result = analyze([ev("driver.load", path="C:\\evil.sys")], pe())
        self.assertIn("driver_load", {f.rule_id for f in result.findings})
        self.assertEqual(result.verdict, "malicious")


if __name__ == "__main__":
    unittest.main()
