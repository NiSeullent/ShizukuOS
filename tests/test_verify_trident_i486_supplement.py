#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real frozen CPU proof baseline and isolated fault controls; no native run."""
import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import verify_trident_i486_supplement as gate

MANIFEST_PINS = {
    "trident-script-native-5abe-20261001-v1": "5ee49445c47e45537e7fbc563dea4007b345f6b6469305c5aa76c7c3e65b57eb",
    "trident-automation-native-5abe-20261001-v1": "13eddef2f02f8bfc3a1ba331aaf8fa027e334cff8e7a2a225ddeeab517e46a9a"}


def encoded(value):
    return (json.dumps(value, indent=2, allow_nan=False) + "\n").encode()


class FrozenGuard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.proof_bytes = gate.read(gate.SUPPLEMENT, 1 << 20)
        cls.proof = gate.parse_json(cls.proof_bytes)
        cls.source = gate.read(gate.SUPPLEMENT.parent / "source/tools/i486_instruction_gate.py", 65536)
        cls.policy = gate.historical_policy(cls.source)

    def manifest(self, component="script"):
        name = next(n for n, s in gate.STAGES.items() if s["component"] == component)
        return gate.BOOT_BUILD / name / "guest-files.json", MANIFEST_PINS[name]

    def verify(self, component="script"):
        manifest, digest = self.manifest(component)
        return gate.verify(manifest, digest, gate.SUPPLEMENT, gate.SUPPLEMENT_SHA)

    def altered(self, target, content, manifest_sha=None, repin_proof=False):
        """Inject read faults only; never change approved stages or proof files."""
        real_read = gate.read
        def faulty(path, limit=8 << 20):
            return content if Path(path) == target else real_read(path, limit)
        manifest, original_pin = self.manifest()
        digest = gate.sha(content) if repin_proof else gate.SUPPLEMENT_SHA
        with patch.object(gate, "read", faulty), patch.object(gate, "SUPPLEMENT_SHA", digest):
            return gate.verify(manifest, original_pin if manifest_sha is None else manifest_sha,
                               gate.SUPPLEMENT, digest)

    def test_actual_both_frozen_components(self):
        for component in ("script", "automation"):
            with self.subTest(component=component):
                result = self.verify(component)
                self.assertTrue(result["saved_cpu_provenance_verified"])
                self.assertEqual(len(result["verified_artifacts"]), 6)
                self.assertEqual(len(result["selected_input_sha256"]), 3)
                self.assertEqual(result["historical_source_sha256"], gate.HISTORICAL_SOURCES)
                self.assertEqual(result["stage_provenance_sha256"],
                    result["checked_evidence_sha256"][str(Path(result["manifest"]).parent / "provenance.json")])
                self.assertFalse(result["historical_controls_rerun"])
                for name in ("actual_cpu_execution_verified", "native_execution", "native_styles", "native_paint",
                             "vm_operations", "full_browser", "full_javascript", "full_css", "full_html5",
                             "wasm", "webgpu", "webgl", "modern_apps"):
                    self.assertIs(result[name], False)
                self.assertTrue(result["original_native_verifier_still_required"])

    def test_hard_receipt_pin_and_wrong_paths(self):
        manifest, digest = self.manifest()
        for path, msha, supplement, ssha in (
            (manifest, "0" * 64, gate.SUPPLEMENT, gate.SUPPLEMENT_SHA),
            (manifest, digest, gate.SUPPLEMENT, "0" * 64),
            (manifest, digest, gate.SUPPLEMENT.parent / "another.json", gate.SUPPLEMENT_SHA),
            (manifest.parent / "another.json", digest, gate.SUPPLEMENT, gate.SUPPLEMENT_SHA),
            (manifest.parent / "nested/guest-files.json", digest, gate.SUPPLEMENT, gate.SUPPLEMENT_SHA),
            (Path("guest-files.json"), digest, gate.SUPPLEMENT, gate.SUPPLEMENT_SHA)):
            with self.subTest(path=path, supplement=supplement), self.assertRaises((ValueError, OSError)):
                gate.verify(path, msha, supplement, ssha)
        with self.assertRaises(ValueError):
            self.altered(gate.SUPPLEMENT, self.proof_bytes + b" ")

    def test_reapproved_synthetic_receipt_scope_and_types(self):
        # Test-only pin replacement exercises deeper validation without claiming
        # any changed receipt is an approved historical production receipt.
        changes = [lambda p: p.update(schema=True), lambda p: p.update(passed=1),
                   lambda p: p.update(native_execution=True), lambda p: p.update(modern_apps=0),
                   lambda p: p.update(full_browser=True),
                   lambda p: p["source_sha256"].update({"tools/i486_instruction_gate.py": "6ba89c7a521e6a7b17e18519f27ed3d1f860d3f8e7ed7d9c89302ea960088973"}),
                   lambda p: p["controls"].update(returncode=True),
                   lambda p: p["controls"].update(actual_modern_after_no_operand_cases=True),
                   lambda p: p["controls"].update(log=str(gate.SUPPLEMENT.parent / "other.log")),
                   lambda p: p["controls"].update(command=["python3", "wrong.py"]),
                   lambda p: p["input_sha256"].pop(next(iter(p["input_sha256"]))),
                   lambda p: p["artifacts"].update(extra={})]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                proof = copy.deepcopy(self.proof); change(proof)
                self.altered(gate.SUPPLEMENT, encoded(proof), repin_proof=True)

    def test_reapproved_synthetic_manifest_profile_faults(self):
        manifest, _ = self.manifest()
        plan = gate.parse_json(gate.read(manifest, 65536))
        changes = [lambda p: p.update(schema=True), lambda p: p.update(network_required=True),
            lambda p: p.update(command=gate.PREFIX + "QJS13PR.EXE"),
            lambda p: p.update(outputs=p["outputs"] + [p["outputs"][0]]),
            lambda p: p.update(nonce="bad nonce"),
            lambda p: p["inputs"][0].update(bytes=True),
            lambda p: p["inputs"][0].update(source=str(manifest.parent / "nested/M98QJS.DLL")),
            lambda p: p["inputs"][0].update(sha256="0" * 64),
            lambda p: p["inputs"].append(p["inputs"][0]),
            lambda p: p["source_receipts"][0].update(path=str(manifest.parent / "outside.json"))]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                value = copy.deepcopy(plan); change(value); content = encoded(value)
                self.altered(manifest, content, manifest_sha=gate.sha(content))

    def test_historical_current_stage_prepared_log_and_input_pin_faults(self):
        manifest, _ = self.manifest()
        first = next(iter(self.proof["artifacts"].values()))
        targets = [gate.SUPPLEMENT.parent / "source/tools/i486_instruction_gate.py",
                   gate.SUPPLEMENT.parent / "source/tests/test_i486_instruction_gate.py",
                   gate.SUPPLEMENT.parent / "source/tools/audit_i486_native_inputs.py",
                   Path(self.proof["controls"]["log"]),
                   Path(first["log"]), manifest.parent / "runtime-build.json",
                   manifest.parent / "source/src/m98_trident_script.c",
                   manifest.parent / "runtime-prepared/quickjs/quickjs.c",
                   manifest.parent / "M98QJS.DLL"]
        for path in targets:
            with self.subTest(path=path), self.assertRaises(ValueError):
                original = gate.read(path, 64 << 20)
                self.altered(path, original + b"changed")

    def test_complete_pins_drift_again_before_return(self):
        target = gate.SUPPLEMENT.parent / "source/tools/i486_instruction_gate.py"
        real_read, times = gate.read, 0
        def drift(path, limit=8 << 20):
            nonlocal times
            data = real_read(path, limit)
            if Path(path) == target:
                times += 1
                if times > 1:
                    data += b"drift"
            return data
        with patch.object(gate, "read", drift), self.assertRaisesRegex(ValueError, "drift"):
            self.verify()

    def test_provenance_drift_during_saved_log_replay(self):
        manifest, _ = self.manifest(); target = manifest.parent / "provenance.json"
        real_read, real_decode, replayed = gate.read, gate.decode, False
        def late_read(path, limit=8 << 20):
            data = real_read(path, limit)
            return data + b"late provenance drift" if Path(path) == target and replayed else data
        def replay(*args, **kwargs):
            nonlocal replayed
            result = real_decode(*args, **kwargs); replayed = True
            return result
        with patch.object(gate, "read", late_read), patch.object(gate, "decode", replay), self.assertRaisesRegex(ValueError, "drift"):
            self.verify()
        self.assertTrue(replayed)

    def test_reapproved_synthetic_artifact_metadata(self):
        path = next(iter(self.proof["artifacts"]))
        changes = [lambda a: a.update(instructions_decoded=True),
            lambda a: a.update(artifact_bytes=True), lambda a: a.update(post_i486_families="unknown"),
            lambda a: a.update(parser="old-cross-newline"),
            lambda a: a.update(command=a["command"][:-1] + ["wrong.dll"]),
            lambda a: a.update(log=str(gate.SUPPLEMENT.parent / "4-M98QJS.DLL-disassembly.log")),
            lambda a: a["executable_sections"][".text"].update(bytes=724423),
            lambda a: a["executable_sections"][".text"].update(address=0),
            lambda a: a["executable_sections"].update(extra=dict(a["executable_sections"][".text"]))]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                proof = copy.deepcopy(self.proof); change(proof["artifacts"][path])
                self.altered(gate.SUPPLEMENT, encoded(proof), repin_proof=True)

    def test_json_duplicate_nonfinite_and_nonobject(self):
        for data in (b'{"schema":1,"schema":1}', b'{"nested":{"a":1,"a":2}}',
                     b'{"a":NaN}', b'{"a":Infinity}', b'[]', b'true'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                gate.parse_json(data)

    def test_read_nonregular_symlink_and_limit(self):
        with tempfile.TemporaryDirectory(prefix="m98-cpu-read-controls-") as directory:
            directory = Path(directory)
            regular = directory / "file"; regular.write_bytes(b"regular")
            link = directory / "link"; link.symlink_to(regular)
            for path, limit in ((directory, 100), (link, 100), (regular, 6)):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    gate.read(path, limit)
            self.assertEqual(gate.read(regular, 7), b"regular")
            real_stat, calls = gate.os.fstat, 0
            def changed_stat(fd):
                nonlocal calls
                value = real_stat(fd); calls += 1
                fields = {k: getattr(value, k) for k in ("st_dev", "st_ino", "st_mode", "st_nlink",
                          "st_size", "st_mtime_ns", "st_ctime_ns")}
                if calls == 2:
                    fields["st_ctime_ns"] += 1
                return SimpleNamespace(**fields)
            with patch.object(gate.os, "fstat", changed_stat), self.assertRaisesRegex(ValueError, "changed"):
                gate.read(regular, 7)

    def test_stage_provenance_scope_and_closure_faults(self):
        manifest, _ = self.manifest(); target = manifest.parent / "provenance.json"
        original = gate.parse_json(gate.read(target, 1 << 20))
        for change in (lambda p: p.update(native_execution=True), lambda p: p.update(wasm=0),
                      lambda p: p.update(kind="wrong-stage"),
                      lambda p: p["stage_sha256"].pop("source/src/m98_trident_script.c"),
                      lambda p: p["source_sha256"].pop("src/m98_trident_script.c")):
            with self.subTest(change=change), self.assertRaises(ValueError):
                value = copy.deepcopy(original); change(value)
                self.altered(target, encoded(value))

    def test_cli_rejections_create_no_output(self):
        manifest, digest = self.manifest()
        output = ROOT / "build/trident-i486-intentionally-rejected-control"
        self.assertFalse(output.exists())
        argv = ["verify_trident_i486_supplement.py", "--manifest", str(manifest), "--manifest-sha256", digest,
            "--supplement", str(gate.SUPPLEMENT), "--supplement-sha256", gate.SUPPLEMENT_SHA, "--out", str(output)]
        with patch.object(sys, "argv", argv), patch.object(gate, "verify", side_effect=gate.EvidenceError("deliberate read-only failure")), contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(gate.main(), 1)
        self.assertFalse(output.exists())
        self.assertFalse(json.loads(captured.getvalue())["native_execution"])
        argv[-1] = str(ROOT / "build")
        with patch.object(sys, "argv", argv), contextlib.redirect_stdout(io.StringIO()) as captured:
            self.assertEqual(gate.main(), 1)
        self.assertFalse(json.loads(captured.getvalue())["passed"])

    def synthetic_decode(self, data, body):
        return gate.decode(("Disassembly of section .text:\n" + body + "\n").encode(),
                           {".text": dict(address=0x401000, data=data)}, self.policy)

    def test_synthetic_horizontal_rows_and_valid_prefixes(self):
        self.assertEqual(self.synthetic_decode(b"\x90\xc3", "401000: 90 nop\n401001: c3 ret")["instructions_decoded"], 2)
        self.assertEqual(self.synthetic_decode(b"\xf3\xa5\xc3", "401000: f3 a5 rep movsl\n401002: c3 ret")["instructions_decoded"], 2)
        self.assertNotIn("btl", self.policy["ALLOWED"])
        for predecessor, prefix in (("nop", b"\x90"), ("ret", b"\xc3"), ("fldz", b"\xd9\xee")):
            for modern, opcode in (("mfence", b"\x0f\xae\xf0"), ("vzeroupper", b"\xc5\xf8\x77"),
                                   ("cpuid", b"\x0f\xa2"), ("ud2", b"\x0f\x0b"),
                                   ("mov %cr4,%eax", b"\x0f\x20\xe0")):
                body = f"401000: {prefix.hex(' ')} {predecessor}\n{0x401000+len(prefix):x}: {opcode.hex(' ')} {modern}"
                with self.subTest(predecessor=predecessor, modern=modern), self.assertRaises(ValueError):
                    self.synthetic_decode(prefix + opcode, body)

    def test_synthetic_coverage_row_and_operand_faults(self):
        values = ["401000: 90 nop", "401001: 90 nop\n401002: c3 ret",
            "401000: 91 nop\n401001: c3 ret", "401000: 90 nop\n401000: c3 ret",
            "401000: 90 nop\n401001: c3 .byte 0xc3", "401000: 90 lock\n401001: c3 ret",
            "401000: 90 mov %xmm0,%eax\n401001: c3 ret", "401000: 90 mov %cr4,%eax\n401001: c3 ret",
            "401000: 90 nop\n401001: c3 ret\nDisassembly of section .text:",
            "401000: 90 nop\nDisassembly of section extra:\n401001: c3 ret",
            "401000: 90 nop\n401001: c3 ret\nunparsed instruction-looking garbage",
            "401000: 90 " + "rep " * 16 + "nop\n401001: c3 ret",
            "401000: 90 nop\n401001: ret", "401000: 90 nop\n401001: C3 ret"]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.synthetic_decode(b"\x90\xc3", value)
        with self.assertRaises(ValueError):
            self.synthetic_decode(b"\x90" * 16, "401000: " + "90 " * 16 + "nop")

    def test_actual_saved_disassembly_mutations(self):
        path = next(p for p in self.proof["artifacts"] if p.endswith("M98JSRUN.EXE"))
        artifact = self.proof["artifacts"][path]
        raw = gate.read(Path(artifact["log"]), 1 << 20)
        sections = gate.pe_sections(gate.read(Path(path), 1 << 20))
        self.assertEqual(gate.decode(raw, sections, self.policy, path)["instructions_decoded"], 544)
        for changed in (raw.replace(path.encode(), b"wrong.exe", 1),
                        raw.replace(b"401000:", b"401001:", 1),
                        raw.replace(b"push   %ebp", b"cpuid", 1),
                        raw + b"Disassembly of section .text:\n", raw.rsplit(b"\n", 3)[0]):
            with self.subTest(changed=changed[-60:]), self.assertRaises(ValueError):
                gate.decode(changed, sections, self.policy, path)

    def test_actual_pe_extent_faults(self):
        path = next(p for p in self.proof["artifacts"] if p.endswith("M98JSRUN.EXE"))
        actual = gate.read(Path(path), 1 << 20)
        nt = struct.unpack_from("<I", actual, 0x3c)[0]; optional = nt + 24
        table = optional + struct.unpack_from("<H", actual, nt + 20)[0]
        values = [b"", actual[:63], b"NO" + actual[2:]]
        for offset, fmt, value in ((0x3c, "I", 0xffffffff), (nt+4, "H", 0x8664),
            (nt+6, "H", 0xffff), (optional, "H", 0x20b), (table+8, "I", 0xffffffff),
            (table+12, "I", 0xfffff000), (table+20, "I", len(actual)),
            (optional+28, "I", 0xffffffff)):
            changed = bytearray(actual);struct.pack_into("<"+fmt, changed, offset, value);values.append(bytes(changed))
        # Duplicate raw and virtual extents into a second section.
        changed = bytearray(actual);changed[table+40+8:table+40+24] = changed[table+8:table+24];values.append(bytes(changed))
        # Non-executable COFF long-name references exist in the actual DLL;
        # executable name indirection is outside this frozen decoder profile.
        changed = bytearray(actual);changed[table:table+8] = b"/4\0\0\0\0\0\0";values.append(bytes(changed))
        for value in values:
            with self.subTest(size=len(value)), self.assertRaises((ValueError, UnicodeError, struct.error)):
                gate.pe_sections(value)


if __name__ == "__main__":
    unittest.main()
