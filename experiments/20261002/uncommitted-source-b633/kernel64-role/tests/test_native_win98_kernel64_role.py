#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host role-binding controls using exact production helper/body source slices.

The builder main is never called. Its argument/input prefix is extracted into
a differently named test function, stopping before validate-only/build/output.
Small synthetic disk/ROM/kernel fixtures prove the role gate, not bootability,
compiler provenance, authenticated signatures, or native Windows acceptance.

An already-patched current source can be checked directly with --phase green
--source /path/to/patched/build.py --source-sha256 its_exact_SHA256 and a fresh
--fixture-root, under the caller's resource admission. This verifies the supplied
current source bytes before/after; it does not apply a patch or run builder main.
"""
import argparse
import ast
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest


def digest(data):
    return hashlib.sha256(data).hexdigest()


def production_slices(source):
    tree = ast.parse(source)
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    main = functions["main"]
    stop = next(n for n in main.body if isinstance(n, ast.If) and
                isinstance(n.test, ast.Attribute) and n.test.attr == "validate_only")
    lines = source.splitlines(keepends=True)
    prefix = "".join(lines[main.lineno - 1:stop.lineno - 1])
    names = ("safe_path", "stable", "pin_format", "pinned_hash", "read_leased",
             "config_bytes", "validate_config", "validate_contents",
             "unique_json_object", "validate_kernel64_role")
    pieces = []
    for name in names:
        if name in functions:
            node = functions[name]
            begin = min([node.lineno, *[n.lineno for n in node.decorator_list]])
            pieces.append("".join(lines[begin - 1:node.end_lineno]))
    imports = [ast.get_source_segment(source, n) for n in tree.body
               if isinstance(n, (ast.Import, ast.ImportFrom))]
    # Only the generated wrapper name and final return differ from production.
    body = prefix.split("\n", 1)[1]
    wrapper = "def extracted_argument_prefix(argv=None):\n" + body + "    return inputs\n"
    program = "\n".join(imports + pieces) + "\n" + wrapper
    namespace = {"__doc__": "production prefix host test", "__file__": __file__,
                 "DISK_BYTES": 512, "ROM_BYTES": 256,
                 "CONFIG": (0x38395753, 1, 128, 0)}
    exec(compile(program, "<exact-production-slices>", "exec"), namespace)
    # Geometry scaling is confined to synthetic container fixtures. Kernel role
    # records, strict JSON decoding, SHA checks and leases use production code.
    namespace.update(DISK_BYTES=512, ROM_BYTES=256,
                     CONFIG=(0x38395753, 1, 128, 0))
    metadata = {"production_sha256": digest(source.encode()),
                "argument_prefix_sha256": digest(prefix.encode()),
                "helper_sha256": {name: digest(ast.get_source_segment(source, functions[name]).encode())
                                  for name in names if name in functions},
                "full_builder_main_executed": False,
                "synthetic_disk_bytes": 512, "synthetic_ROM_bytes": 256}
    return namespace, metadata, tree


class RoleControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code, cls.metadata, cls.tree = production_slices(cls.source_bytes.decode())
        print("PRODUCTION_SLICES " + json.dumps(cls.metadata, sort_keys=True), flush=True)

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix="case-", dir=self.fixture_root))
        disk = bytearray(512); disk[-2:] = b"\x55\xaa"
        rom = bytearray(256); rom[8:15] = b"SeaBIOS"; rom[-16] = 0xEA
        self.data = {"disk": bytes(disk), "rom": bytes(rom),
                     "config": self.code["config_bytes"](),
                     "supervisor": b"synthetic Supervisor Kernel64 role\x00",
                     "standalone": b"synthetic standalone Kernel64 SHZ-EXIT:\x00"}
        self.paths = {}
        for name, data in self.data.items():
            p = self.work / (name + ".bin"); p.write_bytes(data); self.paths[name] = p
        self.document = {"built_utc": "2026-10-01T00:00:00Z",
                         "kernel64_machine": "EM_X86_64 ELF64", "kernels": {
                         "kernel64": {"sha256": digest(self.data["supervisor"]),
                                      "bytes": len(self.data["supervisor"])},
                         "kernel64-standalone": {"sha256": digest(self.data["standalone"]),
                                                 "bytes": len(self.data["standalone"])}}}
        self.receipt = self.work / "kernels-build-result.json"
        self.write_receipt(self.document)

    def write_receipt(self, document=None, raw=None):
        self.receipt.write_bytes(raw if raw is not None else json.dumps(document).encode())
        self.receipt_pin = digest(self.receipt.read_bytes())

    def argv(self, role="supervisor", include_receipt=True):
        args = []
        for name in ("disk", "rom", "config"):
            args += ["--" + name, str(self.paths[name]), "--" + name + "-sha256", digest(self.data[name])]
        if role is not None:
            args += ["--kernel64", str(self.paths[role]), "--kernel64-sha256", digest(self.data[role])]
        if include_receipt:
            args += ["--kernel-build-receipt", str(self.receipt),
                     "--kernel-build-receipt-sha256", self.receipt_pin]
        args += ["--validate-only"]
        return args

    def prefix(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return self.code["extracted_argument_prefix"](args)

    def reject(self, args):
        with self.assertRaises((ValueError, SystemExit)):
            self.prefix(args)

    def test_standalone_input_is_rejected(self):
        args = self.argv("standalone", include_receipt=self.phase == "green")
        try:
            admitted = self.prefix(args)
        except (ValueError, SystemExit):
            return
        print("ORIGINAL_WRONG_ROLE_ADMITTED " + json.dumps({
            "input_role": "synthetic standalone", "mapped_member": "KERNEL64.BIN",
            "sha256": admitted["KERNEL64.BIN"]["sha256"],
            "bytes": admitted["KERNEL64.BIN"]["bytes"],
            "builder_main_executed": False}, sort_keys=True), flush=True)
        self.fail("production input prefix admitted standalone bytes as Supervisor KERNEL64.BIN")

    def test_supervisor_input_is_accepted(self):
        got = self.prefix(self.argv())
        self.assertEqual(got["KERNEL64.BIN"]["sha256"], digest(self.data["supervisor"]))
        self.assertEqual(got["KERNEL64.BIN"]["bytes"], len(self.data["supervisor"]))

    def test_no_kernel_requires_no_new_options(self):
        self.assertNotIn("KERNEL64.BIN", self.prefix(self.argv(None, False)))

    def test_orphan_receipt_options_reject(self):
        for extra in (["--kernel-build-receipt", str(self.receipt)],
                      ["--kernel-build-receipt-sha256", self.receipt_pin],
                      ["--kernel-build-receipt", str(self.receipt),
                       "--kernel-build-receipt-sha256", self.receipt_pin]):
            with self.subTest(extra=extra): self.reject(self.argv(None, False) + extra)

    def test_kernel_requires_complete_explicit_receipt_pair(self):
        for extra in ([], ["--kernel-build-receipt", str(self.receipt)],
                      ["--kernel-build-receipt-sha256", self.receipt_pin]):
            with self.subTest(extra=extra): self.reject(self.argv(include_receipt=False) + extra)

    def test_unpinned_receipt_content_rejects(self):
        args = self.argv(); self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
        self.reject(args)

    def test_missing_receipt_file_rejects(self):
        args = self.argv(); self.receipt.rename(self.work / "preserved-receipt.json")
        with self.assertRaises((ValueError, OSError, SystemExit)): self.prefix(args)

    def test_malformed_json_rejects(self):
        for raw in (b"{", b"null", b"[]", b"NaN"):
            with self.subTest(raw=raw):
                self.write_receipt(raw=raw); self.reject(self.argv())

    def test_duplicate_keys_reject(self):
        good = json.dumps(self.document["kernels"]["kernel64"]).encode()
        for raw in (b'{"kernels":{},"kernels":{"kernel64":' + good + b'}}',
                    b'{"kernels":{"kernel64":' + good + b',"kernel64":' + good + b'}}',
                    b'{"kernels":{"kernel64":{"sha256":"' + digest(self.data["supervisor"]).encode() +
                    b'","bytes":1,"bytes":' + str(len(self.data["supervisor"])).encode() + b'}}}'):
            with self.subTest(raw=raw): self.write_receipt(raw=raw); self.reject(self.argv())

    def test_missing_or_wrong_schema_rejects(self):
        for document in ({}, {"kernels": []}, {"kernels": {}},
                         {"kernels": {"kernel64-standalone": self.document["kernels"]["kernel64"]}},
                         {"kernels": {"kernel64": []}}, {"kernels": {"kernel64": {}}}):
            with self.subTest(document=document): self.write_receipt(document); self.reject(self.argv())

    def test_receipt_digest_mismatch_rejects(self):
        self.document["kernels"]["kernel64"]["sha256"] = "0" * 64
        self.write_receipt(self.document); self.reject(self.argv())

    def test_receipt_size_mismatch_rejects(self):
        self.document["kernels"]["kernel64"]["bytes"] += 1
        self.write_receipt(self.document); self.reject(self.argv())

    def test_invalid_digest_types_or_format_reject(self):
        for value in (None, 123, "bad", "g" * 64):
            with self.subTest(value=value):
                self.document["kernels"]["kernel64"]["sha256"] = value
                self.write_receipt(self.document); self.reject(self.argv())

    def test_invalid_size_types_and_bounds_reject(self):
        for value in (True, False, "34", None, -1, 0, 16 * 1024**2 + 1):
            with self.subTest(value=value):
                self.document["kernels"]["kernel64"]["bytes"] = value
                self.write_receipt(self.document); self.reject(self.argv())

    def test_invalid_explicit_receipt_pin_rejects(self):
        for value in ("", "bad", "g" * 64, "0" * 64):
            with self.subTest(value=value):
                args = self.argv(); args[args.index("--kernel-build-receipt-sha256") + 1] = value
                self.reject(args)

    def test_recheck_rejects_later_receipt_drift(self):
        item = self.prefix(self.argv())["KERNEL64.BIN"]
        gate = self.code["validate_kernel64_role"]
        before = gate(item, self.receipt, self.receipt_pin)
        self.assertEqual(before["kernel64"]["sha256"], item["sha256"])
        original_pin = self.receipt_pin
        self.receipt.write_bytes(self.receipt.read_bytes() + b" ")
        with self.assertRaises(ValueError): gate(item, self.receipt, original_pin)

    def test_make_config_rejects_receipt_options_before_writing(self):
        for flag, value in (("--kernel-build-receipt", str(self.receipt)),
                            ("--kernel-build-receipt-sha256", self.receipt_pin)):
            target = self.work / (flag[2:] + ".config")
            self.reject(["--make-config", str(target), flag, value])
            self.assertFalse(target.exists())

    def test_all_three_production_gate_call_sites_exist(self):
        main = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        calls = [n for n in ast.walk(main) if isinstance(n, ast.Call) and
                 isinstance(n.func, ast.Name) and n.func.id == "validate_kernel64_role"]
        self.assertEqual(len(calls), 3)
        validate_only = next(n for n in main.body if isinstance(n, ast.If) and
                             isinstance(n.test, ast.Attribute) and n.test.attr == "validate_only")
        copying = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and
                       isinstance(n.func, ast.Name) and n.func.id == "copy_fd")
        publish = next(n for n in ast.walk(main) if isinstance(n, ast.Call) and
                       isinstance(n.func, ast.Attribute) and n.func.attr == "update" and
                       any(k.arg == "status" for k in n.keywords))
        sites = sorted(n.lineno for n in calls)
        self.assertLess(sites[0], validate_only.lineno)
        self.assertLess(sites[1], copying.lineno)
        self.assertGreater(sites[2], copying.lineno)
        self.assertLess(sites[2], publish.lineno)

    def test_actual_builder_receipt_expression_serializes_role_binding(self):
        main = next(n for n in self.tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
        assignment = next(n for n in main.body if isinstance(n, ast.Assign) and
                          any(isinstance(t, ast.Name) and t.id == "receipt" for t in n.targets))
        expression = ast.Expression(body=assignment.value)
        for enabled in (False, True):
            with self.subTest(kernel_present=enabled):
                inputs = self.prefix(self.argv("supervisor" if enabled else None, enabled))
                binding = (self.code["validate_kernel64_role"](inputs["KERNEL64.BIN"], self.receipt,
                           self.receipt_pin) if enabled else None)
                environment = {**self.code, "inputs": inputs, "kernel_receipt": binding,
                               "budget": 0, "RESERVE": 17 << 30}
                # This is the exact production initial receipt expression; no
                # builder output, copy loop, compiler or VM branch executes.
                actual = eval(compile(expression, "<production-receipt-expression>", "eval"), environment)
                serialized = json.loads(json.dumps(actual))
                expected = ({"path": str(self.receipt), "sha256": self.receipt_pin,
                             "bytes": self.receipt.stat().st_size,
                             "kernel64": self.document["kernels"]["kernel64"]} if enabled else None)
                self.assertEqual(serialized["kernel64_role_binding"], expected)
                self.assertFalse(serialized["VM_executed"])
                self.assertFalse(serialized["native_Win64_app_verified"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--phase", choices=("red", "green"), required=True)
    args = parser.parse_args()
    RoleControls.source, RoleControls.fixture_root, RoleControls.phase = args.source, args.fixture_root, args.phase
    RoleControls.source_bytes = args.source.read_bytes()
    if digest(RoleControls.source_bytes) != args.source_sha256:
        raise SystemExit("explicit source byte pin differs")
    args.fixture_root.mkdir()
    suite = (unittest.TestSuite([RoleControls("test_standalone_input_is_rejected")]) if args.phase == "red"
             else unittest.defaultTestLoader.loadTestsFromTestCase(RoleControls))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if digest(args.source.read_bytes()) != args.source_sha256:
        raise SystemExit("source byte pin changed after host controls")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
