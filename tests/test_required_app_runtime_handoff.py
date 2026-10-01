"""Complete-package, freshness, architecture and sealed-runtime evidence boundaries."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("required_handoff", ROOT / "tools/required_app_runtime_handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


def executable():
    data = bytearray(1024)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 132, 0x8664, 1, 0, 0, 0, 240, 0x102)
    struct.pack_into("<H", data, 152, 0x20b)
    struct.pack_into("<II", data, 208, 8192, 512)
    struct.pack_into("<H", data, 220, 2)
    struct.pack_into("<I", data, 260, 16)
    data[392:400] = b".text\0\0\0"
    struct.pack_into("<IIII", data, 400, 512, 4096, 512, 512)
    return bytes(data)


class PackageCase(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.files = {"DesktopEditors.exe": executable(), "assets/language.json": b'{"ko":"Korean"}',
                      "resources/html/local.html": b"<p>real local asset</p>", "empty.dat": b""}
        self.archive = self.folder / "publisher.zip"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in self.files.items():
                archive.writestr(name, data)
        archive_bytes = self.archive.read_bytes()
        self.pin = {"architecture": "x64", "version": "9.4.0", "entry_point": "DesktopEditors.exe",
                    "bytes": len(archive_bytes), "algorithm": "sha256", "encoding": "hex",
                    "digest": hashlib.sha256(archive_bytes).hexdigest()}
        self.inventory = {"schema": 1, "status": "PASS", "app": "onlyoffice_x64", "publisher_pin": self.pin,
                          "artifact": {"path": str(self.archive), "bytes": len(archive_bytes),
                                       "sha256": self.pin["digest"], "publisher_digest_verified": True},
                          "entry_point": "DesktopEditors.exe", "archive_members": len(self.files),
                          "declared_expanded_bytes": sum(map(len, self.files.values())),
                          "native_files": [{"path": "DesktopEditors.exe", "bytes": len(executable()),
                                            "sha256": hashlib.sha256(executable()).hexdigest(),
                                            "architecture": "x64", "format": "PE32+"}]}
        self.inventory_path = self.folder / "inventory.json"
        self.inventory_path.write_text(json.dumps(self.inventory))
        self.tree, self.receipt = self.folder / "application", self.folder / "prepared.json"
        self.pin_patch = patch.dict(handoff.corpus.PINS, {"onlyoffice_x64": self.pin})
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)

    def prepare(self):
        with patch.object(handoff, "check_space"):
            return handoff.prepare("onlyoffice_x64", self.archive, self.inventory_path, self.tree, self.receipt)

    def test_complete_package_keeps_assets_empty_files_and_native_content(self):
        result = self.prepare()
        self.assertEqual({p.relative_to(self.tree).as_posix(): p.read_bytes() for p in self.tree.rglob("*") if p.is_file()}, self.files)
        self.assertEqual(len(result["members"]), len(self.files))
        self.assertFalse(result["payload_executed"])
        self.assertFalse(result["app_functionality_verified"])
        self.assertEqual(handoff.verified_tree(self.receipt)[0], result)

    def test_ia32_rejection_precedes_tree_creation_and_disk_gate(self):
        self.inventory["app"] = "onlyoffice"
        self.inventory["publisher_pin"] = handoff.corpus.PINS["onlyoffice"]
        self.inventory_path.write_text(json.dumps(self.inventory))
        with patch.object(handoff, "check_space") as space, self.assertRaisesRegex(handoff.HandoffError, "AMD64"):
            handoff.prepare("onlyoffice", self.archive, self.inventory_path, self.tree, self.receipt)
        space.assert_not_called()
        self.assertFalse(self.tree.exists())
        self.assertFalse(self.receipt.exists())

    def test_forged_native_digest_cannot_publish_a_prepared_tree(self):
        self.inventory["native_files"][0]["sha256"] = "0" * 64
        self.inventory_path.write_text(json.dumps(self.inventory))
        with self.assertRaisesRegex(handoff.HandoffError, "native member"):
            self.prepare()
        self.assertFalse(self.tree.exists())
        self.assertFalse(self.receipt.exists())
        self.assertFalse(list(self.folder.glob(".required-app-*")))

    def test_archive_extent_mismatch_is_rejected_before_extracting_members(self):
        self.inventory["declared_expanded_bytes"] = 1
        self.inventory_path.write_text(json.dumps(self.inventory))
        with patch.object(handoff, "extract_zip") as extraction, self.assertRaisesRegex(handoff.HandoffError, "listing differs"):
            self.prepare()
        extraction.assert_not_called()
        self.assertFalse(self.tree.exists())

    def test_publisher_digest_failure_does_not_publish_tree(self):
        content = bytearray(self.archive.read_bytes())
        content[-1] ^= 1
        self.archive.write_bytes(content)
        with self.assertRaises(handoff.corpus.CorpusError):
            self.prepare()
        self.assertFalse(self.tree.exists())
        self.assertFalse(self.receipt.exists())

    def test_same_size_asset_change_invalidates_receipt(self):
        self.prepare()
        path = self.tree / "assets/language.json"
        data = path.read_bytes()
        path.write_bytes(b"X" + data[1:])
        with self.assertRaisesRegex(handoff.HandoffError, "tree changed"):
            handoff.verified_tree(self.receipt)

    def test_added_member_and_symlink_invalidate_receipt(self):
        self.prepare()
        path = self.tree / "injected.txt"
        path.write_bytes(b"extra")
        with self.assertRaisesRegex(handoff.HandoffError, "tree changed"):
            handoff.verified_tree(self.receipt)
        path.unlink()
        path.symlink_to(self.tree / "DesktopEditors.exe")
        with self.assertRaisesRegex(handoff.HandoffError, "link"):
            handoff.verified_tree(self.receipt)

    def test_source_change_requires_new_preparation(self):
        self.prepare()
        with patch.object(handoff, "source_hashes", return_value={"changed": "0" * 64}), self.assertRaisesRegex(handoff.HandoffError, "source changed"):
            handoff.verified_tree(self.receipt)

    def test_output_reuse_never_overwrites_existing_payload(self):
        self.tree.mkdir()
        sentinel = self.tree / "do-not-replace"
        sentinel.write_bytes(b"retained")
        with self.assertRaisesRegex(handoff.HandoffError, "new tree"):
            self.prepare()
        self.assertEqual(sentinel.read_bytes(), b"retained")

    def test_image_stage_reuses_generic_builder_and_seals_actual_control(self):
        self.prepare()
        runner = SimpleNamespace()
        calls = []
        def original_builder(image, tree, volume, overlay=None):
            calls.append((tree, volume, overlay))
            image.write_bytes(b"private FAT32 fixture")
            Path(str(image) + ".json").write_text('{"key":"fixture"}')
            return [(row["path"], row["bytes"]) for row in handoff.tree_manifest(tree)[0]]
        runner.build_image = original_builder
        def put_file(image, data, name, folder):
            self.assertEqual(name, "K64RUN.TXT")
            with image.open("ab") as output:
                output.write(data)
        runner.put_file = put_file
        # Model the already-read peer content wrapper, not a replacement image writer.
        def product_builder(image, tree, volume, original):
            return original(image, tree, volume)
        productivity = SimpleNamespace(runner=runner, build_product_image=product_builder)
        peer = self.folder / "peer"
        for name in handoff.PEER_FILES:
            path = peer / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture peer " + name).encode())
        hashes = {name: handoff.digest_file(peer / name) for name in handoff.PEER_FILES}
        image, image_receipt = self.folder / "owned.img", self.folder / "image.json"
        with patch.object(handoff, "load_peer", return_value=(productivity, hashes)), patch.object(handoff, "check_space"), patch.object(handoff.shutil, "which", return_value="/fixture/tool"):
            result = handoff.build_image(self.receipt, peer, image, image_receipt, 60)
        self.assertEqual(calls, [(self.tree, "onlyoffice", None)])
        self.assertEqual(result["image"]["sha256"], handoff.digest_file(image))
        self.assertIn(b"image=D:\\onlyoffice\\DesktopEditors.exe\r\n", image.read_bytes())
        self.assertIn(b"cmdline=DesktopEditors.exe \r\n", image.read_bytes())
        self.assertFalse(result["payload_executed"])
        self.assertFalse(result["windows98_execution_verified"])

    def test_run_consumes_sealed_control_preserves_inputs_and_never_calls_startup_a_pass(self):
        prepared = self.prepare()
        image = self.folder / "sealed.img"
        image.write_bytes(b"unchanged private image fixture")
        peer = self.folder / "runtime"
        for name in handoff.PEER_FILES:
            path = peer / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("fixture " + name).encode())
        hashes = {name: handoff.digest_file(peer / name) for name in handoff.PEER_FILES}
        k64, win64 = peer / "build/kernel64s", peer / "build/win64"
        for path in (k64 / "boot.elf", k64 / "KERNEL64S.BIN", win64 / "WIN64.IMG"):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"immutable runtime fixture")
        qemu = self.folder / "qemu-fixture"
        qemu.write_bytes(b"never executed")
        spec, control = handoff.runtime_spec("onlyoffice_x64", "DesktopEditors.exe", 60)
        image_receipt = self.folder / "image.json"
        handoff.write_json(image_receipt, {"schema": 1, "status": "PREPARED", "stage": "standalone-kernel64-image",
                                         "app": "onlyoffice_x64", "source_hashes": handoff.source_hashes(),
                                         "prepared_receipt": {"path": str(self.receipt), "sha256": handoff.digest_file(self.receipt)},
                                         "image": {"path": str(image), "bytes": image.stat().st_size, "sha256": handoff.digest_file(image)},
                                         "runtime_worktree": str(peer), "runtime_source_hashes": hashes,
                                         "spec": spec, "guest_timeout": 60, "control_base64": base64.b64encode(control).decode()})
        original = lambda *args, **kwargs: self.fail("unsealed original writer was called")
        runner = SimpleNamespace(K64S=k64, WIN64=win64, APPS={}, find_exe=original, classify=original,
                                 build_image=original, put_file=original, __file__=str(peer / handoff.PEER_FILES[1]))
        out = self.folder / "run"
        def fake_main():
            active = runner.APPS["required_onlyoffice_x64"]
            self.assertEqual(runner.find_exe(self.tree, active["exe"]), "DesktopEditors.exe")
            runner.build_image(image, self.tree, active["dir"])
            runner.put_file(image, b"image=D:\\onlyoffice\\DesktopEditors.exe\r\ncmdline=DesktopEditors.exe \r\ncwd=D:\\onlyoffice\r\ntimeout=60\r\n", "K64RUN.TXT", out)
            with self.assertRaises(handoff.HandoffError):
                runner.put_file(image, b"injected control", "K64RUN.TXT", out)
            out.mkdir(exist_ok=True)
            (out / "result.json").write_text('{"status":"PASS","exit_code":0}')
            return 0
        runner.main = fake_main
        runner.shzlib = SimpleNamespace(write_json=lambda path, value: path.write_text(json.dumps(value)))
        productivity = SimpleNamespace(runner=runner, classify_product=lambda *args: {})
        with patch.object(handoff, "load_peer", return_value=(productivity, hashes)), patch.object(handoff, "check_space"):
            code = handoff.run_image(image_receipt, out, qemu, "kvm", 90, 4096)
        result = json.loads((out / "result.json").read_text())
        self.assertEqual(code, 1)
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["app_functionality_verified"])
        self.assertFalse(result["windows98_execution_verified"])
        self.assertTrue(result["tree_preserved"])
        self.assertTrue(result["image_preserved"])
        self.assertTrue(result["runtime_inputs_preserved"])
        self.assertTrue(result["sealed_runtime_inputs_preserved"])
        self.assertEqual(result["resource_guard"]["reserve_bytes"], 20 * handoff.GIB)
        self.assertTrue(result["runtime_sources_preserved"])
        self.assertEqual(set(result["runtime_input_hashes"]), {"boot_stub", "kernel", "win64_initrd", "qemu"})
        self.assertEqual(runner.APPS, {})
        self.assertIs(runner.put_file, original)

    def test_sealed_runtime_copy_survives_peer_rebuild_and_rejects_special_input(self):
        source = self.folder / "shared-kernel"
        source.write_bytes(b"frozen kernel content")
        with patch.object(handoff, "check_space"):
            sealed = handoff.seal_runtime_inputs({"kernel": source}, self.folder / "sealed")
        source.write_bytes(b"new peer kernel version")
        copy = Path(sealed["kernel"]["path"])
        self.assertEqual(copy.read_bytes(), b"frozen kernel content")
        self.assertEqual(handoff.digest_file(copy), sealed["kernel"]["sha256"])
        self.assertNotEqual(handoff.digest_file(source), sealed["kernel"]["sha256"])
        fifo = self.folder / "fifo"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(handoff.HandoffError, "regular file"):
            handoff.seal_runtime_inputs({"kernel": fifo}, self.folder / "rejected")


class ResourceGuard(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.qemu = self.folder / "fixture-qemu"
        self.qemu.write_bytes(b"never executed")
        self.out = self.folder / "run"
        self.out.mkdir()
        self.guard = handoff.GuardedSubprocess(self.qemu, self.out)
        self.addCleanup(self.guard.close)

    def test_unlinked_owned_snapshot_is_counted_without_counting_other_descriptors(self):
        path = self.guard.snapshot / "snapshot"
        unrelated = self.folder / "unrelated"
        with path.open("wb+") as stream, unrelated.open("wb+") as other:
            stream.write(b"X" * 8192)
            stream.flush()
            expected = os.fstat(stream.fileno()).st_blocks * 512
            other.write(b"Y" * 16384)
            other.flush()
            path.unlink()
            self.assertGreater(expected, 0)
            self.assertEqual(self.guard.written_bytes(os.getpid()), (expected, 0))

    def test_live_reserve_guard_stops_only_its_child_and_pins_snapshot_directory(self):
        child = SimpleNamespace(pid=os.getpid(), returncode=None, killed=False)
        child.poll = lambda: child.returncode
        def kill():
            child.killed = True
            child.returncode = -9
        child.kill = kill
        child.wait = lambda **kwargs: child.returncode
        captured = {}
        def popen(command, **kwargs):
            captured.update(kwargs)
            return child
        with patch.object(handoff, "check_space"), patch.object(handoff.subprocess, "Popen", side_effect=popen):
            proc = self.guard.Popen([str(self.qemu)], stdout=handoff.subprocess.PIPE)
        self.assertEqual(captured["env"]["TMPDIR"], str(self.guard.snapshot))
        self.assertIs(captured["stdout"], self.guard.output)
        with patch.object(handoff.shutil, "disk_usage", return_value=SimpleNamespace(free=handoff.RESERVE - 1)):
            self.assertEqual(proc.wait(timeout=1), -9)
        self.assertTrue(child.killed)
        self.assertEqual(self.guard.record["termination_reason"], "disk reserve crossed")
        with self.assertRaisesRegex(handoff.HandoffError, "additional child"):
            self.guard.Popen([str(self.qemu)])

    def test_live_write_guard_stops_snapshot_growth_above_reserved_budget(self):
        child = SimpleNamespace(pid=os.getpid(), returncode=None, killed=False)
        child.poll = lambda: child.returncode
        def kill():
            child.killed = True
            child.returncode = -9
        child.kill = kill
        child.wait = lambda **kwargs: child.returncode
        with patch.object(handoff, "check_space"), patch.object(handoff.subprocess, "Popen", return_value=child):
            proc = self.guard.Popen([str(self.qemu)])
        with patch.object(self.guard, "written_bytes", return_value=(handoff.RUN_WRITE_BUDGET + 1, 0)), patch.object(handoff.shutil, "disk_usage", return_value=SimpleNamespace(free=25 * handoff.GIB)):
            self.assertEqual(proc.wait(timeout=1), -9)
        self.assertTrue(child.killed)
        self.assertEqual(self.guard.record["termination_reason"], "guest write budget crossed")

    def test_signal_extraction_reaps_only_its_child_when_live_floor_is_crossed(self):
        child = SimpleNamespace(returncode=None, killed=False)
        child.poll = lambda: child.returncode
        def kill():
            child.killed = True
            child.returncode = -9
        child.kill = kill
        child.wait = lambda **kwargs: child.returncode
        with patch.object(handoff, "check_space", side_effect=[None, handoff.HandoffError("reserve crossed")]), patch.object(handoff.subprocess, "Popen", return_value=child):
            with self.assertRaisesRegex(handoff.HandoffError, "reserve crossed"):
                handoff.extract_signal(self.qemu, self.folder / "archive", self.out)
        self.assertTrue(child.killed)
        self.assertEqual(child.returncode, -9)


class ContractBoundaries(unittest.TestCase):
    def test_extraction_budget_accounts_for_aligned_files_and_all_parent_directories(self):
        entries = [{"name": "resources/local/a", "bytes": 1}, {"name": "resources/local/b", "bytes": 8193}]
        with patch.object(handoff.os, "statvfs", return_value=SimpleNamespace(f_frsize=4096)):
            self.assertEqual(handoff.extraction_budget(entries, Path("/")), 4096 + 12288 + 3 * 4096)

    def test_parent_case_alias_and_file_directory_collision_are_rejected(self):
        for names in (("Resources/a", "resources/b"), ("a", "a/b"), ("a/b", "a"), ("a/file", "A/other")):
            with self.subTest(names=names), self.assertRaises(handoff.HandoffError):
                handoff.validate_layout([{"name": name, "bytes": 1} for name in names])

    def test_long_fat_component_and_traversal_rejected(self):
        for name in ("x" * 256, "../Signal.exe", "a:b", "a/SIGNAL.exe."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                handoff.validate_layout([{"name": name, "bytes": 0}])

    def test_runtime_control_matches_actual_existing_runner_contract(self):
        for app, entry, timeout in (("signal", "Signal.exe", 60), ("onlyoffice_x64", "DesktopEditors.exe", 90)):
            spec, control = handoff.runtime_spec(app, entry, timeout)
            expected = (f"image=D:\\{spec['dir']}\\{spec['exe']}\r\ncmdline={spec['exe']} {spec['args']}\r\n"
                        f"cwd=D:\\{spec['dir']}\r\ntimeout={timeout}\r\n").encode()
            self.assertEqual(control, expected)
            self.assertIsNone(spec["expect"])
            self.assertNotIn(b"MARKER", control)
            self.assertNotIn(b"env=", control)

    def test_control_bounds_reject_injection_path_whitespace_and_timeout(self):
        for entry in ("Signal.exe\r\ntimeout=999", "../Signal.exe", "has space.exe", "x" * 195 + ".exe"):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                handoff.runtime_spec("signal", entry, 60)
        for timeout in (0, 301, -1):
            with self.assertRaises(handoff.HandoffError):
                handoff.runtime_spec("signal", "Signal.exe", timeout)

    def test_free_space_reserve_and_initial_floor(self):
        with patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=24 * handoff.GIB)):
            handoff.check_space(Path("/"), handoff.GIB, initial=True)
            handoff.check_space(Path("/"), 3 * handoff.GIB)
            with self.assertRaises(handoff.HandoffError):
                handoff.check_space(Path("/"), 5 * handoff.GIB)
        with patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=handoff.RESERVE + handoff.GIB + handoff.METADATA_MARGIN - 1)):
            with self.assertRaises(handoff.HandoffError):
                handoff.check_space(Path("/"), handoff.GIB, initial=True)
        with patch.object(shutil, "disk_usage", return_value=SimpleNamespace(free=handoff.RESERVE - 1)):
            with self.assertRaises(handoff.HandoffError):
                handoff.check_space(Path("/"), 0)


if __name__ == "__main__":
    unittest.main()
