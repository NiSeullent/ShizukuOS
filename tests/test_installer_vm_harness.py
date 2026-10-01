#!/usr/bin/env python3
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
import unittest
import subprocess
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("production_installer_vm", Path(__file__).resolve().parents[1] / "tools/test_shizukuos_installer_vm.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
START = "K64 setup: shz.setup=interactive, 0 RAM block device(s); starting \\SHZ\\SETUP\\SHZSETUP.EXE\n"


class ProductionGates(unittest.TestCase):
    def test_actual_ELF_libraries_and_exact_ROM_closure_refuse_stale_or_extra_inputs(self):
        self.assertTrue(hasattr(H, "qemu_runtime_files"), "actual executable library/ROM closure is absent")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("vgabios-stdvga.bin", "kvmvapic.bin"): (root / name).write_bytes(name.encode())
            closure = H.qemu_runtime_files(Path(sys.executable).resolve(), root)
            self.assertGreater(len(closure), 2)
            self.assertIn(str(root / "vgabios-stdvga.bin"), closure)
            H.verify_qemu_runtime(Path(sys.executable).resolve(), root, closure)
            (root / "vgabios-stdvga.bin").write_bytes(b"changed bytes")
            with self.assertRaisesRegex(ValueError, "runtime closure differs"):
                H.verify_qemu_runtime(Path(sys.executable).resolve(), root, closure)
            (root / "unexpected.rom").write_bytes(b"unselected ROM")
            with self.assertRaisesRegex(ValueError, "exact VGA/APIC ROM directory"):
                H.qemu_runtime_files(Path(sys.executable).resolve(), root)
        with patch.dict(os.environ, {"LD_PRELOAD": "/unselected/library.so"}):
            with self.assertRaisesRegex(ValueError, "dynamic loader environment"):
                H.qemu_runtime_files(Path(sys.executable).resolve(), Path(temp))

    def test_installer_topology_is_AHCI_decoy_NVMe_target_readonly_virtio_and_cold_NVMe(self):
        self.assertTrue(hasattr(H.OwnedVM, "frontend_snapshot"), "actual frontend device/model binding is absent")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); files = {"qemu": Path(sys.executable), "seabios": root / "bios"}
            drives = [(root / "decoy", False, False), (root / "target", False, False), (root / "medium", True, True)]
            vm = H.OwnedVM(files, root / "three", "bios", drives, 30)
            try:
                text = " ".join(vm.command)
                self.assertIn("ide-hd,drive=d0,bus=ide.0", text)
                self.assertIn("nvme,drive=d1,serial=SHZ-SETUP-TARGET", text)
                self.assertIn("virtio-blk-pci,drive=d2,bootindex=1", text)
                self.assertNotIn("ide-hd,drive=d1", text)
            finally: vm.__exit__(None, None, None)
            vm = H.OwnedVM(files, root / "cold", "bios", [(root / "installed", False, True)], 30)
            try: self.assertIn("nvme,drive=d0,serial=SHZ-SETUP-TARGET,bootindex=1", " ".join(vm.command))
            finally: vm.__exit__(None, None, None)

    def test_production_PPM_geometry_and_file_extent_are_bounded_before_full_read(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "frame.ppm"
            w, h = 1280, 800
            pixels = bytes((0,0,0, 255,0,0, 0,255,0, 0,0,255)) * (w*h//4)
            p.write_bytes(f"P6\n{w} {h}\n255\n".encode() + pixels)
            self.assertEqual(H.ppm(p), hashlib.sha256(pixels).hexdigest())
            with p.open("wb") as stream: stream.truncate(H.MAX_FRAME_BYTES + 1)
            with self.assertRaisesRegex(ValueError, "bounded production frame"): H.ppm(p)

    def test_actual_owned_audit_failure_is_preserved_and_never_becomes_success(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "repo"; out = Path(temp) / "out"; out.mkdir()
            script = repo / "shizukudos/install/tests/verify_disk.py"; script.parent.mkdir(parents=True)
            script.write_text("import sys,json\nfrom pathlib import Path\nprint('actual owned verifier fixture FAIL')\nPath(sys.argv[-1]).write_text(json.dumps([{'status':'FAIL'}]))\n")
            with self.assertRaisesRegex(ValueError, "rejected the installed target"):
                H.host_audit(repo, Path(temp), Path(temp) / "target", out)
            self.assertIn(b"fixture FAIL", (out / "host-disk-audit.log").read_bytes())
            self.assertEqual((out / "host-disk-audit.stderr").read_bytes(), b"")

    def test_actual_QMP_paused_before_any_guest_instruction_zero_baseline_and_raw_identity(self):
        qemu = Path(os.environ["SHZ_QEMU"]) if os.environ.get("SHZ_QEMU") else None
        data = Path(os.environ["SHZ_QEMU_DATA"]) if os.environ.get("SHZ_QEMU_DATA") else None
        bios = next((Path(p) for p in ("/usr/share/seabios/bios-256k.bin", "/usr/share/qemu/bios-256k.bin") if Path(p).is_file()), None)
        helper = Path(os.environ.get("SHZ_QMP_HELPER", str(Path(__file__).resolve().parents[1] / "shizukudos/tools/qemu.py")))
        if qemu is None or data is None or bios is None or not helper.is_file() or not Path('/dev/kvm').exists():
            self.skipTest("actual paused QMP control needs explicit SHZ_QEMU/SHZ_QEMU_DATA/helper/SeaBIOS/KVM")
        runtime = H.qemu_runtime_files(qemu, data)
        before = H.sha(helper)
        qmp_class = H.load_module(helper, "actual_paused_qmp_helper").QMP
        with tempfile.TemporaryDirectory(prefix="shz-inst-paused-host-") as temp:
            root = Path(temp); decoy, target, medium = root / "decoy", root / "target", root / "readonly-medium"
            decoy.write_bytes(bytes(4096)); target.write_bytes(bytes(4096)); medium.write_bytes(bytes(4096))
            medium_before = H.sha(medium)
            with patch.object(H, "QMP", create=True, new=qmp_class):
                with H.OwnedVM({"qemu": qemu, "seabios": bios, "qemu_data": data}, root / "qmp", "bios",
                               [(decoy, False, False), (target, False, False), (medium, True, True)], 30, start_guest=False) as vm:
                    status = vm.qmp.call("query-status")
                    self.assertFalse(status["running"])
                    self.assertEqual(len(vm.baseline), 3)
                    self.assertTrue(vm.baseline[2]["readonly"])
                    self.assertEqual(vm.baseline[2]["device"], "d2")
                    self.assertEqual([x["model"] for x in vm.frontends], ["ide-hd", "nvme", "virtio-blk-pci"])
                    self.assertEqual([x["drive"] for x in vm.frontends], ["d0", "d1", "d2"])
                    H.write_contract(vm.baseline, vm.block_snapshot("unchanged-paused"), "cancel")
                    vm.qmp.hmp('qemu-io d1 "write -P 0x5a 0 512"')
                    final = vm.block_snapshot("actual-owned-host-write-no-guest-cont")
                    # HMP's direct backend write does not account as frontend
                    # guest I/O. Keep the byte-hash check independently required;
                    # production guest installation still must have counters >0.
                    H.write_contract(vm.baseline, final, "cancel")
                    with self.assertRaises(ValueError): H.verify_unchanged_zero(target, H.zero_sha(4096), 4096)
                    self.assertFalse(vm.qmp.call("query-status")["running"])
                    vm.qmp.call("quit"); self.assertEqual(vm.proc.wait(timeout=5), 0)
            self.assertEqual(decoy.read_bytes(), bytes(4096))
            self.assertEqual(target.read_bytes()[:512], b"\x5a" * 512)
            self.assertEqual(H.sha(medium), medium_before)
            if os.environ.get("SHZ_QMP_EVIDENCE"):
                evidence = H.path(os.environ["SHZ_QMP_EVIDENCE"]); evidence.mkdir()
                for item in (root / "qmp").iterdir():
                    if item.is_file() and item.suffix in (".json", ".log", ".stderr"):
                        shutil.copyfile(item, evidence / item.name)
                import json
                (evidence / "host-control-result.json").write_text(json.dumps({"status": "PASS_ACTUAL_PAUSED_QMP_HOST_CONTROL",
                    "harness_sha256": H.sha(Path(H.__file__)), "helper_sha256": before, "qemu_sha256": H.sha(qemu), "seabios_sha256": H.sha(bios),
                    "qemu_runtime": runtime,
                    "actual_frontend_devices": vm.frontends,
                    "actual_QEMU_host_processes": 1, "actual_guest_instruction_resumed": False, "actual_installer_VM_count": 0,
                    "baseline": vm.baseline, "post_owned_host_write": final, "owned_host_bytes_written": 512,
                    "host_direct_write_counted_as_guest_IO": False, "full_zero_hash_rejected_owned_host_byte_mutation": True,
                    "production_guest_target_positive_counter_gate_preserved": True}, indent=2) + "\n")
        self.assertEqual(H.sha(helper), before)

    def test_fresh_CERTS_bytes_are_required_and_unbuilt_members_are_rejected(self):
        self.assertTrue(hasattr(H, "verify_install_runtime"), "fresh installed CERTS membership gate is absent")
        original = {"\\SHZ\\SYS64\\KERNEL32.DLL": b"fresh dll fixture", "\\SHZ\\FONTS\\UI.TTF": b"fresh font fixture",
                    "\\SHZ\\TESTS\\T_HELLO.EXE": b"fresh hello fixture", "\\SHZ\\CERTS\\ROOTS.PEM": b"fresh roots fixture"}
        H.verify_install_runtime(dict(original), original)
        for action in ("mutate", "unbuilt", "missing"):
            packed = dict(original)
            if action == "mutate": packed["\\SHZ\\CERTS\\ROOTS.PEM"] += b"modified"
            if action == "unbuilt": packed["\\SHZ\\CERTS\\UNBUILT.PEM"] = b"extra"
            if action == "missing": del packed["\\SHZ\\CERTS\\ROOTS.PEM"]
            with self.subTest(action=action), self.assertRaises(ValueError): H.verify_install_runtime(packed, original)

    def test_three_GiB_budget_preserves_seventeen_GiB_floor_and_bounds_audit_peak(self):
        self.assertEqual(getattr(H, "RUN_BUDGET", 4 << 30), 3 << 30)
        self.assertEqual(H.RETAIN_FREE, 17 << 30)
        self.assertLessEqual(H.production_budget(128 * H.MIB)["max_peak_bytes"], H.RUN_BUDGET)
        self.assertEqual(H.production_budget(128 * H.MIB)["host_audit_temporary_bytes"], 2 * H.TARGET_BYTES)
        actual_peak = H.production_budget(40 * H.MIB)["max_peak_bytes"]
        self.assertLess(actual_peak, H.RUN_BUDGET)
        with self.assertRaises(ValueError): H.production_budget(128 * H.MIB + 1)
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "new"
            usage = shutil.disk_usage(temp)
            for free, passes in ((H.RETAIN_FREE + H.RUN_BUDGET - 1, False), (H.RETAIN_FREE + H.RUN_BUDGET, True)):
                value = type(usage)(usage.total, usage.total - free, free)
                with patch.object(H.shutil, "disk_usage", return_value=value):
                    if passes: H.space(out, H.RUN_BUDGET)
                    else:
                        with self.assertRaises(ValueError): H.space(out, H.RUN_BUDGET)
            for free, passes in ((H.RETAIN_FREE + actual_peak - 1, False), (H.RETAIN_FREE + actual_peak, True)):
                value = type(usage)(usage.total, usage.total - free, free)
                with patch.object(H.shutil, "disk_usage", return_value=value):
                    if passes: H.space(out, actual_peak)
                    else:
                        with self.assertRaises(ValueError): H.space(out, actual_peak)

    def test_real_QMP_block_identity_and_zero_write_contract_refuses_missing_or_aliased_counters(self):
        self.assertTrue(hasattr(H, "block_attestation"), "actual block identity/counter gate is absent")
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "target"; p.write_bytes(bytes(4096))
            drives = [(p, False, False)]
            info = [{"device": "d0", "inserted": {"node-name": "raw0", "file": str(p), "drv": "raw", "ro": False,
                     "image": {"filename": str(p), "format": "raw", "virtual-size": 4096}}}]
            stats = [{"device": "d0", "node-name": "raw0", "stats": {"wr_bytes": 0, "wr_operations": 0}}]
            good = H.block_attestation(info, stats, drives)
            H.write_contract(good, good, "cancel")
            import copy
            for kind in ("wrong-file", "wrong-node", "missing", "duplicate", "readonly", "negative", "boolean", "operation"):
                q, r = copy.deepcopy(info), copy.deepcopy(stats)
                if kind == "wrong-file": q[0]["inserted"]["file"] = str(p) + ".different"
                if kind == "wrong-node": r[0]["node-name"] = "other"
                if kind == "missing": del r[0]["stats"]["wr_bytes"]
                if kind == "duplicate": r += copy.deepcopy(r)
                if kind == "readonly": q[0]["inserted"]["ro"] = True
                if kind == "negative": r[0]["stats"]["wr_bytes"] = -1
                if kind == "boolean": r[0]["stats"]["wr_bytes"] = False
                if kind == "operation": r[0]["stats"]["wr_operations"] = 1
                with self.subTest(kind=kind), self.assertRaises(ValueError):
                    H.write_contract(good, H.block_attestation(q, r, drives), "cancel")

    def test_install_write_proof_requires_exact_target_and_never_decoy_writes(self):
        self.assertTrue(hasattr(H, "write_contract"), "actual install write proof is absent")
        base = [{"device": "d0", "file": "decoy", "node": "n0", "readonly": False, "bytes": H.TARGET_BYTES, "wr_bytes": 0, "wr_operations": 0},
                {"device": "d1", "file": "target", "node": "n1", "readonly": False, "bytes": H.TARGET_BYTES, "wr_bytes": 0, "wr_operations": 0}]
        end = [dict(row) for row in base]; end[1].update(wr_bytes=512, wr_operations=1)
        H.write_contract(base, end, "install")
        for changed in ([dict(row) for row in base], [dict(row) for row in end]):
            if changed[1]["wr_bytes"]: changed[0]["wr_bytes"] = 512
            with self.assertRaises(ValueError): H.write_contract(base, changed, "install")

    def test_actual_owned_child_PIPE_capture_keeps_stdout_stderr_and_fails_at_combined_cap(self):
        self.assertTrue(hasattr(H, "PipeCapture"), "bounded actual child PIPE capture is absent")
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp); child = subprocess.Popen([sys.executable, "-c", "import os;os.write(1,b'guest FAIL retained\\n');os.write(2,b'QEMU diagnostic\\n')"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            capture = H.PipeCapture(child, folder / "serial", folder / "stderr", 64)
            child.wait(timeout=5); capture.finish()
            self.assertEqual((folder / "serial").read_bytes(), b"guest FAIL retained\n")
            self.assertEqual((folder / "stderr").read_bytes(), b"QEMU diagnostic\n")
            self.assertIsNone(capture.error)
            child = subprocess.Popen([sys.executable, "-c", "import os;os.write(1,b'X'*8192);os.write(2,b'Y'*8192)"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            capture = H.PipeCapture(child, folder / "overflow-serial", folder / "overflow-stderr", 1024)
            child.wait(timeout=5); capture.finish()
            self.assertIn("log cap", capture.error)
            self.assertLessEqual((folder / "overflow-serial").stat().st_size + (folder / "overflow-stderr").stat().st_size, 1024)

    def test_duplicate_runtime_member_is_rejected_even_when_bytes_are_identical(self):
        name = b"\\SHZ\\TESTS\\T_HELLO.EXE"
        table_end = 16 + 2 * 136
        ent = name.ljust(120, b"\0") + struct.pack("<QQ", table_end, 4)
        duplicate = b"SHZARC01" + struct.pack("<II", 2, 0) + ent * 2 + b"same"
        with self.assertRaisesRegex(ValueError, "identity/range"): H.archive(duplicate)

    def test_capture_from_a_different_harness_is_refused_before_any_VM_work(self):
        with self.assertRaisesRegex(ValueError, "another harness"):
            H.validate_inputs({"schema": "shizukuos-production-installer-vm/1", "harness_sha256": "0" * 64})

    def test_legacy_all_T_pass_is_not_interactive_or_desktop_success(self):
        legacy = "K64 setup: shz.setup=auto\ndone, 0 self-test failure(s)\nSETUP-RESULT: OK\nSHZ-EXIT:0\n"
        for action in (lambda: H.installation_trace(legacy, "cancel"),
                       lambda: H.installation_trace(legacy, "install"),
                       lambda: H.desktop_trace(legacy, "uefi")):
            with self.assertRaises(ValueError): action()

    def test_actual_ordered_cancel_trace_and_exact_review_target(self):
        good = START + "SHZ-SETUP UI ready candidates=2 writes=0\nSHZ-SETUP UI review target=nvme0n1 sectors=1048576\nSETUP-RESULT: CANCELLED (no disk writes)\nK64 setup: SHZSETUP.EXE exit=0 faulted=0 reaped=0, power request none\n"
        H.installation_trace(good, "cancel")
        for changed in (good.replace("nvme0n1", "ahci0"), good.replace("1048576", "1024"),
                        good.replace("faulted=0", "faulted=1"), good + "SHZ-SETUP UI confirmed target=nvme0n1\n",
                        good.replace("writes=0", "writes=1"), good.replace("1048576", "10485760")):
            with self.subTest(changed=changed), self.assertRaises(ValueError): H.installation_trace(changed, "cancel")

    def test_confirm_write_success_shutdown_order_and_decoy_refusal(self):
        good = START + "SHZ-SETUP UI ready candidates=2 writes=0\nSHZ-SETUP UI review target=nvme0n1 sectors=1048576\nSHZ-SETUP UI confirmed target=nvme0n1\nSETUP-RESULT: OK\nK64 setup: SHZSETUP.EXE exit=0 faulted=0 reaped=0, power request shutdown\nSHZ-EXIT:0\n"
        H.installation_trace(good, "install")
        for changed in (good.replace("confirmed target=nvme0n1", "confirmed target=ahci0"),
                        good.replace("SHZ-EXIT:0", "SHZ-EXIT:1"), good.replace("power request shutdown", "power request none"),
                        good.replace("SETUP-RESULT: OK", "SETUP-RESULT: FAIL"),
                        good.replace("confirmed target=nvme0n1", "confirmed target=nvme0n10")):
            with self.subTest(changed=changed), self.assertRaises(ValueError): H.installation_trace(changed, "install")

    def test_production_desktop_path_not_constructor_only(self):
        good = "Supervisor loader (UEFI x64)\nBOOT.INI mode=kernel64\nK64 desktop: production profile (self-tests not run)\nSHZ-DESKTOP READY width=1024 height=768\nSHZ-DESKTOP EDITOR path=D:\\DESKTOP.TXT bytes=0 dirty=0\nSHZ-DESKTOP EXIT requested=1\nK64 desktop: result exited exit=0 faulted=0 reaped=0\nK64 desktop: volume flush rc 0\nSHZ-EXIT:0\n"
        H.desktop_trace(good, "uefi")
        for changed in (good.replace("SHZ-DESKTOP READY", "GUI-READY: status"), good.replace("volume flush rc 0", "volume flush rc 1"),
                        good.replace("faulted=0", "faulted=1")):
            with self.subTest(changed=changed), self.assertRaises(ValueError): H.desktop_trace(changed, "uefi")

    def test_zero_hash_reads_actual_bytes_not_sparse_file_size(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "blank"
            with p.open("xb") as stream: stream.truncate(4096)
            pin = H.zero_sha(4096)
            H.verify_unchanged_zero(p, pin, 4096)
            with p.open("r+b") as stream: stream.seek(3072); stream.write(b"X")
            with self.assertRaises(ValueError): H.verify_unchanged_zero(p, pin, 4096)

    def test_actual_source_receipt_drift_and_required_new_UI_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "shizukudos/win64/setup/interactive_ui.c"
            source.parent.mkdir(parents=True); source.write_bytes(b"real source fixture")
            pins = {str(source.relative_to(root)): hashlib.sha256(source.read_bytes()).hexdigest()}
            H.verify_sources(root, pins, required=list(pins))
            with self.assertRaises(ValueError): H.verify_sources(root, pins, required=["shizukudos/win64/setup/interactive_choice.c"])
            source.write_bytes(b"newer source fixture")
            with self.assertRaises(ValueError): H.verify_sources(root, pins, required=list(pins))

    def test_guard_device_alias_symlink_and_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); p = root / "original"; p.write_bytes(b"bytes")
            alias = root / "alias"; alias.symlink_to(p)
            for q in (alias, Path('/root/../dev/refused'), Path('/root/../proc/refused')):
                with self.subTest(q=q), self.assertRaises(ValueError): H.path(q)
            with self.assertRaises(ValueError): H.new_output(root, root)

    def test_fifo_hash_is_refused_without_blocking_or_writer(self):
        with tempfile.TemporaryDirectory() as temp:
            fifo = Path(temp) / "input-fifo"; os.mkfifo(fifo)
            start = time.monotonic()
            with self.assertRaisesRegex(ValueError, "regular file"): H.sha(fifo)
            self.assertLess(time.monotonic() - start, 1)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "Linux owned-child pidfds")
    def test_failed_QMP_connection_reaps_only_actual_owned_child(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence = {"VM_executed": False, "actual_VM_count": 0}
            vm = H.OwnedVM({"qemu": Path(sys.executable), "seabios": Path(temp) / "bios"}, Path(temp) / "vm", "bios", [], 30, evidence)
            vm.command = [sys.executable, "-c", "import time; time.sleep(60)"]
            with patch.object(H, "QMP", create=True, side_effect=ValueError("fixture refuses QMP")):
                with self.assertRaisesRegex(ValueError, "fixture refuses QMP"): vm.__enter__()
            self.assertIsNotNone(vm.proc.poll())
            self.assertTrue(vm.err.closed)
            self.assertFalse(vm.sockdir.exists())
            self.assertEqual(evidence, {"VM_executed": True, "actual_VM_count": 1})

    def test_failed_spawn_never_claims_guest_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            evidence = {"VM_executed": False, "actual_VM_count": 0}
            vm = H.OwnedVM({"qemu": Path(temp) / "absent-executable", "seabios": Path(temp) / "bios"}, Path(temp) / "vm", "bios", [], 30, evidence)
            with self.assertRaises(FileNotFoundError): vm.__enter__()
            self.assertTrue(vm.err.closed)
            self.assertFalse(vm.sockdir.exists())
            self.assertEqual(evidence, {"VM_executed": False, "actual_VM_count": 0})

    @unittest.skipUnless(all(shutil.which(t) for t in ("mkfs.vfat", "mmd", "mcopy")), "actual FAT/mtools required")
    def test_actual_installer_FAT_members_read_back_and_input_bytes_stay_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); out = root / "out"; out.mkdir()
            files = {}
            for key in ("loader", "kernel64s", "install"):
                files[key] = root / key; files[key].write_bytes((key + " host fixture, not executable\n").encode() * 37)
            before = {key: H.sha(p) for key, p in files.items()}
            with patch.object(H, "space"):
                medium = H.boot_medium(out, files)
            self.assertEqual(medium.stat().st_size, 128 * H.MIB)
            self.assertEqual((out / "EFI_SHIZUKU_BOOT.INI.readback").read_bytes(), b"mode=install\r\nmenu_timeout=0\r\n")
            for key, member in (("loader", "EFI_BOOT_BOOTX64.EFI"), ("kernel64s", "SHZDOS_KERNEL64S.BIN"), ("install", "SHZ_SETUP_INSTALL.IMG")):
                self.assertEqual(H.sha(out / (member + ".readback")), before[key])
                self.assertEqual(H.sha(files[key]), before[key])


if __name__ == "__main__": unittest.main(verbosity=2)
