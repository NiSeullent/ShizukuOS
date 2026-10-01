#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Use actual producer modules and actual FAT generation, without guest binaries."""
import base64
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SOURCES = ("shizukudos/install/mkpayload.py", "shizukudos/install/desktop_profile.py",
           "shizukudos/install/gptmbr.asm", "shizukudos/install/shzsetup.ini", "shizukudos/tools/shzlib.py",
           "shizukudos/win64/build.py", "shizukudos/win64/tools/verres.py",
           "shizukudos/win64/tools/public_trust_fixtures.py")
HELLO = "\\SHZ\\TESTS\\T_HELLO.EXE"
WORKER = r'''
import base64, hashlib, importlib.util, json, sys
from pathlib import Path
root, action = Path(sys.argv[1]), sys.argv[2]
sys.path.insert(0, str(root/'shizukudos/install'))
spec=importlib.util.spec_from_file_location('actual_mkpayload', root/'shizukudos/install/mkpayload.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
if action == 'pack':
    items=json.loads(Path(sys.argv[3]).read_text())
    Path(sys.argv[4]).write_bytes(m.load_win64_build().pack_archive([(p,base64.b64decode(b)) for p,b in items]))
elif action == 'runtime':
    files,hello,setup=m.runtime_files(sys.argv[3]=='desktop')
    print(json.dumps({'files':[(p,hashlib.sha256(b).hexdigest()) for p,b in files]}))
'''


def members(blob):
    if blob[:8] != b"SHZARC01": raise AssertionError("archive magic")
    count, reserved = struct.unpack_from("<II", blob, 8)
    if reserved: raise AssertionError("archive reserved")
    result = []
    for i in range(count):
        at = 16 + 136 * i
        name = blob[at:at + 120].split(b"\0", 1)[0].decode()
        offset, size = struct.unpack_from("<QQ", blob, at + 120)
        if offset < 16 + count * 136 or offset + size > len(blob): raise AssertionError("archive extent")
        result.append((name, blob[offset:offset + size]))
    return result


class ActualProducer(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in SOURCES:
            target = self.root / name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / name, target)
        self.w = self.root / "build/shizukudos/win64"; self.w.mkdir(parents=True)
        self.dlls = {n: (n + " fixture bytes, not executable").encode() for n in ("ntdll", "kernel32", "user32", "gdi32")}
        for name, data in self.dlls.items(): (self.w / (name + ".dll")).write_bytes(data)
        (self.w / "t_hello.exe").write_bytes(b"hello fixture, not executable")
        (self.w / "SHZSETUP.EXE").write_bytes(b"setup fixture, not executable")
        self.runtime = [("\\SHZ\\SYS64\\" + name + ".dll", data) for name, data in self.dlls.items()]
        self.runtime += [("\\SHZ\\SYS64\\SHZDESK.EXE", b"shell fixture"), ("\\SHZ\\FONTS\\fixture.ttf", b"font fixture"),
                         (HELLO, (self.w / "t_hello.exe").read_bytes())]
        self.write_runtime(self.runtime)
        for name in ("supervisor/BOOTX64.EFI", "kernel64s/KERNEL64S.BIN", "kernel64s/boot.elf",
                     "kernel64/KERNEL64.BIN", "kernel32/KERNEL32.BIN", "dos16/shizukudos-dos10.img"):
            target = self.root / "build/shizukudos" / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(b"component host fixture")

    def worker(self, action, *args):
        return subprocess.run([sys.executable, "-B", "-c", WORKER, str(self.root), action, *map(str, args)],
                              capture_output=True, text=True, timeout=30)

    def write_runtime(self, items):
        fixture = self.root / "fixture-members.json"
        fixture.write_text(json.dumps([(name, base64.b64encode(data).decode()) for name, data in items]))
        run = self.worker("pack", fixture, self.w / "WIN64.IMG")
        self.assertEqual(run.returncode, 0, run.stderr)
        receipt = {"modules": {"user32": {}, "gdi32": {}},
                   "archive": {"sha256": hashlib.sha256((self.w / "WIN64.IMG").read_bytes()).hexdigest()}}
        (self.w / "build-result.json").write_text(json.dumps(receipt))

    def package(self, profile):
        out = self.root / ("package-" + profile)
        run = subprocess.run([sys.executable, "-B", str(self.root / "shizukudos/install/mkpayload.py"),
                              "--desktop" if profile == "desktop" else "--no-desktop", "--no-bios-boot", "--out", str(out)],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return out

    @unittest.skipUnless(all(shutil.which(p) for p in ("mkfs.fat", "mmd", "mcopy", "fsck.fat", "nasm")), "actual FAT/nasm tools")
    def test_actual_desktop_producer_packs_hello_once_in_boot_install_and_system(self):
        out = self.package("desktop")
        installed = members((out / "INSTALL.IMG").read_bytes())
        system = members((out / "payload/SYSTEM.ARC").read_bytes())
        esp_runtime = out / "runtime-readback.img"
        subprocess.run(["mcopy", "-i", str(out / "esp.img"), "::/SHZDOS/WIN64.IMG", str(esp_runtime)],
                       check=True, capture_output=True, timeout=30)
        for items in (installed, system, members(esp_runtime.read_bytes())):
            names = [name.upper() for name, _ in items]
            self.assertEqual(names.count(HELLO), 1)
            self.assertEqual(len(names), len(set(names)))
            self.assertEqual(next(data for name, data in items if name.upper() == HELLO), (self.w / "t_hello.exe").read_bytes())

    @unittest.skipUnless(all(shutil.which(p) for p in ("mkfs.fat", "mmd", "mcopy", "fsck.fat", "nasm")), "actual FAT/nasm tools")
    def test_actual_QA_producer_preserves_system_DLL_baseline_and_unique_boot_archives(self):
        out = self.package("qa")
        expected = {("\\SHZ\\SYS64\\" + n + ".dll").upper(): data for n, data in self.dlls.items()}
        system = members((out / "payload/SYSTEM.ARC").read_bytes())
        self.assertEqual({name.upper(): data for name, data in system if name.upper().startswith("\\SHZ\\SYS64\\")}, expected)
        self.assertNotIn(HELLO, [name.upper() for name, _ in system])
        esp_runtime = out / "runtime-readback.img"
        subprocess.run(["mcopy", "-i", str(out / "esp.img"), "::/SHZDOS/WIN64.IMG", str(esp_runtime)],
                       check=True, capture_output=True, timeout=30)
        for items in (members((out / "INSTALL.IMG").read_bytes()), members(esp_runtime.read_bytes())):
            names = [name.upper() for name, _ in items]
            self.assertEqual(names.count(HELLO), 1)
            self.assertEqual(len(names), len(set(names)))
        self.assertEqual(json.loads((out / "payload/manifest.json").read_text())["boot_profile"], "self-test")

    def test_actual_archive_producer_refuses_case_alias_even_with_same_bytes(self):
        fixture = self.root / "ambiguous-members.json"
        items = [*self.runtime, (HELLO.lower(), (self.w / "t_hello.exe").read_bytes())]
        fixture.write_text(json.dumps([(name, base64.b64encode(data).decode()) for name, data in items]))
        run = self.worker("pack", fixture, self.root / "rejected.img")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("duplicate archive path", run.stderr)
        self.assertFalse((self.root / "rejected.img").exists())

    def test_archive_hello_must_match_the_actual_separate_built_executable(self):
        (self.w / "t_hello.exe").write_bytes(b"different actual hello fixture")
        run = self.worker("runtime", "desktop")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("runtime paths or T_HELLO", run.stderr)

    def test_QA_duplicate_case_alias_module_is_refused(self):
        receipt = json.loads((self.w / "build-result.json").read_text())
        receipt["modules"]["NTDLL"] = {}; (self.w / "NTDLL.dll").write_bytes(b"other dll bytes")
        (self.w / "build-result.json").write_text(json.dumps(receipt))
        run = self.worker("runtime", "qa")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("runtime paths or T_HELLO", run.stderr)


if __name__ == "__main__": unittest.main(verbosity=2)
