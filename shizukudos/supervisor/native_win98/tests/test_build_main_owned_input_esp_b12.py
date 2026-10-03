#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real build.main -> real _assemble (mkfs.vfat/mmd/mcopy/mtype + sparse FAT32 inserter).

Modeled and NOT real: the Supervisor payload compile (compile.py is replaced by a
stand-in BOOTX64.EFI), the 2 GiB disk / 2304 MiB ESP geometry (tiny disk, 64 MiB ESP),
and the free-space reserve. Input bytes are synthetic. The ESP is read back with mtools.
No QEMU, HostGrant, VM, guest or boot is involved; nothing here is boot evidence."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_optional_native_inputs as fx  # noqa: E402

B = fx.B
TOOLS = ('mkfs.vfat', 'mmd', 'mcopy', 'mtype')


def policy(vga, flags=3):
    raw = bytearray(96)
    struct.pack_into('<IHHII', raw, 0, 0x4E493957, 1, 96, flags, 1)
    raw[16:48] = bytes(range(1, 33))
    raw[48:80] = hashlib.sha256(vga).digest()
    return bytes(raw)


@unittest.skipUnless(all(shutil.which(t) for t in TOOLS), 'mtools/mkfs.vfat absent: ' + ','.join(t for t in TOOLS if not shutil.which(t)))
class BuildMainOwnedInput(unittest.TestCase):
    def run_main(self, with_input, bad_input=None):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        root = Path(temp.name); (root / 'build').mkdir()
        cfg, rom, receipt = fx.firmware()
        raw = {'disk': bytes(510) + b'\x55\xaa' + bytes((512 << 10) - 512), 'rom': bytearray(B.ROM_BYTES),
               'config': B.config_bytes(), 'kernel32': b'HOST_K32', 'kernel64': b'HOST_K64', 'win64-img': b'HOST_ARCHIVE',
               'vga-config': cfg, 'vga-rom': rom, 'vga-build-receipt': fx.serial(receipt)}
        raw['rom'][:7] = b'SeaBIOS'; raw['rom'][-16] = 0xea
        if with_input:
            raw['input-policy'] = bad_input if bad_input is not None else policy(cfg)
        args = []
        for name, body in raw.items():
            path = root / name; path.write_bytes(body)
            args += ['--' + name, str(path), '--' + name + '-sha256', hashlib.sha256(body).hexdigest()]
        source = root / 'shizukudos/supervisor/native_win98/compile.py'
        source.parent.mkdir(parents=True); source.write_text('# MODELED COMPILE; NEVER EXECUTED\n')
        out = root / 'build/out'; args += ['--out', str(out)]
        real_command = B.command
        def command(argv, receipt, **kwargs):
            if any(str(part).endswith('compile.py') for part in argv):
                components = Path(argv[-1]); components.mkdir(); loader = components / 'BOOTX64.EFI'
                loader.write_bytes(b'STAND_IN_EFI_NOT_EXECUTABLE')
                (components / 'result.json').write_bytes(fx.serial({
                    'status': 'PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN',
                    'artifacts': {'BOOTX64.EFI': {'sha256': B.file_sha(loader)}}}))
                return
            return real_command(argv, receipt, **kwargs)
        sink = []; stdout = io.StringIO(); error = None
        with patch.object(B, 'ROOT', root), patch.object(B, 'DISK_BYTES', 512 << 10), patch.object(B, 'ESP_MIB', 64), \
             patch.object(B, 'RESERVE', 0), patch.object(B, 'source_files', return_value=[source]), \
             patch.object(B, 'command', command), contextlib.redirect_stdout(stdout):
            try:
                B.main(args, receipt_sink=sink.append)
            except BaseException as caught:
                error = caught
        return out, raw, error, sink

    def members(self, esp):
        listing = subprocess.run(['mdir', '-i', str(esp), '-/', '-b', '::/'], capture_output=True, text=True, check=True).stdout
        return {line.strip().upper() for line in listing.splitlines() if line.strip()}

    def mtype(self, esp, name):
        return subprocess.run(['mtype', '-i', str(esp), '::/' + name], capture_output=True, check=True).stdout

    def test_input_profile_has_member_and_boot_key(self):
        out, raw, error, sink = self.run_main(True)
        self.assertIsNone(error, repr(error))
        result = json.loads((out / 'result.json').read_text())
        self.assertEqual(result['status'], 'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN')
        self.assertFalse(result['VM_executed'])
        esp = out / 'esp-win98.img'
        self.assertIn('::/SHZDOS/W98INPT.BIN', self.members(esp))
        self.assertEqual(self.mtype(esp, 'SHZDOS/W98INPT.BIN'), raw['input-policy'])
        self.assertEqual(self.mtype(esp, 'SHZDOS/VGACFG.BIN'), raw['vga-config'])
        boot = self.mtype(esp, 'EFI/SHIZUKU/BOOT.INI')
        self.assertIn(b'win98_input=yes\r\n', boot); self.assertIn(b'win98_vga=yes\r\n', boot)
        self.assertEqual(result['members']['SHZDOS/W98INPT.BIN']['sha256'], hashlib.sha256(raw['input-policy']).hexdigest())
        self.assertEqual(result['optional_native_inputs']['W98INPT.BIN']['bytes'], 96)

    def test_default_profile_has_no_input_member_or_key(self):
        out, raw, error, sink = self.run_main(False)
        self.assertIsNone(error, repr(error))
        esp = out / 'esp-win98.img'
        self.assertFalse(any('W98INPT' in m for m in self.members(esp)))
        boot = self.mtype(esp, 'EFI/SHIZUKU/BOOT.INI')
        self.assertNotIn(b'win98_input', boot); self.assertIn(b'win98_vga=yes\r\n', boot)
        self.assertNotIn('SHZDOS/W98INPT.BIN', json.loads((out / 'result.json').read_text())['members'])

    def test_unbound_input_policy_refused_without_esp(self):
        cfg, _, _ = fx.firmware()
        wrong = bytearray(policy(cfg)); wrong[48:80] = bytes(32 * [7])
        out, raw, error, sink = self.run_main(True, bad_input=bytes(wrong))
        self.assertIsInstance(error, ValueError)
        self.assertFalse(sink)
        self.assertFalse((out / 'esp-win98.img').exists())


if __name__ == '__main__':
    unittest.main()
