# SPDX-License-Identifier: GPL-2.0-only
"""Strict actual C execution with modeled UEFI only; no physical issuer proof."""
from pathlib import Path
import subprocess
import tempfile
import unittest
class CaptureControls(unittest.TestCase):
    def test_actual_capture_c(self):
        root=Path(__file__).resolve().parents[3]
        with tempfile.TemporaryDirectory(prefix='gop-capture-host-') as d:
            exe=Path(d)/'capture'
            subprocess.run(['gcc','-std=c11','-Wall','-Wextra','-Werror','-O2',
                str(Path(__file__).with_name('gop_capture_host.c')),
                str(root/'uefi/boot.c'),'-o',str(exe)],check=True)
            subprocess.run([str(exe)],check=True,timeout=10)
if __name__=='__main__':unittest.main()
