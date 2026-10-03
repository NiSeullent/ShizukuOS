# SPDX-License-Identifier: GPL-2.0-only
"""Bounded runtime negotiation; does not claim a large physical source."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
K=ROOT/'shizukudos/kernel64'
class Capacity(unittest.TestCase):
 def test_negotiated_bounds_and_absent_authority(self):
  cc=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  with tempfile.TemporaryDirectory() as temp:
   exe=Path(temp)/'negotiation'
   flags=['-std=c11','-O2','-g','-Wall','-Wextra','-Werror']
   if 'clang' in cc:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   files=[K/'host/test_native_capacity_negotiation.c']
   files += [ROOT/'shizukudos/win64/setup'/name for name in ('native_runtime.c','native_runtime_sha.c','native_provider.c','native_fat32_relocate.c','install.c','native_install.c','sfsw.c','gpt.c','fat32fmt.c','textparse.c')]
   built=subprocess.run([cc,*flags,*map(str,files),'-o',str(exe)],capture_output=True,text=True,timeout=30)
   self.assertEqual(built.returncode,0,built.stderr)
   ran=subprocess.run([str(exe)],capture_output=True,text=True,timeout=10)
   print(ran.stdout,flush=True);self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
