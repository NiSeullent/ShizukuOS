# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual production device body against modeled time, no Windows/VM."""
from pathlib import Path
import hashlib
import subprocess
import tempfile
import unittest
HERE=Path(__file__).resolve().parent
class NativeDeviceContracts(unittest.TestCase):
 def test_actual_native_devices_gcc_and_clang_sanitizers(self):
  for compiler in ('gcc','clang'):
   with self.subTest(compiler=compiler),tempfile.TemporaryDirectory() as temporary:
    target=Path(temporary)/'devices'
    flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror']
    if compiler=='clang':flags+=['-fsanitize=address,undefined']
    built=subprocess.run([compiler,*flags,str(HERE/'native_devices_host.c'),'-o',str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(built.returncode,0,built.stderr)
    result=subprocess.run([str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(result.stdout.startswith('PASS '));self.assertEqual(result.stderr,'')
 def test_actual_existing_IRQ14_cascade_body_gcc_and_clang_sanitizers(self):
  for compiler in ('gcc','clang'):
   with self.subTest(compiler=compiler),tempfile.TemporaryDirectory() as temporary:
    target=Path(temporary)/'pic'
    flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror']
    if compiler=='clang':flags+=['-fsanitize=address,undefined']
    built=subprocess.run([compiler,*flags,str(HERE/'pic_host.c'),str(HERE.parent.parent/'src/devices.c'),'-o',str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(built.returncode,0,built.stderr)
    result=subprocess.run([str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(result.returncode,0,result.stderr);self.assertTrue(result.stdout.startswith('PASS '));self.assertEqual(result.stderr,'')
 def test_whole_default_profile_matches_pinned_prior_wire_transcript(self):
  # Prior actual devices.c SHA08c9d1ed… generated this exact 6000-operation
  # protocol transcript under the same modeled time. No native activation.
  for compiler in ('gcc','clang'):
   with self.subTest(compiler=compiler),tempfile.TemporaryDirectory() as temporary:
    target=Path(temporary)/'defaults'
    flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror']
    if compiler=='clang':flags+=['-fsanitize=address,undefined']
    built=subprocess.run([compiler,*flags,str(HERE/'default_devices_host.c'),'-o',str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(built.returncode,0,built.stderr)
    result=subprocess.run([str(target)],capture_output=True,timeout=60)
    self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stderr,b'')
    self.assertEqual(len(result.stdout),97892)
    self.assertEqual(hashlib.sha256(result.stdout).hexdigest(),'48b25118cd1fb0f0023aaa6fc3dd9090783ff9d478efae1b60383e6951425df1')
if __name__=='__main__':unittest.main()
