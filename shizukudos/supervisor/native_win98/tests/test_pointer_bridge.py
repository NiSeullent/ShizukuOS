# SPDX-License-Identifier: GPL-2.0-only
"""Run actual I2C/HID/adapter/native-i8042 source; physical boundaries modeled."""
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SOURCES=[HERE/'pointer_bridge_host.c',HERE.parent/'pointer_bridge.c',*[ROOT/'drivers/shz_laptop'/name for name in ('pointer_adapter.c','hid.c','hidi2c.c')]]
class PointerBridge(unittest.TestCase):
 def test_portable_driver_and_supervisor_headers_compose_in_both_orders(self):
  headers=('shizukudos/supervisor/native_win98/pointer_bridge.h','shizukudos/abi/shz_abi.h')
  for compiler in ('gcc','clang'):
   for order in (headers,headers[::-1]):
    with self.subTest(compiler=compiler,order=order):
     source=''.join('#include "'+name+'"\n' for name in order)
     source+='_Static_assert(SHZ_DRIVER_OK==0 && SHZ_OK==0,"distinct success domains");\n'
     result=subprocess.run([compiler,'-x','c','-std=c11','-Wall','-Wextra','-Werror','-I',str(ROOT),'-fsyntax-only','-'],input=source,capture_output=True,text=True,timeout=60)
     self.assertEqual(result.returncode,0,result.stderr)
 def test_actual_bridge_and_device_bodies(self):
  for compiler in ('gcc','clang'):
   with self.subTest(compiler=compiler),tempfile.TemporaryDirectory() as temporary:
    target=Path(temporary)/'pointer'
    flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror']
    if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    built=subprocess.run([compiler,*flags,*map(str,SOURCES),'-o',str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(built.returncode,0,built.stderr)
    run=subprocess.run([str(target)],capture_output=True,text=True,timeout=60)
    self.assertEqual(run.returncode,0,run.stderr);self.assertTrue(run.stdout.startswith('PASS '));self.assertEqual(run.stderr,'')
if __name__=='__main__':unittest.main()
