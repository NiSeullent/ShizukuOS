"""Actual Windows syscall export metadata, transitive source closure and wire ABI."""
import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
class NativeABI(unittest.TestCase):
 def test_actual_exports_and_source_closure(self):
  spec=importlib.util.spec_from_file_location('native_abi_win64_build',ROOT/'shizukudos/win64/build.py')
  build=importlib.util.module_from_spec(spec);spec.loader.exec_module(build)
  calls=build.syscall_list();self.assertEqual([n for n,v in calls if v==0xb5],['NtShzSetupNative'])
  policy=json.loads((ROOT/'shizukudos/win64/ntdll/ordinals.json').read_text())['ordinals']
  self.assertIn('NtShzSetupNative',policy);self.assertIn('ZwShzSetupNative',policy)
  self.assertEqual(len(policy.values()),len(set(policy.values())))
  abi=ROOT/'shizukudos/kernel64/setup_native_abi.h';self.assertIn(abi,build.runtime_source_paths())
  with tempfile.TemporaryDirectory(prefix='native-wire-abi-') as tmp:
   for cc in ('gcc','clang','x86_64-w64-mingw32-gcc','i686-w64-mingw32-gcc'):
    r=subprocess.run([cc,'-std=c11','-ffreestanding','-Wall','-Wextra','-Werror','-x','c','-c','-o',str(Path(tmp)/(cc+'.o')),'-'],input='#include "'+str(abi)+'"\n',capture_output=True,text=True)
    self.assertEqual(r.returncode,0,r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
