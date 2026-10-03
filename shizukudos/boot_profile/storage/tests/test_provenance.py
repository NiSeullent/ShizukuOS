"""Actual bounded UEFI observer; firmware protocol responses modeled explicitly."""
from pathlib import Path
import os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[4]
class Provenance(unittest.TestCase):
 def test_observation(self):
  cc=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  with tempfile.TemporaryDirectory(prefix='shz-uefi-provenance-') as d:
   flags=['-std=c11','-O2','-g','-Wall','-Wextra','-Werror']
   if 'clang' in cc:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   exe=Path(d)/'test'
   r=subprocess.run([cc,*flags,str(Path(__file__).with_name('test_observation.c')),'-o',str(exe)],capture_output=True,text=True,timeout=30)
   self.assertEqual(r.returncode,0,r.stderr)
   r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=20)
   print(r.stdout,flush=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
