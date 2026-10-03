"""Actual archive parser/namespace + sealed source + authority, host PMM model."""
from pathlib import Path
import os,subprocess,tempfile,unittest,hashlib,re
ROOT=Path(__file__).resolve().parents[3]
K=ROOT/'shizukudos/kernel64'
class ArchiveSource(unittest.TestCase):
 def test_actual_archive_source_and_external_roles(self):
  cc=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  with tempfile.TemporaryDirectory(prefix='shz-archive-source-') as tmp:
   binary=Path(tmp)/'archive'
   flags=['-D_POSIX_C_SOURCE=200809L','-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-pthread']
   if 'clang' in cc:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   files=['host/test_archive_source.c','archive_source.c','boot_storage.c','blk_authority.c','blk.c','blk_part.c','fs.c']
   cmd=[cc,*flags,'-include',str(K/'host/blk_authority_host_shim.h'),*[str(K/p) for p in files],str(ROOT/'shizukudos/accounts/sha256.c'),'-o',str(binary)]
   c=subprocess.run(cmd,capture_output=True,text=True,timeout=30);self.assertEqual(c.returncode,0,c.stderr)
   for mode in ('release','poison'):
    with self.subTest(mode=mode):
     r=subprocess.run([str(binary),mode],capture_output=True,text=True,timeout=20)
     print(mode+': '+r.stdout,flush=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
     expected=hashlib.sha256(bytes((i*37)%256 for i in range(288,10288))).hexdigest()
     self.assertEqual(re.search(r'snapshot_sha256=([0-9a-f]{64})',r.stdout).group(1),expected)
if __name__=='__main__':unittest.main(verbosity=2)
