"""Compile actual Kernel64 registry/authority; model only IRQ/RNG/kernel roles.
No guest, private media or destructive physical block I/O is used.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[3]
K=ROOT/'shizukudos/kernel64'
class BackendAuthority(unittest.TestCase):
 def test_actual_registry_and_claimed_io(self):
  compiler=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  with tempfile.TemporaryDirectory(prefix='shz-blk-authority-') as tmp:
   binary=Path(tmp)/'authority'
   flags=['-D_POSIX_C_SOURCE=200809L','-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-pthread']
   if 'clang' in compiler:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   # Compile the actual fs_mount/root_of bodies; model namespace storage only.
   fs=(K/'fs.c').read_text()
   bodies=fs[fs.index('int fs_mount('):fs.index('/* NT device names')]
   namespace=Path(tmp)/'namespace.c'
   namespace.write_text('#include "'+str(K/'fs.h')+'"\nstatic fsnode_t *mounts[26];\nstatic uint64_t next_node_id=2;\nstatic char fold(char c){return c>=\'a\'&&c<=\'z\'?c-32:c;}\n'+bodies)
   cmd=[compiler,*flags,'-include',str(K/'host/blk_authority_host_shim.h'),str(K/'host/test_blk_authority.c'),str(K/'blk.c'),str(K/'blk_authority.c'),str(K/'blk_part.c'),str(K/'vfs_mounts.c'),str(namespace),'-o',str(binary)]
   compiled=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
   self.assertEqual(compiled.returncode,0,compiled.stderr)
   for mode in ('write','read','flush'):
    with self.subTest(mode=mode):
     ran=subprocess.run([binary,mode],capture_output=True,text=True,timeout=20)
     print(mode+': '+ran.stdout,flush=True)
     self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
     self.assertIn('failures=0',ran.stdout)
if __name__=='__main__':unittest.main(verbosity=2)
