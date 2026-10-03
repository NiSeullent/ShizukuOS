"""Actual syscall/namespace/snapshot/registry/claim bodies; no guest launched."""
from pathlib import Path
import os,subprocess,tempfile,unittest
ROOT=Path(__file__).resolve().parents[3]
K=ROOT/'shizukudos/kernel64'
class NativeGui(unittest.TestCase):
 def test_actual_gui_preview_through_process_owned_syscall(self):
  cc=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  with tempfile.TemporaryDirectory(prefix='shz-native-sys-') as tmp:
   flags=['-D_POSIX_C_SOURCE=200809L','-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-pthread']
   if 'clang' in cc:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
   files=['host/test_native_gui.c','setup_native_sys.c','archive_source.c','boot_storage.c','blk_authority.c','blk.c','blk_part.c','fs.c']
   for mode in ('production-absent','host-modeled-admission'):
    with self.subTest(mode=mode):
     binary=Path(tmp)/mode
     selected=files+(['setup_native_release.c'] if mode=='production-absent' else [])
     cmd=[cc,*flags,*(['-DSHZ_TEST_COMPILED_ADMISSION'] if mode!='production-absent' else []),'-include',str(K/'host/setup_native_host_shim.h'),*[str(K/p) for p in selected],*[str(ROOT/'shizukudos/win64/setup'/p) for p in ('native_gui.c','native_runtime.c','native_runtime_sha.c','native_provider.c','native_fat32_relocate.c','install.c','native_install.c','sfsw.c','gpt.c','fat32fmt.c','textparse.c')],'-o',str(binary)]
     c=subprocess.run(cmd,capture_output=True,text=True,timeout=30);self.assertEqual(c.returncode,0,c.stderr)
     for failure in ('gui',):
      r=subprocess.run([str(binary),failure],capture_output=True,text=True,timeout=20)
      print(mode+'/'+failure+': '+r.stdout,flush=True);self.assertEqual(r.returncode,0,r.stdout+r.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
