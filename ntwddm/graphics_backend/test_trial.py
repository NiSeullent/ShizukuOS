# SPDX-License-Identifier: GPL-2.0-only
import importlib.util,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('ntg_trial_gate_test',HERE/'trial.py');trial=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial)
NONCE='0123456789abcdef0123456789abcdef'
def fixture():
 names=list(trial.MANDATORY)+['extra_'+str(i) for i in range(55-len(trial.MANDATORY))]
 prefix='[win64 NTG64PR.EXE pid 60] '
 lines=['K64 autorun: starting D:\\graphicsprobe\\NTG64PR.EXE (cwd D:\\graphicsprobe, timeout30 s)','K64 autorun: started pid60'.replace('pid60','pid 60'),prefix+'NTG64 BEGIN nonce='+NONCE]
 lines += [prefix+'NTG64 PASS '+name for name in names]
 lines += [prefix+'NTG64 COUNTS checks=55 failures=0 paints=1 pixels=16384',prefix+'NTG64 RESULT PASS nonce='+NONCE,'K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms']
 return '\n'.join(lines)+'\n'
class Evidence(unittest.TestCase):
 def test_actual_normal_exit_grammar(self):self.assertTrue(trial.parse(fixture(),NONCE)['kernel_child_reaped'])
 def reject(self,old,new):
  with self.assertRaises(ValueError):trial.parse(fixture().replace(old,new),NONCE)
 def test_wrong_nonce(self):self.reject('BEGIN nonce='+NONCE,'BEGIN nonce='+'a'*32)
 def test_duplicate_nonce(self):self.reject('NTG64 BEGIN nonce='+NONCE,'NTG64 BEGIN nonce='+NONCE+'\n[win64 NTG64PR.EXE pid 60] NTG64 BEGIN nonce='+NONCE)
 def test_wrong_pid(self):self.reject('NTG64PR.EXE pid 60','NTG64PR.EXE pid 61')
 def test_wrong_exe(self):self.reject('[win64 NTG64PR.EXE','[win64 OTHER.EXE')
 def test_unprefixed_spoof(self):self.reject('[win64 NTG64PR.EXE pid 60] ','')
 def test_no_kernel_exit(self):self.reject('K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms','SHZEXIT=0')
 def test_timeout(self):self.reject('result exited','result timeout')
 def test_nonzero_exit(self):self.reject('exit=0','exit=1')
 def test_fault(self):self.reject('faulted=0','faulted=1')
 def test_not_reaped(self):self.reject('reaped=0','reaped=-1')
 def test_still_alive(self):self.reject('reaped=0 after','reaped=0 (1 thread(s) still alive) after')
 def test_mismatched_count(self):self.reject('checks=55','checks=56')
 def test_missing_draw(self):self.reject('PASS actual_guest_mesa_triangle_dispatch','PASS skipped_draw')
 def test_missing_lifetime(self):self.reject('PASS all_allocator_blocks_released','PASS skipped_free')
 def test_no_window(self):self.reject('paints=1','paints=0')
 def test_wrong_pixels(self):self.reject('pixels=16384','pixels=1')
 def test_missing_cleanup(self):self.reject('PASS unregister_window_class','PASS skipped_cleanup')
 def test_loader_rejection(self):self.reject('K64 autorun: result','K64 ldr: backend not loaded\nK64 autorun: result')
 def test_duplicate_exit(self):self.reject('K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms','K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms\nK64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms')
class Pixels(unittest.TestCase):
 def capture(self,directory):
  from PIL import Image
  image=Image.new('RGB',(1024,768),(255,255,255))
  for y in range(128):
   for x in range(128):
    sx,sy=x//4,y//4;color=((255*(2*sx+1)+32)//64,(255*(2*sy+1)+32)//64,64) if sx+sy<31 else (3,7,11);image.putpixel((114+x,133+y),color)
  path=Path(directory)/'capture.ppm';image.save(path);return path
 def test_all_real_visible_pixels(self):
  with tempfile.TemporaryDirectory() as d:self.assertEqual(trial.screenshot(self.capture(d))['checked_pixels'],16384)
 def test_one_wrong_pixel(self):
  from PIL import Image
  with tempfile.TemporaryDirectory() as d:
   path=self.capture(d)
   with Image.open(path) as image:image.putpixel((115,135),(0,0,0));image.save(path)
   with self.assertRaises(ValueError):trial.screenshot(path)
 def test_wrong_mode(self):
  from PIL import Image
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'capture.ppm';Image.new('RGB',(640,480)).save(path)
   with self.assertRaises(ValueError):trial.screenshot(path)
if __name__=='__main__':unittest.main()
