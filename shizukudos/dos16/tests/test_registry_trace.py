# SPDX-License-Identifier: GPL-2.0-only
"""Actual NASM hook execution; original DOS interrupt services are modeled."""
import pathlib,re,struct,subprocess,tempfile,unittest
from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_INTR,UC_HOOK_CODE
from unicorn.x86_const import *
SOURCE=pathlib.Path(__file__).resolve().parents[1]/'probes/registry_trace.asm'
REGS=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,
      UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_BP,UC_X86_REG_DS,UC_X86_REG_ES]
class Model:
 def __init__(self,com,symbols,*,psp=0x2000,parent=0x1000):
  self.u=Uc(UC_ARCH_X86,UC_MODE_16);self.u.mem_map(0,1<<20);self.u.mem_write(0x10100,com)
  self.s=symbols;self.psp=psp;self.calls=[];self.response={};self.error=False;self.stopped=False
  self.u.mem_write(0x30000,b'\xcd\xf1\xcf');self.u.mem_write(0x30010,b'\xcd\xf2\xcf')
  self.write('old21',struct.pack('<HH',0,0x3000));self.write('old2f',struct.pack('<HH',16,0x3000))
  self.write('owner',struct.pack('<H',0x1000));self.write('armed',b'\x01')
  self.write('systempath',b'C:\\WINDOWS\\SYSTEM.DAT\0');self.write('userpath',b'C:\\WINDOWS\\USER.DAT\0')
  self.u.mem_write(psp*16,b'\xcd\x20');self.u.mem_write(psp*16+0x16,struct.pack('<H',parent))
  self.u.hook_add(UC_HOOK_INTR,self.interrupt)
 def write(self,name,b):self.u.mem_write(0x10000+self.s[name],b)
 def word(self,name):return struct.unpack('<H',self.u.mem_read(0x10000+self.s[name],2))[0]
 def flags_frame(self,value):
  a=self.u.reg_read(UC_X86_REG_SS)*16+self.u.reg_read(UC_X86_REG_SP)+4
  self.u.mem_write(a,struct.pack('<H',value))
 def interrupt(self,u,n,_):
  if n==0xf3:self.stopped=True;u.emu_stop();return
  assert n in (0xf1,0xf2)
  ax=u.reg_read(UC_X86_REG_AX)&65535
  if n==0xf1 and ax==0x5100:u.reg_write(UC_X86_REG_BX,self.psp);return
  self.calls.append((n,[u.reg_read(r)&65535 for r in REGS]))
  for r,v in self.response.items():u.reg_write(r,v)
  self.flags_frame(0x0c03 if self.error else 0x0c02)
 def call(self,ax,*,bx=0,cx=24,dx=0x500,path=None,vec=0x21,caller=None):
  caller=self.psp if caller is None else caller
  self.stopped=False
  for r,v in zip(REGS,[ax,bx,cx,dx,0xaaaa,0xbbbb,0xcccc,self.psp,0x1234]):self.u.reg_write(r,v)
  if path:self.u.mem_write(self.psp*16+dx,path.encode()+b'\0')
  self.u.mem_write(caller*16+0x800,b'\xcd\xf3\xf4')
  self.u.reg_write(UC_X86_REG_SS,self.psp);self.u.reg_write(UC_X86_REG_SP,0xeff0)
  self.u.mem_write(self.psp*16+0xeff0,struct.pack('<HHH',0x800,caller,0x0c02))
  self.u.reg_write(UC_X86_REG_EFLAGS,0x402) # INT entry: IF cleared, DF set.
  self.u.reg_write(UC_X86_REG_CS,0x1000)
  off=self.s['hook21' if vec==0x21 else 'hook2f'];self.u.reg_write(UC_X86_REG_IP,off)
  self.u.emu_start(0x10000+off,1<<20,count=10000)
  assert self.stopped
  return [self.u.reg_read(r)&65535 for r in REGS],self.u.reg_read(UC_X86_REG_EFLAGS)&65535
 def records(self):
  b=bytes(self.u.mem_read(0x10000+self.s['trace_records'],self.word('trace_count')*36))
  return [struct.unpack('<18H',b[i:i+36]) for i in range(0,len(b),36)]
class TraceTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();p=pathlib.Path(cls.tmp.name)
  subprocess.run(['nasm','-f','bin',str(SOURCE),'-o',str(p/'trace.com'),'-l',str(p/'trace.lst')],check=True)
  cls.com=(p/'trace.com').read_bytes();cls.symbols={};pending=[]
  for line in (p/'trace.lst').read_text().splitlines():
   if re.search(r'\bHOOK hook21,',line):pending.append('hook21')
   label=re.search(r'\b([A-Za-z_][A-Za-z_0-9]*):\s*$',line)
   if label:pending.append(label[1])
   if re.search(r'\bHOOK hook2f,',line):pending.append('hook2f')
   a=re.match(r'\s*\d+\s+([0-9A-F]{8})\s+\S+\s+(?:<\d>\s+)?(.*)',line)
   if not a:continue
   off=int(a[1],16)+0x100
   for name in pending:cls.symbols[name]=off
   pending=[]
   name=re.search(r'(\w+)\s+(?:dd|dw|db|times)\b',a[2])
   if name:cls.symbols[name[1]]=off
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def model(self,**kw):return Model(self.com,self.symbols,**kw)
 def test_exact_old_registers_and_return_registers_flags(self):
  m=self.model();m.response=dict(zip(REGS,[6,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88]))
  out,f=m.call(0x3d01,path=r'C:\WINDOWS\SYSTEM.DAT')
  self.assertEqual(m.calls[0][1],[0x3d01,0,24,0x500,0xaaaa,0xbbbb,0xcccc,0x2000,0x1234])
  self.assertEqual(out,list(m.response.values()));self.assertEqual(f,0x0c02)
  self.assertEqual(m.word('trace_child'),0x2000);self.assertEqual(m.records()[0][16],0x77)
 def test_open_write_commit_close_lifecycle(self):
  m=self.model();m.response={UC_X86_REG_AX:6};m.call(0x3d01,path=r'C:\WINDOWS\SYSTEM.DAT')
  m.response={UC_X86_REG_AX:24};m.call(0x4000,bx=6)
  m.response={UC_X86_REG_AX:0};m.call(0x6800,bx=6);m.call(0x3e00,bx=6)
  m.call(0x4000,bx=6)
  self.assertEqual([r[1] for r in m.records()],[0x3d01,0x4000,0x6800,0x3e00])
 def test_exact_class_words_for_read_seek_write_commit_close(self):
  for path,expected in ((r'C:\WINDOWS\USER.DAT',1),(r'C:\WINDOWS\SYSTEM.DAT',2)):
   m=self.model();m.response={UC_X86_REG_AX:6};m.call(0x3d01,path=path)
   for ax in (0x3f05,0x4200,0x4018,0x6800,0x3e18):
    m.response={UC_X86_REG_AX:24 if ax>>8 in (0x3f,0x40) else 0};m.call(ax,bx=6)
   self.assertEqual([r[8] for r in m.records()],[expected]*6)
   self.assertEqual([call[1][0] for call in m.calls],[0x3d01,0x3f05,0x4200,0x4018,0x6800,0x3e18])
 def test_cf_error_and_short_count_are_observed_unchanged(self):
  m=self.model();m.response={UC_X86_REG_AX:6};m.call(0x3d01,path=r'C:\WINDOWS\USER.DAT')
  m.response={UC_X86_REG_AX:12};out,f=m.call(0x4000,bx=6)
  self.assertEqual(out[0],12);self.assertEqual(m.records()[-1][9],12)
  m.error=True;m.response={UC_X86_REG_AX:5};out,f=m.call(0x6800,bx=6)
  self.assertEqual((out[0],f&1),(5,1));self.assertEqual(m.records()[-1][-1]&1,1)
 def test_unrelated_paths_not_logged_or_copied(self):
  m=self.model();m.call(0x3d00,path=r'C:\SECRET.DAT')
  self.assertEqual(m.word('trace_count'),0);self.assertEqual(len(m.calls),1)
 def test_case_preservation_and_attr_input(self):
  m=self.model();m.call(0x4301,cx=2,path=r'c:\windows\system.dat')
  self.assertEqual(m.records()[0][3],2);self.assertEqual(m.records()[0][8],2)
  self.assertEqual(m.calls[0][1][3],0x500)
 def test_parent_or_foreign_child_cannot_admit(self):
  for kw in ({'psp':0x1000},{'parent':0x4321}):
   m=self.model(**kw);m.call(0x4301,path=r'C:\WINDOWS\SYSTEM.DAT')
   self.assertEqual(m.word('trace_count'),0)
 def test_first_nonflat_caller_cannot_admit(self):
  m=self.model();m.call(0x4301,path=r'C:\WINDOWS\SYSTEM.DAT',caller=0x2100)
  self.assertEqual(m.word('trace_child'),0)
 def test_overflow_explicit_and_forwarding_continues(self):
  m=self.model()
  for _ in range(129):m.call(0x4301,path=r'C:\WINDOWS\SYSTEM.DAT')
  self.assertEqual(m.word('trace_count'),128);self.assertEqual(m.word('trace_overflow'),1)
  self.assertEqual(len(m.calls),129)
 def test_reentrancy_chain_preserves_regs_and_flags(self):
  m=self.model();m.write('busy',b'\x01');m.error=True
  out,f=m.call(0x4301,path=r'C:\WINDOWS\SYSTEM.DAT')
  self.assertEqual(m.word('trace_count'),0);self.assertEqual(out[0],0x4301);self.assertEqual(f&1,1)
 def test_mux1611_no_pointer_dereference_and_exact_unsupported(self):
  m=self.model();m.response={UC_X86_REG_AX:0x1611,UC_X86_REG_BX:0}
  out,f=m.call(0x1611,vec=0x2f,dx=0xffff)
  self.assertEqual((out[0],out[1]),(0x1611,0));self.assertEqual(m.records()[0][0],0x2f);self.assertEqual(m.records()[0][8],0)
 def test_segment_wrap_path_refused_without_overread(self):
  m=self.model();m.u.mem_write(0x20000+0xffff,b'C');m.call(0x4301,dx=0xffff)
  self.assertEqual(m.word('trace_count'),0)
class StartupTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  TraceTests.setUpClass();cls.com=TraceTests.com;cls.symbols=TraceTests.symbols;cls.tmp=TraceTests.tmp
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def startup(self,arg,*,image=b'\xe9\x00',extent=35671,changed_vector=False):
  u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,1<<20);u.mem_write(0x10100,self.com)
  for r in (UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS):u.reg_write(r,0x1000)
  u.reg_write(UC_X86_REG_SP,0xfffe);u.mem_write(0x10080,bytes([len(arg)])+arg.encode()+b'\r')
  calls=[];vectors={0x21:(0,0x3000),0x2f:(16,0x3000)};exitcode=[]
  def result(ax=0,cf=False):
   u.reg_write(UC_X86_REG_AX,ax);f=u.reg_read(UC_X86_REG_EFLAGS);u.reg_write(UC_X86_REG_EFLAGS,(f|1) if cf else (f&~1))
  def intr(uc,n,_):
   assert n==0x21
   ax=u.reg_read(UC_X86_REG_AX)&65535;ah=ax>>8;ds=u.reg_read(UC_X86_REG_DS);dx=u.reg_read(UC_X86_REG_DX)
   calls.append(ax)
   if ah in (9,2):return
   if ax==0x3d00:result(6)
   elif ah==0x3f:u.mem_write(ds*16+dx,image);result(2)
   elif ax==0x4202:u.reg_write(UC_X86_REG_DX,extent>>16);result(extent&65535)
   elif ah==0x3e:result()
   elif ah==0x4a:result()
   elif ah==0x35:
    off,seg=vectors[ax&255];u.reg_write(UC_X86_REG_BX,off);u.reg_write(UC_X86_REG_ES,seg)
   elif ah==0x25:vectors[ax&255]=(dx,ds)
   elif ax==0x4b00:
    if changed_vector:vectors[0x21]=(0x123,0x4444)
    result(2,True)
   elif ah in (0x4c,0x31):exitcode.append(ax&255);u.emu_stop()
   else:raise AssertionError(hex(ax))
  ticks=[0]
  def clock(uc,address,size,_):
   ticks[0]+=20;u.mem_write(0x46c,struct.pack('<I',ticks[0]))
  u.hook_add(UC_HOOK_CODE,clock,begin=0x10000+self.symbols['read_bios_tick'],end=0x10000+self.symbols['read_bios_tick'])
  u.hook_add(UC_HOOK_INTR,intr);off=self.symbols['start'];u.emu_start(0x10000+off,1<<20,count=50000)
  self.assertTrue(exitcode);return calls,vectors,exitcode[0]
 def test_wrapper_rejects_injection_before_target_access(self):
  for arg in (' C:\\WINDOWS\\WIN.COM & X',' C:\\LONGWINDOWS\\WIN.COM',' D:WIN.COM'):
   calls,_,status=self.startup(arg);self.assertEqual(status,1);self.assertNotIn(0x3d00,calls)
 def test_wrapper_rejects_mz_and_oversized_images_before_hooks(self):
  for opts in ({'image':b'MZ'},{'extent':0x10000}):
   calls,vectors,status=self.startup(' C:\\WINDOWS\\WIN.COM',**opts)
   self.assertEqual(status,1);self.assertNotIn(0x2521,calls)
 def test_failed_exec_restores_vectors_without_log_or_success(self):
  calls,vectors,status=self.startup(' C:\\WINDOWS\\WIN.COM')
  self.assertIn(0x4b00,calls);self.assertEqual(vectors,{0x21:(0,0x3000),0x2f:(16,0x3000)})
  self.assertEqual(status,1);self.assertNotIn(0x5b00,calls)
 def test_changed_callee_vector_is_retained_not_overwritten_or_freed(self):
  calls,vectors,status=self.startup(' C:\\WINDOWS\\WIN.COM',changed_vector=True)
  self.assertEqual(status,1);self.assertIn(0x3101,calls)
  self.assertEqual(vectors[0x21],(0x123,0x4444));self.assertNotIn(0x4c01,calls)
class PauseTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # The same NASM routine is assembled with a reduced finite poll budget for
  # modeled stalled-clock refusal. Production default remains 0x04000000 polls.
  cls.tmp=tempfile.TemporaryDirectory();p=pathlib.Path(cls.tmp.name)
  subprocess.run(['nasm','-DPAUSE_POLL_BOUND=16','-f','bin',str(SOURCE),'-o',str(p/'pause.com'),'-l',str(p/'pause.lst')],check=True)
  cls.com=(p/'pause.com').read_bytes();cls.symbols={};pending=[]
  for line in (p/'pause.lst').read_text().splitlines():
   label=re.search(r'\b([A-Za-z_][A-Za-z_0-9]*):\s*$',line)
   if label:pending.append(label[1])
   a=re.match(r'\s*\d+\s+([0-9A-F]{8})\s+\S+',line)
   if a:
    for name in pending:cls.symbols[name]=int(a[1],16)+0x100
    pending=[]
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def pause(self,sequence):
  u=Uc(UC_ARCH_X86,UC_MODE_16);u.mem_map(0,1<<20);u.mem_write(0x10100,self.com)
  for r in (UC_X86_REG_CS,UC_X86_REG_SS):u.reg_write(r,0x1000)
  u.reg_write(UC_X86_REG_SP,0xe000);u.mem_write(0x1e000,struct.pack('<H',0x9000));u.mem_write(0x19000,b'\xcd\xf3')
  u.reg_write(UC_X86_REG_EAX,0x12345678);u.reg_write(UC_X86_REG_EDX,0x9abcdef0);u.reg_write(UC_X86_REG_EFLAGS,0x202)
  count=[0];stopped=[False]
  def tick(uc,a,size,_):
   value=sequence[min(count[0],len(sequence)-1)];count[0]+=1;u.mem_write(0x46c,struct.pack('<I',value))
  def interrupt(uc,n,_):self.assertEqual(n,0xf3);stopped[0]=True;u.emu_stop()
  address=0x10000+self.symbols['read_bios_tick'];u.hook_add(UC_HOOK_CODE,tick,begin=address,end=address)
  u.hook_add(UC_HOOK_INTR,interrupt);u.emu_start(0x10000+self.symbols['announcement_pause'],1<<20,count=3000)
  self.assertTrue(stopped[0]);self.assertEqual(u.reg_read(UC_X86_REG_EAX),0x12345678)
  self.assertEqual(u.reg_read(UC_X86_REG_EDX),0x9abcdef0);self.assertTrue(u.reg_read(UC_X86_REG_EFLAGS)&0x200)
  return u.reg_read(UC_X86_REG_EFLAGS)&1,count[0]
 def test_progressive_clock_waits_54_ticks(self):self.assertEqual(self.pause([100,100,120,153,154]),(0,5))
 def test_stalled_clock_refuses_at_finite_poll_budget(self):self.assertEqual(self.pause([100]),(1,17))
 def test_true_midnight_rollover(self):self.assertEqual(self.pause([0x1800b0-20,0x1800b0-10,0,34]),(0,4))
 def test_backward_or_implausible_timer_refused(self):
  for sequence in ([100,99],[0x1800b0],[100,220]):self.assertEqual(self.pause(sequence)[0],1)
if __name__=='__main__':unittest.main()
