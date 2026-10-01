# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the combined production FreeDOS startup bodies and physical layout."""
from pathlib import Path
import ast, hashlib, os, re, subprocess, tempfile, unittest
ROOT=Path(__file__).resolve().parents[3]
BASE=Path(os.environ.get('SHZ_FREEDOS_SOURCE',ROOT/'build/upstream/freedos-kernel'))
PATCH_DIR=ROOT/'shizukudos/dos16/patches'
# Read the actual producer's literal selection without running its toolchain or
# image builder. Every selected patch is applied below to pinned source bytes.
BUILDER=ROOT/'shizukudos/dos16/build.py'
PATCH_NAMES=ast.literal_eval(next(node.value for node in ast.parse(BUILDER.read_text()).body
 if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='KERNEL_PATCH_NAMES' for t in node.targets)))
PATCHES=tuple(PATCH_DIR/name for name in PATCH_NAMES)
PINS={'kernel/inthndlr.c':'0793e3bb94c558b6fdeb335f9e15577486b4b6ae53e987c89c095909fb363727',
'kernel/kernel.asm':'d678196d67f88111ebf3b6b60edaa068a8feb64016073bb7b799de48160ed50f',
'hdr/win.h':'7688c971830beb6274c490db7d97a04c7a19772e9cba1fae60e003c77b3a59f0',
'kernel/main.c':'42a2ca87eb2f72d87af2d9cb2e3b7d420929de3ffcb5524211557776adeb868a',
'hdr/version.h':'bd38e66d28be664b9ba20f5695df5a4f8f4dcd4de2fb0f7f48abdc33fd19797d'}
class Startup(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='dos-startup-body-');self.addCleanup(self.temp.cleanup)
  self.root=Path(self.temp.name)
  for n in PINS:
   raw=(BASE/n).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),PINS[n],n)
   p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
  for patch in PATCHES:
   subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1','-i',str(patch)],cwd=self.root,check=True,capture_output=True)
 def test_actual_startup_failure_standard_chain_and_reentry(self):
  text=(self.root/'kernel/inthndlr.c').read_text()
  a=text.index('      case 0x05:          /* Windows Startup Broadcast */')
  b=text.index('      case 0x07:          /* DOSMGR Virtual Device API */',a)
  cases=text[a:b]
  harness=r"""#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t UBYTE;typedef uint16_t UWORD;typedef uint32_t ULONG;
#define WIN31SUPPORT
#define FAR
#define ASM
#pragma pack(push,1)
#include "hdr/win.h"
#pragma pack(pop)
#define DebugPrintf(x) ((void)0)
#define FP_SEG(p) ((uint16_t)0x1234)
#define FP_OFF(p) ((uint16_t)0x5678)
struct regs {uint16_t AX,BX,CX,DX,ds,SI,es,di,BP,FLAGS;};
UWORD winInstanced;UBYTE winReportHidden;UWORD winActiveVersion;
struct WinStartupInfo winStartupInfo;
static unsigned checks,fail;UWORD winseg1,winseg2,winseg3;
#define CHECK(x) do {checks++;if(!(x)) {fail++;if(fail<5) fprintf(stderr,"failure line %u\n",__LINE__);}}while(0)
static void dispatch(struct regs *pr) {
#define r (*pr)
switch(r.AX&255) {
"""+cases+r"""}
#undef r
}
int main(void){
 struct regs initial={0x1605,0x2222,0,0,0xABCD,0xEF01,0x1111,0x040A,0x9876,0x0243},r,expected;
 struct WinStartupInfo before;
 CHECK(sizeof(struct WinStartupInfo)==22);
 for(unsigned cx=1;cx<65536;cx++) {
  memset(&winStartupInfo,0xA5,sizeof winStartupInfo);before=winStartupInfo;winInstanced=0;
  r=initial;r.CX=cx;expected=r;dispatch(&r);
  CHECK(!memcmp(&r,&expected,sizeof r));CHECK(!memcmp(&winStartupInfo,&before,sizeof before));CHECK(winInstanced==0);
 }
 for(unsigned dx=1;dx<65536;dx+=2) {
  memset(&winStartupInfo,0xA5,sizeof winStartupInfo);before=winStartupInfo;winInstanced=0;
  r=initial;r.DX=dx;expected=r;dispatch(&r);
  CHECK(!memcmp(&r,&expected,sizeof r));CHECK(!memcmp(&winStartupInfo,&before,sizeof before));CHECK(winInstanced==0);
 }
 memset(&winStartupInfo,0,sizeof winStartupInfo);winInstanced=0;
 r=initial;expected=r;expected.es=0x1234;expected.BX=0x5678;dispatch(&r);
 CHECK(!memcmp(&r,&expected,sizeof r));CHECK(winStartupInfo.next==0x11112222ul);CHECK(winInstanced==1);
 before=winStartupInfo;expected=r;dispatch(&r);CHECK(!memcmp(&r,&expected,sizeof r));CHECK(!memcmp(&winStartupInfo,&before,sizeof before));
 r=initial;r.AX=0x1606;expected=r;dispatch(&r);CHECK(winInstanced==0);CHECK(!memcmp(&r,&expected,sizeof r));
 r=initial;r.es=0;r.BX=0;dispatch(&r);CHECK(winStartupInfo.next==0);CHECK(winInstanced==1);
 printf("{\"checks\":%u,\"failures\":%u}\n",checks,fail);return fail?1:0;
}
"""
  c=self.root/'actual.c';c.write_text(harness)
  for cc,args in [('gcc',[]),('clang',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
   exe=self.root/cc
   run=subprocess.run([cc,'-std=gnu11','-Wall','-Wextra','-Werror',*args,str(c),'-o',str(exe)],capture_output=True,text=True,timeout=60)
   self.assertEqual(run.returncode,0,run.stderr)
   run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30)
   self.assertEqual(run.returncode,0,run.stdout+run.stderr)
   print(cc+" actual startup body: "+run.stdout.strip())
 def test_real_assembler_startup_layout_matches_c_optional_pointer(self):
  text=(self.root/'kernel/kernel.asm').read_text()
  block=text.split('%IFDEF WIN31SUPPORT',1)[1].split('%ENDIF ; WIN31SUPPORT',1)[0]
  asm='bits 16\nsection .data\nextern save_DS,save_BX,_InDOS,_MachineId,_CritPatch,_uppermem_root\n'+block
  source=self.root/'layout.asm';obj=self.root/'layout.o';source.write_text(asm)
  run=subprocess.run(['nasm','-f','elf','-w+all','-Werror','-o',str(obj),str(source)],capture_output=True,text=True,timeout=30)
  self.assertEqual(run.returncode,0,run.stderr)
  rows=subprocess.check_output(['nm','-n',str(obj)],text=True).splitlines()
  symbols={x[2]:int(x[0],16) for row in rows if len(x:=row.split())==3 and re.fullmatch('[0-9a-fA-F]+',x[0])}
  self.assertEqual(symbols['instance_table']-symbols['_winStartupInfo'],22,'header has optional DWORD at18, so instance records must start at22')
if __name__=='__main__':unittest.main(verbosity=2)
