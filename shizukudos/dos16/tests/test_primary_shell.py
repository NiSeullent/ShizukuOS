# SPDX-License-Identifier: GPL-2.0-or-later
"""Actual patched C and NASM transport; loader/interrupt surroundings are modeled.

SHIZUKUDOS_PRIMARY_SHELL_SOURCE selects an actual patched FreeDOS tree.
These controls do not run Windows or establish guest compatibility.
"""
import os,pathlib,re,shutil,subprocess,tempfile,unittest
TREE=pathlib.Path(os.environ.get('SHIZUKUDOS_PRIMARY_SHELL_SOURCE',str(pathlib.Path(__file__).resolve().parents[3]/'build/shizukudos/dos16/work/freedos-kernel')))

def function(source,name):
 m=re.search(r'(?m)^(?:STATIC[ \t]+)?(?:VOID|BYTE|int|BOOL|void|COUNT|UWORD|UBYTE)[ \t]+(?:\*[ \t]*)?(?:ASMCFUNC[ \t]+)?'+name+r'\([^;]*?\)\s*\{',source)
 if not m:raise AssertionError('actual function missing: '+name)
 at=m.end();level=1
 while level:level+=(source[at]=='{')-(source[at]=='}');at+=1
 return source[m.start():at]

@unittest.skipUnless((TREE/'kernel/inthndlr.c').is_file(),'actual patched source required')
class PrimaryShell(unittest.TestCase):
 def compile(self,source):
  with tempfile.TemporaryDirectory() as td:
   c=pathlib.Path(td)/'check.c';exe=pathlib.Path(td)/'check';c.write_text(source)
   result=subprocess.run([shutil.which('clang') or 'cc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(exe)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
   result=subprocess.run([str(exe)],capture_output=True,text=True)
   self.assertEqual(result.returncode,0,result.stderr)
 def resident(self):
  actual=(TREE/'kernel/inthndlr.c').read_text()
  declarations=actual[actual.index('STATIC BYTE winShellName'):actual.index('VOID winShellReset')]
  self.assertNotIn('BSS_INIT',declarations)
  return r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <setjmp.h>
#define STATIC static
#define BYTE char
#define UBYTE uint8_t
#define UWORD uint16_t
#define ULONG unsigned long
#define BOOL int
#define VOID void
#define FAR
#define ASMCFUNC
#define TRUE 1
#define FALSE 0
#define WIN31SUPPORT
#define NAMEMAX 67
#define CTBUFFERSIZE 127
#define fmemcpy memcpy
typedef struct {UBYTE ctCount;char ctBuffer[CTBUFFERSIZE];} CommandTail;
static uint16_t name_offset,tail_offset;
static const void *source_name,*source_tail;
static uint16_t offset_of(const void *p);
#define FP_OFF(p) offset_of(p)
#define FP_SEG(p) ((void)(p),0x2345)
'''+declarations+r'''
static uint16_t offset_of(const void *p) {
 if(p==source_name)return name_offset;
 if(p==source_tail)return tail_offset;
 if(p==&winShellTail)return 0x0300;
 return 0x0200;
}
'''+''.join(function(actual,n) for n in ('winShellReset','winShellStage','winShellCommit','winShellProcessEnd'))+r'''
void stage(char *name,CommandTail *tail,uint16_t owner) {
 source_name=name;source_tail=tail;winShellStage(name,tail,owner);
}
'''
 def test_actual_carrier_survives_init_and_exec_scratch_reuse(self):
  self.compile(self.resident()+r'''
int main(void) {
 char name[67]="D:\\TOOLS\\FREECOM.COM";CommandTail tail={7," /P /E:\r"};
 stage(name,&tail,0x0060);assert(winShellPending&&!winShellPublished);
 winShellCommit(0x0070,0x2000);assert(!winShellPublished);
 winShellCommit(0x0060,0x2000);assert(winShellPublished&&!winShellPending);
 memset(name,'X',sizeof(name));memset(&tail,'X',sizeof(tail));
 assert(strcmp(winShellName,"D:\\TOOLS\\FREECOM.COM")==0);
 assert(winShellTail.ctCount==7&&memcmp(winShellTail.ctBuffer," /P /E:\r",8)==0);
 winShellCommit(0x2000,0x3000);assert(winShellPsp==0x2000);
 winShellProcessEnd(0x3000);assert(winShellPublished);
 winShellProcessEnd(0x2000);assert(!winShellPublished&&!winShellPending);
 return 0;
}
''')
 def test_exact_count_limits_cr_and_far_segment_bounds(self):
  self.compile(self.resident()+r'''
int main(void) {
 char name[68];CommandTail tail;memset(name,'N',66);name[66]=0;
 memset(&tail,0,sizeof(tail));memset(tail.ctBuffer,'Q',126);tail.ctCount=126;tail.ctBuffer[126]='\r';
 stage(name,&tail,0x60);assert(winShellPending);winShellCommit(0x60,0x2000);assert(winShellPublished);
 tail.ctCount=127;stage(name,&tail,0x60);assert(!winShellPublished&&!winShellPending);
 tail.ctCount=126;tail.ctBuffer[126]='X';stage(name,&tail,0x60);assert(!winShellPending);
 tail.ctCount=0;tail.ctBuffer[0]='\r';strcpy(name,"SHELL.EXE");stage(name,&tail,0x60);assert(winShellPending);
 name_offset=65535;stage(name,&tail,0x60);assert(!winShellPending);name_offset=0;
 tail_offset=65535;stage(name,&tail,0x60);assert(!winShellPending);tail_offset=65534;
 stage(name,&tail,0x60);assert(winShellPending);tail_offset=0;
 memset(name,'N',67);name[67]=0;stage(name,&tail,0x60);assert(!winShellPending);
 name[0]=0;stage(name,&tail,0x60);assert(!winShellPending);
 strcpy(name,"BAD\nNAME");stage(name,&tail,0x60);assert(!winShellPending);
 strcpy(name,"SHELL.EXE");stage(name,&tail,0);assert(!winShellPending);
 stage(name,&tail,0x60);winShellCommit(0x60,0);assert(!winShellPublished);
 winShellCommit(0x60,0x60);assert(!winShellPublished);return 0;
}
''')
 def test_actual_dispatch_requires_published_and_preserves_other_fields(self):
  actual=(TREE/'kernel/inthndlr.c').read_text();start=actual.index('      case 0x11:          /* MS-DOS7: actual primary')
  case=actual[start:actual.index('      case 0x13:',start)]
  self.compile(self.resident()+r'''
struct frame {UWORD AX,BX,CX,DX,SI,DI,BP,ds,es,FLAGS;};
static struct frame query(struct frame r){switch(r.AX&255){'''+case+r'''
}return r;}
int main(void) {
 struct frame before={0x1611,0x3456,1,0x6789,0x4567,0x5678,0x7890,0x1234,0x4321,0x646},r;
 char name[]="Z:\\BIN\\OTHER.EXE";CommandTail tail={0,"\r"};
 r=query(before);assert(memcmp(&r,&before,sizeof(r))==0);
 stage(name,&tail,0x60);r=query(before);assert(memcmp(&r,&before,sizeof(r))==0);
 winShellCommit(0x60,0x2000);r=query(before);
 assert(r.AX==0&&r.BX==0&&r.ds==0x2345&&r.DX==0x200&&r.SI==0x300);
 assert(r.CX==before.CX&&r.DI==before.DI&&r.BP==before.BP&&r.es==before.es&&r.FLAGS==before.FLAGS);
 winShellReset();r=query(before);assert(memcmp(&r,&before,sizeof(r))==0);return 0;
}
''')
 def test_actual_primary_launch_reads_selected_config_and_failed_exec_retracts(self):
  actual=(TREE/'kernel/task.c').read_text();body=function(actual,'P_0')
  self.compile(self.resident()+r'''
struct config {char *cfgInit,*cfgInitTail;UBYTE cfgP_0_startmode;};
typedef struct {struct {void *fcb_1,*fcb_2;UWORD env_seg;CommandTail *cmd_line;} exec;} exec_blk;
typedef char fcb;
#define DOS_PSP 0x60
#define MK_FP(seg,off) ((void)(seg),(off))
#define fstrcpy strcpy
static char Shell[1024];static uint16_t cu_psp=0x60;
static jmp_buf end;static int launched;static const char *expected_name,*expected_tail;
static void put_string(const char *s){(void)s;}
#define STDIN 0
static int res_read(int fd,char *b,int max){(void)fd;(void)b;(void)max;assert(!winShellPublished&&!winShellPending);longjmp(end,1);}
static void res_DosExec(int mode,exec_blk *exb,char *name) {
 assert(mode==0x80&&strcmp(name,expected_name)==0);
 assert(exb->exec.cmd_line->ctCount==strlen(expected_tail));
 assert(memcmp(exb->exec.cmd_line->ctBuffer,expected_tail,strlen(expected_tail))==0);
 assert(winShellPending&&!winShellPublished);
 winShellCommit(cu_psp,0x2000);assert(winShellPublished);
 assert(strcmp(winShellName,expected_name)==0);memset(Shell,'X',sizeof(Shell));Shell[0]=0;
 assert(strcmp(winShellName,expected_name)==0);++launched;
}
'''+body+r'''
int main(void) {
 char name[]="D:\\CUSTOM\\START.COM",tail[]=" /P /E:512\r\n";struct config cfg={name,tail,0x80};
 expected_name=name;expected_tail=" /P /E:512";
 if(!setjmp(end))P_0(&cfg);assert(launched==1);return 0;
}
''')
 def test_actual_config_parser_and_default_primary_arguments(self):
  actual=(TREE/'kernel/config.c').read_text()
  start=actual.index('struct config Config = {');initial=actual[start:actual.index('};',start)]
  strings=re.findall(r'"([^"\n]*)"',initial)
  self.assertEqual(len(strings),2)
  default='static char default_name[]="'+strings[0]+'",default_tail[]="'+strings[1]+'";\n'
  helpers=''.join(function(actual,n) for n in ('iswh','skipwh','isnum','scan','GetStringArg','InitPgm','InitPgmHigh'))
  self.compile(self.resident()+r'''
struct config {char *cfgInit,*cfgInitTail;UBYTE cfgP_0_startmode;};
static struct config Config;static int askThisSingleCommand,DontAskThisSingleCommand;
static unsigned MenuLine,Menus;
static void publish_selected(void) {
 CommandTail tail;size_t n=0;memset(&tail,0,sizeof(tail));
 while(Config.cfgInitTail[n]!='\r'){assert(n<126);tail.ctBuffer[n]=Config.cfgInitTail[n];++n;}
 tail.ctCount=n;tail.ctBuffer[n]='\r';stage(Config.cfgInit,&tail,0x60);winShellCommit(0x60,0x2000);
 assert(winShellPublished&&strcmp(winShellName,Config.cfgInit)==0);
 assert(winShellTail.ctCount==n&&memcmp(winShellTail.ctBuffer,Config.cfgInitTail,n+1)==0);
}
'''+default+helpers+r'''
int main(void) {
 char custom[]="D:\\ALT\\4DOS.COM /P /E:1024",plain[]="Z:\\OTHER.EXE";
 Config.cfgInit=default_name;Config.cfgInitTail=default_tail;publish_selected();winShellReset();
 InitPgmHigh(custom);assert(Config.cfgP_0_startmode==0x80);
 assert(strcmp(Config.cfgInit,"D:\\ALT\\4DOS.COM")==0&&strcmp(Config.cfgInitTail," /P /E:1024\r\n")==0);
 publish_selected();winShellReset();InitPgm(plain);
 assert(Config.cfgP_0_startmode==0&&strcmp(Config.cfgInit,"Z:\\OTHER.EXE")==0);
 publish_selected();return 0;
}
''')
 def test_actual_loadngo_transfer_is_the_publication_boundary(self):
  actual=(TREE/'kernel/task.c').read_text();body=function(actual,'load_transfer')
  self.assertLess(body.index('if (mode == LOADNGO)'),body.index('winShellCommit'))
  self.assertLess(body.index('winShellCommit'),body.index('exec_user'))
  end=function(actual,'return_user');self.assertLess(end.index('winShellProcessEnd'),end.index('FreeProcessMem'))
  self.compile(self.resident()+r'''
#define COUNT int
#define LOADNGO 0
#define LOAD 1
#define SUCCESS 0
#define FLG_CARRY 1
typedef struct {UWORD AX,BX,CX,DX,SI,DI,BP,DS,ES,CS,IP,FLAGS;} iregs;
typedef struct psp {UWORD ps_parent;struct psp *ps_prevpsp;BYTE *ps_stack;CommandTail ps_cmd;} psp;
typedef struct {struct {BYTE *stack,*start_addr;} exec;} exec_blk;
static psp parent_psp,child_psp;
static psp *get_psp(uint16_t seg){return seg==0x60?&parent_psp:&child_psp;}
#define MK_FP(seg,off) ((void)(off),get_psp(seg))
static UWORD cu_psp=0x60;static CommandTail *dta;static int InDOS=1;
static iregs saved_regs;static iregs *user_r=&saved_regs;static jmp_buf finish;
static void exec_user(iregs *r,int mode){assert(mode==1&&r->AX==0x42&&r->BX==0x42&&winShellPublished);longjmp(finish,1);}
'''+body+r'''
int main(void) {
 char name[]="PRIMARY.COM";CommandTail tail={0,"\r"};BYTE stack[256];exec_blk exp;
 exp.exec.stack=stack+sizeof(stack);exp.exec.start_addr=stack;stage(name,&tail,0x60);
 assert(!winShellPublished);if(!setjmp(finish))load_transfer(0x2000,&exp,0x42,LOADNGO);
 assert(winShellPsp==0x2000&&cu_psp==0x2000&&child_psp.ps_parent==0x60);
 winShellReset();cu_psp=0x60;stage(name,&tail,0x60);exp.exec.stack=stack+sizeof(stack);
 assert(load_transfer(0x2000,&exp,0x42,LOAD)==SUCCESS&&!winShellPublished);return 0;
}
''')
 def test_actual_nasm_interrupt_transport_returns_changed_ds_and_preserves_rest(self):
  from unicorn import Uc,UC_ARCH_X86,UC_MODE_16,UC_HOOK_INTR
  from unicorn.x86_const import UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_BP,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_CS,UC_X86_REG_EFLAGS
  import struct
  source=(TREE/'kernel/int2f.asm').read_text()
  macros=source[source.index('%macro SwitchToInt2fStack'):source.index('segment\tHMA_TEXT')]
  body=source[source.index('IntDosCal:'):source.index('\t\tglobal\tSHARE_CHECK')]
  asm='bits 16\norg 100h\n%define XCPU 386\n%define WATCOM\njmp near IntDosCal\nreturned: int 0xf2\nhlt\n'+macros+body+'\n_int2F_12_handler: int 0xf1\nret\n_DGROUP_: dw 0x1800\nint2f_stk_top equ 0xf000\n'
  asm=re.sub(r'^\s*extern[^\n]*\n','',asm,flags=re.M)
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'transport.asm';out=p.with_suffix('.com');p.write_text(asm)
   subprocess.run(['nasm','-f','bin',str(p),'-o',str(out)],check=True);com=out.read_bytes()
  regs=[UC_X86_REG_AX,UC_X86_REG_BX,UC_X86_REG_CX,UC_X86_REG_DX,UC_X86_REG_SI,UC_X86_REG_DI,UC_X86_REG_BP,UC_X86_REG_DS,UC_X86_REG_ES]
  inputs=[0x1611,0x3456,1,0x6789,0x4567,0x5678,0x7890,0x1234,0x4321]
  for published in (False,True):
   uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,1<<20);uc.mem_write(0x10100,com)
   for r,v in zip(regs,inputs):uc.reg_write(r,v)
   uc.reg_write(UC_X86_REG_CS,0x1000);uc.reg_write(UC_X86_REG_SS,0x3000);uc.reg_write(UC_X86_REG_SP,0xe000)
   uc.mem_write(0x3e000,struct.pack('<3H',0x103,0x1000,0x646));observed=[]
   def interrupt(u,n,_):
    if n==0xf2:observed.append(n);u.emu_stop();return
    self.assertEqual(n,0xf1);ss=u.reg_read(UC_X86_REG_SS);sp=u.reg_read(UC_X86_REG_SP)
    at,seg=struct.unpack('<2H',u.mem_read(ss*16+sp+2,4));frame=seg*16+at
    self.assertEqual(struct.unpack('<H',u.mem_read(frame+16,2))[0],0x1611)
    if published:
     for off,value in ((16,0),(10,0),(2,0x1800),(12,0x800),(6,0x900)):
      u.mem_write(frame+off,struct.pack('<H',value))
   uc.hook_add(UC_HOOK_INTR,interrupt);uc.emu_start(0x10100,1<<20,count=10000)
   expected=[0,0,1,0x800,0x900,0x5678,0x7890,0x1800,0x4321] if published else inputs
   self.assertEqual([uc.reg_read(r) for r in regs],expected);self.assertEqual(observed,[0xf2])
   self.assertEqual(uc.reg_read(UC_X86_REG_EFLAGS)&0xffff,0x646)

if __name__=='__main__':unittest.main()
