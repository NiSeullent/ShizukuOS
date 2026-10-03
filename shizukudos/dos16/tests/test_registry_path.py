# SPDX-License-Identifier: GPL-2.0-or-later
"""Actual patched C functions and production NASM init-interrupt transport.

Set SHIZUKUDOS_REGISTRY_SOURCE to a real built patched FreeDOS tree.
Host C sanitizer controls and modeled interrupts are not guest boot evidence.
"""
import os, pathlib, re, shutil, subprocess, tempfile, unittest
TREE=pathlib.Path(os.environ.get('SHIZUKUDOS_REGISTRY_SOURCE',str(pathlib.Path(__file__).resolve().parents[3]/'build/shizukudos/dos16/work/freedos-kernel')))

def function(source,name):
    m=re.search(r'(?m)^[^\n;]*\b'+name+r'\([^;]*?\)\s*\{',source)
    if not m: raise AssertionError('actual source function missing: '+name)
    at=m.end();level=1
    while level:
        level+=(source[at]=='{')-(source[at]=='}');at+=1
    return source[m.start():at]

@unittest.skipUnless((TREE/'kernel/inthndlr.c').is_file(),'requires actual patched source tree')
class RegistryPath(unittest.TestCase):
    def compile(self,source):
        with tempfile.TemporaryDirectory() as td:
            c=pathlib.Path(td)/'control.c';exe=pathlib.Path(td)/'control';c.write_text(source)
            subprocess.run([shutil.which('clang') or 'cc','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(c),'-o',str(exe)],check=True,capture_output=True)
            subprocess.run([str(exe)],check=True,capture_output=True)
    def resident(self):
        actual=(TREE/'kernel/inthndlr.c').read_text()
        self.assertIn('STATIC BYTE winRegistryPath[WIN_REGISTRY_MAX + 1];',actual)
        self.assertNotIn('winRegistryPath[WIN_REGISTRY_MAX + 1] BSS_INIT',actual)
        return r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define STATIC static
#define BYTE char
#define UWORD uint16_t
#define ULONG unsigned long
#define BOOL int
#define TRUE 1
#define FALSE 0
#define FAR
#define WIN_REGISTRY_MAX 78
#define FP_OFF(p) (offset)
#define fmemcpy memcpy
static uint16_t offset;
static char winRegistryPath[79];
'''+''.join(function(actual,n) for n in ('winRegistryPathValid','winRegistrySet','winRegistryGet'))
    def test_resident_atomic_set_get_and_segment_bounds(self):
        self.compile(self.resident()+r'''
int main(void) {
 char destination[82], saved[79], longest[79], overlong[80];int i;
 memset(destination,0x5a,sizeof(destination));
 assert(winRegistryGet(destination,80)==0x1613);
 assert(destination[0]==0x5a);
 assert(winRegistrySet("C:\\WINDOWS\\SYSTEM.DAT")==0);
 strcpy(saved,winRegistryPath);
 assert(winRegistryGet(destination,80)==0);
 assert(strcmp(destination,saved)==0 && destination[strlen(saved)+1]==0x5a);
 memset(destination,0x5a,sizeof(destination));
 assert(winRegistryGet(destination,strlen(saved))==78 && destination[0]==0x5a);
 offset=65520; assert(winRegistryGet(destination,80)==78 && destination[0]==0x5a);
 assert(winRegistrySet("C:\\WINDOWS\\SYSTEM.DAT")==78);
 assert(strcmp(winRegistryPath,saved)==0);
 offset=65536-strlen(saved)-1;
 assert(winRegistryGet(destination,80)==0);
 offset=0;
 strcpy(longest,"C:\\");for(i=0;i<8;++i)strcat(longest,"ABCDEFGH\\");strcat(longest,"XYZ");
 assert(strlen(longest)==78 && winRegistrySet(longest)==0);
 strcpy(saved,winRegistryPath);
 strcpy(overlong,longest);strcat(overlong,"Q");
 assert(winRegistrySet(overlong)==78 && strcmp(winRegistryPath,saved)==0);
 return 0;
}
''')
    def test_invalid_paths_preserve_exact_resident_value(self):
        self.compile(self.resident()+r'''
int main(void) {
 const char *bad[]={"","SYSTEM.DAT","C:SYSTEM.DAT","C:/WINDOWS/SYSTEM.DAT",
 "C:\\..\\SYSTEM.DAT","C:\\WINDOWS.\\SYSTEM.DAT","C:\\TOOLONGDIR\\SYSTEM.DAT",
 "C:\\WINDOWS\\SYSTEM.DATA","C:\\WINDOWS\\SYSTEM.DAT ","C:\\WINDOWS\\SYS;RUN.DAT",
 "C:\\WINDOWS\\SYSTEM.DAT\n",NULL};char saved[79],out[80];int i;
 assert(winRegistrySet("D:\\WIN98\\SYSTEM.DAT")==0);strcpy(saved,winRegistryPath);
 for(i=0;bad[i];++i){assert(winRegistrySet(bad[i])==78);assert(strcmp(saved,winRegistryPath)==0);}
 assert(winRegistryGet(out,sizeof(out))==0 && strcmp(out,saved)==0);
 return 0;
}
''')
    def test_real_dispatch_preserves_query_capacity_and_only_changes_ax(self):
        actual=(TREE/'kernel/inthndlr.c').read_text()
        cases=actual[actual.index('      case 0x13:'):actual.index('      case 0x0:',actual.index('      case 0x13:'))]
        self.compile(self.resident()+r'''
static char farbuf[80];
#define MK_FP(segment,offset) farbuf
struct frame { UWORD AX,CX,es,DI; };
static struct frame dispatch(struct frame r){switch(r.AX&255){'''+cases+r'''
}return r;}
int main(void){struct frame r={0x1613,80,0x1000,0x4567};
 memset(farbuf,0x5a,sizeof(farbuf));r=dispatch(r);assert(r.AX==0x1613&&farbuf[0]==0x5a);
 strcpy(farbuf,"C:\\WINDOWS\\SYSTEM.DAT");r.AX=0x1614;r=dispatch(r);
 assert(r.AX==0&&r.CX==80&&r.es==0x1000&&r.DI==0x4567);
 memset(farbuf,0x5a,sizeof(farbuf));r.AX=0x1613;r=dispatch(r);
 assert(r.AX==0&&r.CX==80&&r.es==0x1000&&r.DI==0x4567);
 assert(strcmp(farbuf,"C:\\WINDOWS\\SYSTEM.DAT")==0);
 r.AX=0x1613;r.CX=2;farbuf[0]='Z';r=dispatch(r);assert(r.AX==78&&r.CX==2&&farbuf[0]=='Z');
 r.AX=0x16ff;r=dispatch(r);assert(r.AX==0x16ff&&r.CX==2);return 0;}
''')
    def test_real_config_pass1_bridge_admits_only_success(self):
        actual=(TREE/'kernel/config.c').read_text()
        self.assertIn('{"WINREG", 1, CfgWinReg}',actual)
        self.compile(r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#define STATIC static
#define VOID void
#define BYTE char
#define FP_SEG(p) 0x1234
#define FP_OFF(p) 0x5678
struct reg {uint16_t x;};typedef struct{struct reg a;uint16_t es,di;}iregs;
static char szBuf[256];static int calls,failures,status;
static char *skipwh(char *p){while(*p==' '||*p=='\t')++p;return p;}
static char *GetStringArg(char *p,char *out){p=skipwh(p);while(*p&&*p!=' '&&*p!='\r'&&*p!='\n')*out++=*p++;*out=0;return p;}
static void CfgFailure(char *p){(void)p;++failures;}
static void init_call_intr(int nr,iregs *r){assert(nr==0x2f&&r->a.x==0x1614&&r->es==0x1234&&r->di==0x5678);assert(strcmp(szBuf,"C:\\WINDOWS\\SYSTEM.DAT")==0);++calls;r->a.x=status;}
'''+function(actual,'CfgWinReg')+r'''
int main(void){char ok[]="C:\\WINDOWS\\SYSTEM.DAT",bad[]="C:\\WINDOWS\\SYSTEM.DAT extra";
 CfgWinReg(ok);assert(calls==1&&failures==0);
 status=78;CfgWinReg(ok);assert(calls==2&&failures==1);
 status=0x1614;CfgWinReg(ok);assert(calls==3&&failures==2);
 CfgWinReg(bad);assert(calls==3&&failures==3);return 0;}
''')
    def test_actual_nasm_init_transport_keeps_es_di_and_returns_status(self):
        try:
            from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
            from unicorn.x86_const import (UC_X86_REG_AX,UC_X86_REG_CS,UC_X86_REG_DS,
              UC_X86_REG_ES,UC_X86_REG_SS,UC_X86_REG_SP,UC_X86_REG_DI)
        except ImportError: self.skipTest('requires isolated Unicorn2.1.4')
        source=(TREE/'kernel/intr.asm').read_text()
        macro=source[source.index('%macro INTR 1'):source.index('%endmacro')+len('%endmacro')]
        bridge=source[source.index('INIT_CALL_INTR:'):source.index('; int init_call_XMScall')]
        asm='bits16\norg0x100\n%define WATCOM\n%define XCPU 386\n%include "'+str(TREE/'hdr/stacks.inc')+'"\n'+macro+'''
start:
 push word 0x2f
 push word regs
 call INIT_CALL_INTR
 mov ax,[regs]
 mov ah,0x4c
 int 0x21
regs: dw 0x1614,0,0,0,0,path,0,0,0x1000,0,0,0
path: db 'C:\\WINDOWS\\SYSTEM.DAT',0
'''+bridge
        asm=asm.replace('bits16','bits 16').replace('org0x100','org 0x100')
        # Skip the macro declarations/include: execute at the source-written entry.
        asm=asm.replace('org 0x100','org 0x100\njmp start')
        with tempfile.TemporaryDirectory() as td:
            p=pathlib.Path(td)/'bridge.asm';out=pathlib.Path(td)/'bridge.com';p.write_text(asm)
            subprocess.run(['nasm','-f','bin','-Wall','-Werror','-o',str(out),str(p)],check=True)
            com=out.read_bytes()
        for result in (0,78):
            uc=Uc(UC_ARCH_X86,UC_MODE_16);uc.mem_map(0,1<<20);uc.mem_write(0x10100,com)
            for r in (UC_X86_REG_CS,UC_X86_REG_DS,UC_X86_REG_ES,UC_X86_REG_SS):uc.reg_write(r,0x1000)
            uc.reg_write(UC_X86_REG_SP,0xfffe);observed=[]
            def interrupt(uc,n,_):
                if n==0x2f:
                    self.assertEqual(uc.reg_read(UC_X86_REG_AX),0x1614)
                    address=uc.reg_read(UC_X86_REG_ES)*16+uc.reg_read(UC_X86_REG_DI)
                    self.assertEqual(bytes(uc.mem_read(address,22)),b'C:\\WINDOWS\\SYSTEM.DAT\0')
                    observed.append(n);uc.reg_write(UC_X86_REG_AX,result)
                else:
                    self.assertEqual(n,0x21);self.assertEqual(uc.reg_read(UC_X86_REG_AX),0x4c00|result)
                    self.assertEqual(uc.reg_read(UC_X86_REG_DS),0x1000);uc.emu_stop()
            uc.hook_add(UC_HOOK_INTR,interrupt);uc.emu_start(0x10100,0x20000,count=10000,timeout=1_000_000)
            self.assertEqual(observed,[0x2f])

if __name__=='__main__':unittest.main()
