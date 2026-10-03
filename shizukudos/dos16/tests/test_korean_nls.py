# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise real patched NLS C functions and assembled resident package bytes."""
import os, pathlib, re, struct, subprocess, tempfile, unittest

ROOT=pathlib.Path(__file__).resolve().parents[3]
PATCH=ROOT/'shizukudos/dos16/patches/0005-korean-cp949-nls.patch'
# The production builder materializes this pinned upstream tree. An isolated
# compiler review can explicitly select its separately built source directory.
TREE=pathlib.Path(os.environ.get('SHIZUKUDOS_NLS_SOURCE',str(ROOT/'build/shizukudos/dos16/work/freedos-kernel')))


def function(source,name):
    found=re.search(r'(?m)^[^\n;]*\b'+name+r'\([^;]*?\)\s*\{',source)
    if not found: raise AssertionError('real function missing: '+name)
    start=found.start();at=found.end();level=1
    while level:
        level+=(source[at]=='{')-(source[at]=='}');at+=1
    return source[start:at]


@unittest.skipUnless((TREE/'kernel/nls.c').is_file() and (TREE/'kernel/nls_hc.asm').is_file(),
                     'build the patched DOS kernel, or set SHIZUKUDOS_NLS_SOURCE')
class ResidentKoreanNLS(unittest.TestCase):
    def test_real_nasm_package_keeps_437_and_resolves_all_949_tables(self):
        source=(TREE/'kernel/nls_hc.asm').read_text()
        source=re.sub(r'^\s*(?:GLOBAL|extern|segment).*$', '',source,flags=re.M)
        source=source.replace('%include "segs.inc"','%define DGROUP 0\n%define _CharMapSrvc 0')
        with tempfile.TemporaryDirectory() as td:
            asm=pathlib.Path(td)/'nls.asm';binary=pathlib.Path(td)/'nls.bin';asm.write_text(source)
            subprocess.run(['nasm','-f','bin','-o',str(binary),str(asm)],check=True,capture_output=True)
            data=binary.read_bytes()
        offset,segment,country,cp=struct.unpack_from('<4H',data)
        self.assertEqual((segment,country,cp),(0,1,437))
        self.assertNotEqual(offset,0)
        nxt,seg,country,cp,flags,yes,no,count=struct.unpack_from('<8H',data,offset)
        self.assertEqual((nxt,seg,country,cp,yes,no,count),(0,0,82,949,ord('Y'),ord('N'),6))
        pointers={}
        for index in range(5):
            kind,at,seg=struct.unpack_from('<BHH',data,offset+16+5*index)
            self.assertEqual(seg,0);self.assertLess(at,len(data));pointers[kind]=at
        for kind in (2,4):
            at=pointers[kind];self.assertEqual(struct.unpack_from('<H',data,at)[0],128)
            self.assertEqual(data[at+2:at+130],bytes(range(128,256)))
        at=pointers[7];self.assertEqual(data[at+2:at+6],bytes([0x81,0xfe,0,0]))
        at=pointers[6];self.assertEqual(struct.unpack_from('<H',data,at)[0],256)
        self.assertEqual(data[at+2+ord('a')],ord('A'))
        self.assertEqual(data[at+2+0xb0],0xb0)
        self.assertEqual(struct.unpack_from('<B4H',data,offset+41),(1,28,82,949,2))
        # Independently observed Korean DOS country format: whole won, 24h time.
        self.assertEqual(data[offset+41+23:offset+41+25],bytes([0,1]))

    def test_explicit_config_selection_uses_init_bridge_and_preserves_file_loader(self):
        actual=function((TREE/'kernel/config.c').read_text(),'Country')
        pre=r'''
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#define STATIC static
#define VOID void
#define BYTE char
#define COUNT short
#define FLG_CARRY 1
struct reg { unsigned short x; };
typedef struct { struct reg a,b,d;unsigned short flags; } iregs;
static char szBuf[256];static int bridge_calls,file_calls,failures,force_carry;
static char *skipwh(char *p){while(*p==' ')++p;return p;}
static char *GetNumArg(char *p,short *out){char *end;long n=strtol(p,&end,10);if(p==end)return NULL;*out=(short)n;return end;}
static void GetStringArg(char *p,char *out){strcpy(out,skipwh(p));}
static int LoadCountryInfo(char *file,short country,short cp){(void)file;(void)country;(void)cp;++file_calls;return 1;}
static void CfgFailure(char *p){(void)p;++failures;}
static void init_call_intr(int nr,iregs *r){
 assert(nr==0x21 && r->a.x==0x6602 && r->b.x==949 && r->d.x==949);
 ++bridge_calls;r->flags=force_carry?FLG_CARRY:0;
}
'''
        checks=r'''
int main(void) {
 char resident[]="82,949", named[]="82,949,C:\\WINDOWS\\COUNTRY.SYS", other[]="1,437";
 Country(resident);assert(bridge_calls==1&&file_calls==0&&failures==0);
 Country(named);assert(bridge_calls==1&&file_calls==1&&failures==0);
 Country(other);assert(bridge_calls==1&&file_calls==2&&failures==0);
 force_carry=1;Country(resident);assert(bridge_calls==2&&file_calls==2&&failures==1);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            c=pathlib.Path(td)/'config.c';exe=pathlib.Path(td)/'config';c.write_text(pre+actual+checks)
            subprocess.run(['clang','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-o',str(exe),str(c)],check=True)
            subprocess.run([str(exe)],check=True,capture_output=True)

    def test_actual_c_switching_unsupported_pages_and_dbcs_casing(self):
        source=(TREE/'kernel/nls.c').read_text()
        actual='\n'.join(function(source,n) for n in ('upMMem','nlsLeadByte','nlsCaseMem','nlsLoadPackage','DosGetCodepage','DosSetCodepage'))
        pre=r'''
#include <assert.h>
#include <stddef.h>
#include <string.h>
#define STATIC static
#define REG register
#define FAR
#define VOID void
#define BOOL int
#define TRUE 1
#define FALSE 0
#define COUNT int
#define UBYTE unsigned char
#define UWORD unsigned short
#define SUCCESS 0
#define DE_INVLDDATA -13
#define NLS_DEFAULT 65535
struct nlsDBCS { UWORD numEntries,dbcsTbl[4]; };
struct nlsPackage { UWORD cp,cntry; struct nlsDBCS dbcs; };
static struct nlsPackage usa={437,1,{0,{0}}}, korea={949,82,{2,{0xfe81,0}}};
static struct { UWORD sysCodePage;struct nlsPackage *actPkg; } nlsInfo={437,&usa};
#define getTable7(nls) (&(nls)->dbcs)
static struct nlsPackage *searchPackage(UWORD cp,UWORD country) {
 if(cp==437 && country==1)return &usa;
 if(cp==949 && country==82)return &korea;
 return NULL;
}
static int DosSetPackage(UWORD cp,UWORD country) { (void)cp;(void)country;return -13; }

'''
        checks=r'''
int main(void) {
 unsigned char map[256];unsigned i;
 UWORD active,system;unsigned char buf[]={0x61,0x81,0x61,0x62,0xb0,0xa1,0x7a};
 unsigned char expected[]={0x41,0x81,0x61,0x42,0xb0,0xa1,0x5a};
 for(i=0;i<256;++i)map[i]=(unsigned char)i;
 assert(DosGetCodepage(&active,&system)==0 && active==437 && system==437);
 assert(DosSetCodepage(949,949)==0);
 assert(DosGetCodepage(&active,&system)==0 && active==949 && system==949);
 assert(nlsInfo.actPkg->cntry==82);
 assert(nlsLeadByte(&korea,0x81)&&nlsLeadByte(&korea,0xfe));
 assert(!nlsLeadByte(&korea,0x80)&&!nlsLeadByte(&korea,0xff));
 assert(!nlsLeadByte(&usa,0x81));
 nlsCaseMem(&korea,map,buf,sizeof(buf));assert(!memcmp(buf,expected,sizeof(buf)));
 { unsigned char tail=0x81;nlsCaseMem(&korea,map,&tail,1);assert(tail==0x81); }
 { static unsigned char large[40001];
   for(i=0;i<40000;i+=4) {large[i]='a';large[i+1]=0x81;large[i+2]='a';large[i+3]='z';}
   large[40000]=0x5e;nlsCaseMem(&korea,map,large,40000);
   for(i=0;i<40000;i+=4)assert(large[i]=='A'&&large[i+1]==0x81&&large[i+2]=='a'&&large[i+3]=='Z');
   assert(large[40000]==0x5e);
 }
 assert(DosSetCodepage(932,932)==-13);
 assert(DosGetCodepage(&active,&system)==0 && active==949 && system==949);
 assert(nlsInfo.actPkg->cntry==82);
 assert(DosSetCodepage(437,437)==0);
 assert(DosGetCodepage(&active,&system)==0 && active==437 && system==437);
 assert(nlsInfo.actPkg->cntry==1);
 return 0;
}
'''
        with tempfile.TemporaryDirectory() as td:
            c=pathlib.Path(td)/'nls.c';exe=pathlib.Path(td)/'nls';c.write_text(pre+actual+checks)
            subprocess.run(['clang','-std=c99','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-o',str(exe),str(c)],check=True)
            subprocess.run([str(exe)],check=True,capture_output=True)

if __name__=='__main__':unittest.main()
