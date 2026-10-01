#!/usr/bin/env python3
"""Test actual PE walkers and exact native NTDLL lookup with publisher inputs."""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'build/modern-apps/long-symbols-host-v4'
OLD = ROOT / 'build/modern-apps/long-symbols-before'
PUBLISHED = Path('/root/Win98-Modern-codex-20260930/build/app-inputs/productivity-01a0f3d0cb43/tools/office-startup-closure-v1')


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def body(p):
    s = p.read_text()
    start = s.index('SHZ_EXPORT NTSTATUS NTAPI LdrGetProcedureAddress(')
    end = s.index('\n/* ---------------------------------------------------------------- misc Rtl */', start)
    return s[start:end]


SYNTHETIC = r'''
#define main publisher_probe_main
#include "pe_probe.c"
#undef main
static unsigned checks;
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL %d %s\n",__LINE__,#c); exit(1); } } while (0)
static void w16(uint8_t *p,unsigned v) { p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p,unsigned v) { w16(p,v);w16(p+2,v>>16); }
static void w64(uint8_t *p,uint64_t v) { w32(p,(unsigned)v);w32(p+4,(unsigned)(v>>32)); }
static void image_init(uint8_t *b,pe_info_t *o,size_t length)
{
 unsigned nt=0x80,opt=nt+24,sec=opt+240;
 memset(b,0,0x10000);b[0]='M';b[1]='Z';w32(b+0x3c,nt);
 b[nt]='P';b[nt+1]='E';w16(b+nt+4,0x8664);w16(b+nt+6,1);w16(b+nt+20,240);w16(b+nt+22,0x2002);
 w16(b+opt,0x20b);w64(b+opt+24,0x10000000);w32(b+opt+32,4096);w32(b+opt+36,4096);
 w32(b+opt+56,0x10000);w32(b+opt+60,0x1000);w16(b+opt+68,3);w32(b+opt+108,16);
 w32(b+opt+112,0x1000);w32(b+opt+116,0x100);
 w32(b+opt+120,0x1400);w32(b+opt+124,40);
 w32(b+opt+112+13*8,0x1600);w32(b+opt+116+13*8,64);
 memcpy(b+sec,".data",5);w32(b+sec+8,0xf000);w32(b+sec+12,0x1000);w32(b+sec+16,0xf000);w32(b+sec+20,0x1000);
 w32(b+sec+36,0xc0000040);
 /* Two exact exports: a long decorated-like symbol and a short name. */
 w32(b+0x1010,1);w32(b+0x1014,2);w32(b+0x1018,2);
 w32(b+0x101c,0x1100);w32(b+0x1020,0x1200);w32(b+0x1024,0x1300);
 w32(b+0x1100,0x9000);w32(b+0x1104,0x9010);
 w32(b+0x1200,0x2000);w32(b+0x1204,0x3000);w16(b+0x1302,1);
 memset(b+0x2000,'X',length);b[0x2000+length]=0;memcpy(b+0x3000,"Short",6);
 /* Both walkers use the same name at 0x4000, with distinct thunk arrays. */
 w32(b+0x1400,0x1800);w32(b+0x140c,0x1700);w32(b+0x1410,0x1900);
 w32(b+0x1600,1);w32(b+0x1604,0x1700);w32(b+0x1608,0x1c00);w32(b+0x160c,0x1b00);w32(b+0x1610,0x1a00);
 memcpy(b+0x1700,"library.dll",12);w64(b+0x1800,0x4000);w64(b+0x1a00,0x4000);
 w16(b+0x4000,77);memcpy(b+0x4002,b+0x2000,length+1);
 CHECK(pe_parse(b,0x10000,o)==PE_OK);
}
struct callback { const uint8_t *base;size_t length;unsigned calls;int stop;int ordinal; };
static int cb(void *p,const char *dll,const char *name,uint16_t hint,int ord,uint32_t slot)
{
 struct callback *c=p;++c->calls;CHECK(!strcmp(dll,"library.dll"));CHECK(slot>=0x1900);
 CHECK(ord==c->ordinal);
 if (ord) CHECK(!name && hint==55);
 else { CHECK(hint==77);CHECK(strlen(name)==c->length);CHECK(name==(const char *)c->base+0x4002); }
 return c->stop;
}
static int dcb(void *p,const pe_delay_desc_t *d,const char *name,uint16_t hint,int ord,uint32_t slot)
{ return cb(p,d->dll,name,hint,ord,slot); }
static int walk(uint8_t *b,pe_info_t *o,struct callback *c,int delay)
{ return delay ? pe_walk_delay_imports(b,0x10000,o,dcb,c) : pe_walk_imports(b,0x10000,o,cb,c); }
static void run_case(size_t n)
{
 uint8_t *b=malloc(0x10000);pe_info_t o;PVOID address=0;NTSTATUS st;
 struct { USHORT Length,MaximumLength;PCHAR Buffer; } as;
 char *counted=malloc(n);struct callback c;int delay;
 CHECK(b && counted);image_init(b,&o,n);memset(counted,'X',n);
 as.Length=(USHORT)n;as.MaximumLength=(USHORT)n;as.Buffer=counted;
 st=LdrGetProcedureAddress(b,&as,0,&address);CHECK(st==0 && address==b+0x9000);
 counted[n-1]='Y';CHECK(LdrGetProcedureAddress(b,&as,0,&address)==STATUS_ENTRYPOINT_NOT_FOUND);counted[n-1]='X';
 as.Length=(USHORT)(n-1);CHECK(LdrGetProcedureAddress(b,&as,0,&address)==STATUS_ENTRYPOINT_NOT_FOUND);
 as.Length=(USHORT)n;counted[n/2]=0;CHECK(LdrGetProcedureAddress(b,&as,0,&address)==STATUS_ENTRYPOINT_NOT_FOUND);counted[n/2]='X';
 as.Buffer=0;CHECK(LdrGetProcedureAddress(b,&as,0,&address)==STATUS_INVALID_PARAMETER);
 as.Length=0;CHECK(LdrGetProcedureAddress(b,&as,0,&address)==STATUS_ENTRYPOINT_NOT_FOUND);
 CHECK(LdrGetProcedureAddress(b,0,1,&address)==STATUS_SUCCESS && address==b+0x9000);
 for(delay=0;delay<2;++delay) {
  c=(struct callback){b,n,0,0,0};CHECK(walk(b,&o,&c,delay)==0 && c.calls==1);
  c.calls=0;c.stop=42;CHECK(walk(b,&o,&c,delay)==42 && c.calls==1);c.stop=0;
  b[0x4002+n-1]=0x1f;c.calls=0;CHECK(walk(b,&o,&c,delay)==(delay ? PE_E_DELAY : PE_E_IMPORT) && c.calls==0);
  b[0x4002+n-1]=0x80;c.calls=0;CHECK(walk(b,&o,&c,delay)==(delay ? PE_E_DELAY : PE_E_IMPORT) && c.calls==0);
  b[0x4002+n-1]='X';
  w64(b+(delay ? 0x1a00 : 0x1800),UINT64_C(0x8000000000000037));c.ordinal=1;c.calls=0;
  CHECK(walk(b,&o,&c,delay)==0 && c.calls==1);c.ordinal=0;
  /* A terminator only outside the declared raw extent must be rejected. */
  w64(b+(delay ? 0x1a00 : 0x1800),0xff00);w16(b+0xff00,77);memset(b+0xff02,'X',254);
  c.calls=0;CHECK(walk(b,&o,&c,delay)==(delay ? PE_E_DELAY : PE_E_IMPORT) && c.calls==0);
  /* NUL at the final backed byte is valid; the pointer still denotes raw input. */
  b[0xffff]=0;c.length=253;
  /* Validate extent with counting callback because its pointer differs. */
  {struct counts counts={0,0,0};int rc=delay ? pe_walk_delay_imports(b,0x10000,&o,delay_cb,&counts) : pe_walk_imports(b,0x10000,&o,import_cb,&counts);
   CHECK(rc==0 && counts.count==1 && counts.longest==253);}
  w64(b+(delay ? 0x1a00 : 0x1800),0x4000);c.length=n;
 }
 free(counted);free(b);
}
int main(void) { static const size_t sizes[]={1,127,128,159,160,202,781,974};size_t i;
 for(i=0;i<sizeof sizes/sizeof sizes[0];++i)run_case(sizes[i]);
 printf("long-symbol synthetic: %u checks PASS\n",checks);return 0; }
'''


def main():
    assert not OUT.exists()
    OUT.mkdir(parents=True)
    sources = [ROOT/'shizukudos/win64'/n for n in ('pe_parse.c','pe_parse.h','ntdll/ntdll_main.c')]
    before = {str(p):sha(p) for p in [Path(__file__),*sources,PUBLISHED/'pe_probe.c',PUBLISHED/'host-probe-result-v2.json']}
    host = json.loads((PUBLISHED/'host-probe-result-v2.json').read_text())
    program = Path(json.loads((PUBLISHED/'closure-analysis-v2.json').read_text())['publisher_program'])
    files = {p.name.lower():p for p in program.iterdir() if p.is_file()}
    publisher_pins = {name:sha(files[name]) for name in {x['module'] for x in host['probes']}}
    assert all(publisher_pins[x['module']]==x['publisher_sha256'] for x in host['probes'])
    (OUT/'pe_probe.c').write_bytes((PUBLISHED/'pe_probe.c').read_bytes())
    (OUT/'ntdll_exact_body.inc').write_text(body(sources[2]))
    (OUT/'synthetic.c').write_text(SYNTHETIC)
    commands, evidence = [], []
    for compiler,extra in [('gcc',['-O2']),('clang',['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        common = [compiler,'-std=c11','-Wall','-Wextra','-Werror',*extra,'-I'+str(ROOT/'shizukudos/win64')]
        for unit in ('pe_probe','synthetic'):
            cmd=[*common,str(OUT/(unit+'.c')),str(sources[0]),'-o',str(OUT/(unit+'-'+compiler))]
            subprocess.run(cmd,check=True,capture_output=True,text=True);commands.append(cmd)
        run=subprocess.run([str(OUT/('synthetic-'+compiler))],check=True,capture_output=True,text=True)
        assert not run.stderr
        evidence.append({'compiler':compiler,'synthetic':run.stdout.strip(),'publisher':[]})
        for previous in host['probes']:
            cmd=[str(OUT/('pe_probe-'+compiler)),previous['mode'],str(files[previous['module']])]
            if previous['name'] is not None: cmd.append(previous['name'])
            run=subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=60)
            result=json.loads(run.stdout);assert not run.stderr
            if previous['mode'] in ('imports','delay'): assert result['parse']==0 and result['walk']==0,result
            elif previous['mode']=='ntdll':
                direct=subprocess.run([str(OUT/('pe_probe-'+compiler)),'export',str(files[previous['module']]),previous['name']],check=True,capture_output=True,text=True,timeout=60)
                lookup=json.loads(direct.stdout);assert result['status']=='00000000' and result['rva']==lookup['rva'],(previous,result,lookup)
            else: assert result==previous['result']
            evidence[-1]['publisher'].append({'module':previous['module'],'mode':previous['mode'],'name_bytes':previous['name_bytes'],'result':result})
        short=next(x for x in host['probes'] if x['mode']=='ntdll' and x['name_bytes']==127)
        fake=short['name']+'#nonexistent'
        run=subprocess.run([str(OUT/('pe_probe-'+compiler)),'ntdll',str(files[short['module']]),fake],check=True,capture_output=True,text=True)
        answer=json.loads(run.stdout);assert answer['status']=='c0000139' and answer['rva']==0
        evidence[-1]['former_prefix_alias_rejected']=answer
    # Preserve the exact old body/parser and demonstrate the new checks fail.
    olddir=OUT/'old';olddir.mkdir()
    for n in ('pe_probe.c','synthetic.c'): (olddir/n).write_bytes((OUT/n).read_bytes())
    (olddir/'synthetic.c').write_text(SYNTHETIC.replace('sizes[]={1,127,128,159,160,202,781,974}', 'sizes[]={128,159,160,202,781,974}'))
    oldbody='static int str_eq(const char *a,const char *b) { while(*a && *a==*b){++a;++b;}return *a==*b; }\n'+body(OLD/'shizukudos/win64/ntdll/ntdll_main.c')
    (olddir/'ntdll_exact_body.inc').write_text(oldbody)
    cmd=['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I'+str(OLD/'shizukudos/win64'),str(olddir/'synthetic.c'),str(OLD/'shizukudos/win64/pe_parse.c'),'-o',str(olddir/'synthetic')]
    subprocess.run(cmd,check=True,capture_output=True,text=True)
    oldrun=subprocess.run([str(olddir/'synthetic')],capture_output=True,text=True)
    assert oldrun.returncode!=0 and 'FAIL' in oldrun.stderr
    assert before=={str(p):sha(p) for p in [Path(__file__),*sources,PUBLISHED/'pe_probe.c',PUBLISHED/'host-probe-result-v2.json']}
    assert publisher_pins=={name:sha(files[name]) for name in publisher_pins}
    proof={'publisher_pins':publisher_pins,'status':'PASS','source_pins':before,'commands':commands,'evidence':evidence,'old_counterfactual':{'returncode':oldrun.returncode,'stderr':oldrun.stderr},'sources_unchanged':True,'publisher_inputs_unchanged':True,'PE_code_executed':False,'app_functionality_verified':False}
    (OUT/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    print('PASS:',len(evidence),'compiler variants; actual publisher probes',len(host['probes']),'each; exact old counterfactual FAIL')


if __name__=='__main__':main()
