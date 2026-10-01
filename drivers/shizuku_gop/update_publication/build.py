#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Opt-in private candidate build. Never install, stage, or start a VM."""
import argparse
import ast
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import traceback
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = REPO / 'build/shizukudos/shizuku-gop-ne-selector'
BASE_PIN = '7ecca89ce708a865029bdff3e38468c9b2779dc0f392eb5a5132aba782c1bbad'
REPORT = REPO / 'build/display-quality-investigation-20261001T0900-v1/result.json'
REPORT_PIN = '00a6428eb36cb6672a6130ce0c52b47b9db2606528e2a705f8dfd9c7de68b274'
OW = REPO / 'build/tools/ow'
PRIOR_FAILURES = [
    ('build/shzgop-publication-candidate-20261001T1040-v1/result.json',
     'c1dae3b31f4cbab39ef6c8b3c69d93c99c631eef0a2fcd22277452a97b69deb5'),
    ('build/shzgop-publication-candidate-20261001T1120-v5/result.json',
     '960a8ec4184464cc11e7507160fc91c900281e47ca2325886408fb8cf6333fe0'),
]
PRIOR_CANDIDATES = [
    ('build/shzgop-publication-candidate-20261001T1050-v2/result.json',
     'b85bbc0f00f684bf995443627069245717ec5cc603e1cc3986d5d302e89c2368'),
    ('build/shzgop-publication-candidate-20261001T1100-v3/result.json',
     '29aeebcc39b20b8852207c92b8dd072e8022cf8710e685a637830f2220043f73'),
    ('build/shzgop-publication-candidate-20261001T1110-v4/result.json',
     '104668a77478cebf2d9616f6f3993d128cfe1749c1b28454599525f4b9036063'),
]

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def write(p, v):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(v, indent=2, sort_keys=True)+'\n')

def pin(p, expected):
    if sha(p) != expected:
        raise RuntimeError('Pinned input changed: '+str(p))

def function(text, name):
    """Exact definition slice, accounting for comments and quoted strings."""
    match = re.search(r'(?m)^(?:static )?[^\n;{}]+\b'+re.escape(name)+r'\([^;{}]*\)\s*\{', text)
    if not match:
        raise RuntimeError('Definition absent: '+name)
    start = match.start(); at = text.index('{', match.start()); depth = 0
    token = re.compile(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]', re.S)
    for m in token.finditer(text, at):
        if m.group() == '{': depth += 1
        elif m.group() == '}':
            depth -= 1
            if not depth: return text[start:m.end()]+'\n'
    raise RuntimeError('Unclosed definition: '+name)

def host_translation(tree, destination, baseline):
    backend = (tree/'vxd_vesa.c').read_text()
    pixels = (tree/'vxd_wram.c').read_text()
    async_source = (tree/'vxd_async.c').read_text()
    declarations = '''#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t DWORD; typedef int32_t LONG; typedef uint16_t WORD;
typedef uint8_t BYTE; typedef int BOOL;
#define TRUE 1
#define FALSE 0
#include "wram.h"
typedef struct { DWORD width,height,pitch; } shzgop_mode;
typedef struct { DWORD width,height,stride,onflip; BYTE *vram_pm32; } FBHDA_t;
static FBHDA_t host_hda; static FBHDA_t *hda=&host_hda;
static LONG fb_lock_cnt; static shzgop_mode native_mode; static blit_t frame;
static BOOL ready,hires,timer_running;
wram_t *wram;
static void draw(blit_t *);
void FBHDA_access_begin(DWORD); void FBHDA_access_end(DWORD);
void FBHDA_access_rect(DWORD,DWORD,DWORD,DWORD);
static DWORD publication_irq_enter(void); static void publication_irq_leave(DWORD);
static void host_blit_enter(blit_t *); static void host_pixel_hook(blit_t *);
#define dbg_printf(...) ((void)0)
static void FBHDA_lock(void) {} static void FBHDA_unlock(void) {}
#define __stdcall
typedef void (*draw_callback_h)(blit_t *);
static DWORD screen_time=16,last_update,host_time=16,host_timeout_result=1,host_timeout_calls;
static blit_t *blit; static draw_callback_h draw_callback;
static volatile DWORD *curtime;
#define TIME_MIN_PLAN 4
static volatile DWORD *Get_System_Time_Address(void) { return &host_time; }
static DWORD Set_Timeout(DWORD delay,DWORD ref,void (*fn)(void)) {
    (void)delay;(void)ref;(void)fn;host_timeout_calls++;return host_timeout_result;
}
static void async_timeout_proc(void) {}
'''
    if not baseline:
        declarations += '''static volatile DWORD publication_depth;
static volatile BOOL publication_inflight,publication_fault;
static wram_publication_cursor_t publication_cursor;
'''
    blit = pixels[pixels.index('static DWORD readpx8'):pixels.index('void wram_clear_target')]
    anchor = '\tif(readfn == NULL || writefn == NULL) return;'
    if blit.count(anchor) != 1: raise RuntimeError('Blit entry instrumentation context changed')
    blit = blit.replace(anchor, anchor+'\n\thost_blit_enter(blit);')
    anchor = '\t\t\tpx.dw = readfn(x, y);'
    if blit.count(anchor) != 1: raise RuntimeError('Pixel instrumentation context changed')
    blit = blit.replace(anchor, anchor+'\n\t\t\thost_pixel_hook(blit);')
    changes = '#define SWAP_DW(a,b) do { DWORD tmp=a;a=b;b=tmp; } while(0)\n'+function(pixels,'wram_changes')
    names = ([] if baseline else ['publication_damage','publication_begin','publication_snapshot_cursor'])
    names += ['draw','VESA_validmode','VESA_setmode','VESA_clear','VESA_HIRES_enable',
              'VESA_HIRES_disable','FBHDA_access_begin','FBHDA_access_rect','FBHDA_access_end']
    slices = {n: function(backend,n) for n in names}
    async_slices={n:function(async_source,n) for n in ['calc_delta','async_blit_init','async_timeout']}
    destination.write_text(declarations+blit+changes+'\n'.join(slices.values())+'\n'+'\n'.join(async_slices.values())+'\n#include "host_test.c"\n')
    return {'functions': {n:hashlib.sha256(s.encode()).hexdigest() for n,s in slices.items()},
            'actual_pixel_functions_instrumented_sha256':hashlib.sha256(blit.encode()).hexdigest(),
            'actual_changes_sha256':hashlib.sha256(changes.encode()).hexdigest(),
            'actual_async_functions':{n:hashlib.sha256(s.encode()).hexdigest() for n,s in async_slices.items()},
            'instrumentation':'Entry count and one delivery hook immediately after actual readfn; pixel operations unchanged',
            'translation_sha256':sha(destination)}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',required=True);args=parser.parse_args()
    out=Path(args.out).resolve()
    if out.exists(): raise SystemExit('Refusing existing output directory')
    out.mkdir(parents=True); logs=[]
    result={'schema':1,'status':'INCOMPLETE','application_success':False,'native_acceptance':'pending',
            'scope':'Private source/object candidate only; no staging, VM, device, installed/default source change'}
    env=dict(os.environ);env['WATCOM']=str(OW);env['PATH']=str(OW/'binl64')+os.pathsep+env['PATH'];env['INCLUDE']=str(OW/'h')
    def run(argv,cwd,expected=0):
        number=len(logs)+1; path=out/'logs'/('%02d.json'%number)
        cp=subprocess.run([str(x) for x in argv],cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=180)
        record={'argv':[str(x) for x in argv],'cwd':str(cwd),'exit':cp.returncode,'stdout':cp.stdout,'stderr':cp.stderr}
        write(path,record);logs.append({'path':str(path.relative_to(out)),'sha256':sha(path),'exit':cp.returncode})
        if cp.returncode!=expected: raise RuntimeError('Command failed; frozen log '+str(path))
        return cp.stdout
    try:
        pin(BASE/'build-result.json',BASE_PIN);pin(REPORT,REPORT_PIN)
        receipt=json.loads((BASE/'build-result.json').read_text())
        result['parents']=[{'path':str(BASE/'build-result.json'),'sha256':BASE_PIN},{'path':str(REPORT),'sha256':REPORT_PIN}]
        result['prior_failures']=[]
        for name,expected in PRIOR_FAILURES:
            p=REPO/name;pin(p,expected)
            q=out/'frozen/prior'/Path(name).parent.name/'result.json';q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
            result['prior_failures'].append({'path':str(p),'sha256':expected,'frozen':str(q.relative_to(out))})
        result['prior_candidates']=[]
        for name,expected in PRIOR_CANDIDATES:
            p=REPO/name;pin(p,expected)
            q=out/'frozen/prior'/Path(name).parent.name/'result.json';q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
            result['prior_candidates'].append({'path':str(p),'sha256':expected,'frozen':str(q.relative_to(out))})
        source_records={}; own={}
        for p in sorted(HERE.iterdir()):
            if p.is_file():
                q=out/'frozen/own'/p.name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
                own[p.name]={'path':str(p),'sha256':sha(p),'frozen':str(q.relative_to(out))}
        result['own_sources']=own
        sourcezip=BASE/'package/SOURCE.zip'
        if not sourcezip.exists(): sourcezip=BASE/'SOURCE.zip'
        pin(sourcezip,receipt['artifacts']['SOURCE.zip']['sha256'])
        with zipfile.ZipFile(sourcezip) as z:
            for name,expected in receipt['compiled_sources'].items():
                p=BASE/'work'/name;pin(p,expected)
                data=z.read('vmdisp9x/'+name)
                if hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('SOURCE.zip mismatch '+name)
                q=out/'baseline'/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(data)
                source_records[name]={'sha256':expected,'frozen':str(q.relative_to(out))}
        result['baseline_sources']=source_records
        original={}
        for name,expected in receipt['original_inputs'].items():
            p=REPO/'drivers/shizuku_gop'/name;pin(p,expected)
            q=out/'frozen/original'/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
            original[name]={'path':str(p),'sha256':expected,'frozen':str(q.relative_to(out))}
        result['original_sources']=original
        artifact_records={}
        for name,rec in receipt['artifacts'].items():
            p=BASE/'package'/name
            if not p.exists():p=BASE/name
            pin(p,rec['sha256']);q=out/'frozen/old-package'/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
            artifact_records[name]={'path':str(p),'sha256':rec['sha256'],'bytes':rec['bytes'],'frozen':str(q.relative_to(out))}
        result['unchanged_old_package']=artifact_records
        tools={}
        for name in ['wcc386','wlink','wdis']:
            p=OW/'binl64'/name
            if name in receipt['toolchain']:pin(p,receipt['toolchain'][name]['sha256'])
            tools[name]={'path':str(p),'sha256':sha(p)}
        for name in ['gcc','clang','ld']:
            p=Path(shutil.which(name)).resolve();tools[name]={'path':str(p),'sha256':sha(p)}
            run([p,'--version'],out)
        for name,args2 in [('cc1',['gcc','-print-prog-name=cc1']),('collect2',['gcc','-print-prog-name=collect2'])]:
            p=Path(run(args2,out).strip()).resolve();tools[name]={'path':str(p),'sha256':sha(p)}
        fix=out/'frozen/tools/fixlink';fix.parent.mkdir(parents=True);shutil.copy2(BASE/'work/fixlink',fix)
        tools['fixlink']={'path':str(BASE/'work/fixlink'),'sha256':sha(fix),'frozen':str(fix.relative_to(out))}
        result['tools']=tools;result['open_watcom_snapshot']=receipt['open_watcom_snapshot']
        headers={}
        for p in sorted((OW/'h').rglob('*')):
            if p.is_file():
                name=str(p.relative_to(OW/'h'));q=out/'frozen/watcom-headers'/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,q)
                headers[name]={'path':str(p),'sha256':sha(p),'frozen':str(q.relative_to(out))}
        result['watcom_header_superset']=headers
        link=BASE/'work/SHZGOP32.lnk';pin(link,receipt['generated_link_inputs']['SHZGOP32.lnk'])
        shutil.copy2(link,out/'baseline/SHZGOP32.lnk')
        objects={}
        for name in re.findall(r'^file (\S+)$',link.read_text(),re.M):
            p=BASE/'work'/name;q=out/'baseline'/name;shutil.copy2(p,q)
            objects[name]={'path':str(p),'sha256':sha(p),'frozen':str(q.relative_to(out))}
        result['baseline_link_object_inputs']=objects
        run([OW/'binl64/wlink','@SHZGOP32.lnk'],out/'baseline')
        result['baseline_before_fixlink_sha256']=sha(out/'baseline/SHZGOP.VXD')
        run([fix,'-vxd32','SHZGOP.VXD'],out/'baseline')
        pin(out/'baseline/SHZGOP.VXD',receipt['artifacts']['SHZGOP.VXD']['sha256'])
        result['baseline_reproduction']={'sha256':sha(out/'baseline/SHZGOP.VXD'),'exact_old_vxd':True}
        shutil.copytree(out/'baseline',out/'candidate')
        for old,new in [('vxd_vesa.c','backend.c'),('vxd_wram.c','vxd_wram.c'),('wram.h','wram.h')]:
            shutil.copy2(out/'frozen/own'/new,out/'candidate'/old)
        patch=''.join(''.join(difflib.unified_diff((out/'baseline'/n).read_text().splitlines(True),(out/'candidate'/n).read_text().splitlines(True),fromfile='baseline/'+n,tofile='candidate/'+n)) for n in ['vxd_vesa.c','wram.h','vxd_wram.c'])
        if patch!=(out/'frozen/own/publication.patch').read_text():raise RuntimeError('Patch does not describe exact candidate')
        result['patch_sha256']=sha(out/'frozen/own/publication.patch')
        host_records={}
        for label in ['baseline','candidate']:
            tree=out/label;host=out/('host-'+label);host.mkdir()
            shutil.copy2(tree/'wram.h',host/'wram.h');shutil.copy2(out/'frozen/own/host_test.c',host/'host_test.c')
            host_records[label]=host_translation(tree,host/'actual_functions.c',label=='baseline')
            for compiler,sanitize in [('gcc',False),('clang',True)]:
                binary=host/(compiler+'-controls')
                argv=[tools[compiler]['path'],'-std=c99','-O2','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-parameter','-Wno-misleading-indentation']
                if label=='baseline':argv+=['-DBASELINE']
                if sanitize:argv+=['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
                argv+=['actual_functions.c','-o',str(binary)]
                run(argv,host);observed=json.loads(run([binary],host));host_records[label][compiler]={'binary_sha256':sha(binary),**observed}
        result['host_controls']=host_records
        for stem in ['vxd_vesa','vxd_wram']:
            command=next(c['argv'] for c in receipt['commands'] if c['argv'][0]=='wcc386' and c['argv'][-1]==stem+'.c')
            command=[str(OW/'binl64/wcc386')]+command[1:]
            run(command,out/'candidate')
            run([OW/'binl64/wdis','-l='+str(out/'candidate'/(stem+'.dis')),stem+'.obj'],out/'candidate')
        run([OW/'binl64/wlink','@SHZGOP32.lnk'],out/'candidate')
        result['candidate_before_fixlink_sha256']=sha(out/'candidate/SHZGOP.VXD')
        run([fix,'-vxd32','SHZGOP.VXD'],out/'candidate')
        package=out/'candidate-package';package.mkdir()
        shutil.copy2(out/'candidate/SHZGOP.VXD',package/'SHZGOP.VXD')
        shutil.copy2(out/'frozen/old-package/SHZGOP.DRV',package/'SHZGOP.DRV')
        for name in ['SHZGOP.INF','LICENSE.MIT','FIXLINK.MIT','GPL-2.0.txt','WATCOM.txt']:
            shutil.copy2(out/'frozen/old-package'/name,package/name)
        shutil.copy2(out/'frozen/own/README.md',package/'CANDIDATE.txt')
        artifacts={p.name:{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(package.iterdir())}
        data=(package/'SHZGOP.VXD').read_bytes();off=struct.unpack_from('<I',data,0x3c)[0]
        if data[off:off+2]!=b'LE':raise RuntimeError('Candidate is not LE')
        if (package/'SHZGOP.DRV').read_bytes()!=(out/'frozen/old-package/SHZGOP.DRV').read_bytes():raise RuntimeError('DRV changed')
        result['candidate_artifacts']=artifacts
        # Reuse only the two exact pure format validators from the pinned original
        # builder. Never import or execute its main, adaptation, tool, or VM paths.
        old_builder=(out/'frozen/original/build.py').read_text()
        module=ast.parse(old_builder)
        validators='import struct\n\n'+'\n\n'.join(ast.get_source_segment(old_builder,n)
            for n in module.body if isinstance(n,ast.FunctionDef) and n.name in ['validate_ne','validate_binaries'])+'\n'
        vp=out/'frozen/format_validators.py';vp.write_text(validators)
        validator_scope={};exec(compile(validators,str(vp),'exec'),validator_scope)
        result['formats']=validator_scope['validate_binaries'](package)
        result['format_validator']={'derived_pure_definitions_from':original['build.py'],
            'frozen':str(vp.relative_to(out)),'sha256':sha(vp)}
        result['candidate_sources']={n:sha(out/'candidate'/n) for n in source_records}
        result['candidate_link_inputs']={n:sha(out/'candidate'/n) for n in objects}
        dis=(out/'candidate/vxd_vesa.dis').read_text()
        draw_dis=dis[dis.index('\tdraw:\n'):dis.index('\tVESA_init_hw:\n')]
        cursor_dis=dis[dis.index('\tpublication_snapshot_cursor:\n'):dis.index('\tdraw:\n')]
        blit_call=draw_dis.index('call\t\twram_publication_blit')
        if not (draw_dis.index('\tcli')<draw_dis.index('\trep movsd')<
                draw_dis.index('call\t\tpublication_snapshot_cursor')<draw_dis.index('\tpopfd')<blit_call):
            # The first popfd is the refused-publication branch; require an
            # additional restored flags path immediately before the actual copy.
            prefix=draw_dis[:blit_call]
            if not (prefix.index('\tcli')<prefix.index('\trep movsd')<
                    prefix.index('call\t\tpublication_snapshot_cursor')<prefix.rindex('\tpopfd')):
                raise RuntimeError('Compiled publication/copy instruction ordering changed')
        if '\tcli' not in draw_dis[blit_call:] or '\tpopfd' not in draw_dis[blit_call:]:
            raise RuntimeError('Compiled completion does not restore flags')
        if cursor_dis.count('call\t\tmemcpy')!=2 or '0x00001000' not in cursor_dis:
            raise RuntimeError('Compiled bounded cursor snapshot changed')
        if 'Wait_Semaphore' in draw_dis or 'FBHDA_lock' in draw_dis:
            raise RuntimeError('Blocking lock reached the publisher')
        result['compiled_controls']={'cpu_flag':'-4s, real Open Watcom i486 LE candidate','format':'LE',
            'unchanged_ne_drv':True,'cursor_snapshot_bytes':8212,'cli_instruction_count':len(re.findall(r'\bcli\b',dis)),
            'popfd_instruction_count':len(re.findall(r'\bpopfd\b',dis)),
            'disassembly_sha256':sha(out/'candidate/vxd_vesa.dis'),
            'cursor_blit_disassembly_sha256':sha(out/'candidate/vxd_wram.dis'),
            'actual_instruction_order':'cli; detached 64-byte descriptor; bounded cursor snapshot; restored flags; pixel copy; cli; inflight clear; restored flags',
            'native_interrupt_flags_and_latency':'pending; host flags are delivery-model controls, not privileged instruction execution'}
        for rec in own.values():pin(Path(rec['path']),rec['sha256'])
        for rec in headers.values():pin(Path(rec['path']),rec['sha256'])
        for name,expected in receipt['compiled_sources'].items():pin(BASE/'work'/name,expected)
        for rec in original.values():pin(Path(rec['path']),rec['sha256'])
        for rec in artifact_records.values():pin(Path(rec['path']),rec['sha256'])
        manifest={'schema':1,'application_success':False,'native_acceptance':'pending',
            'source_changes':['vxd_vesa.c','wram.h','vxd_wram.c'],
            'baseline_vxd_sha256':receipt['artifacts']['SHZGOP.VXD']['sha256'],
            'driver_inputs':{'directory':str(package),'files':artifacts},
            'deployment_authorized':False,'staging_performed':False,'vm_started':False}
        write(out/'manifest.json',manifest);result['manifest_sha256']=sha(out/'manifest.json')
        result['status']='HOST-CANDIDATE-BUILD-PASS'
    except Exception as e:
        result['status']='FROZEN-BUILD-FAIL';result['failure']=str(e);result['traceback']=traceback.format_exc()
    finally:
        result['logs']=logs
        write(out/'result.json',result)
        print(json.dumps({'status':result['status'],'result':str(out/'result.json'),'sha256':sha(out/'result.json'),'failure':result.get('failure')}))
    return 0 if result['status']=='HOST-CANDIDATE-BUILD-PASS' else 1

if __name__=='__main__':raise SystemExit(main())
