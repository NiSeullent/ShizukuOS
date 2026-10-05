#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Closed Dead Screen host + Kernel64 build. Never edits default sources or runs a VM."""
import argparse
import ast
import datetime
import difflib
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
OWN = REPO / 'shizukudos/dead_screen'
HISTORY_RECEIPTS = {
    'build/dead-screen-candidate-20261001T1035-v1/result.json':'b5a9e1298dfb875a6ea553e9a37344ea2cc0c986d1e9d4a7036799dd4a4e2642',
    'build/dead-screen-candidate-20261001T1040-v2/result.json':'5d1ee9d489a78af5938eb8945a73344e6a7bdadfee362b16a8257c162e5848c6',
    'build/dead-screen-candidate-20261001T1045-v3/result.json':'7e9c6bfcfa7ae77b66509da866db06129459b25bd5d84f1ad30fee0fa0ceafc6',
    'build/dead-screen-candidate-20261001T1100-v4/result.json':'934a1bdc4caabf78ea481af8ee5b65c2d7887851e2ecb82b18b1d70e6a9b6799',
}

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def record(p):
    p=Path(p)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}

def collect_history(repo, verify):
    """Private lab provenance is optional and never a native acceptance claim."""
    if not verify:
        return {}
    parents={}
    for rel,want in HISTORY_RECEIPTS.items():
        p=repo/rel
        if not p.is_file() or sha(p)!=want:
            raise RuntimeError('parent receipt differs '+rel)
        parents[rel]=record(p)
    return parents

def replace_once(s,a,b):
    if s.count(a)!=1:
        raise RuntimeError('private integration seam differs: '+a[:100])
    return s.replace(a,b,1)

def integration_state(base):
    """Admit either seven bare seams or a coherent already integrated kernel.

    Partial/duplicate hooks cannot be silently completed or compiled as a
    baseline lacking their implementations. This also makes changed idempotent.
    """
    seams={
        'lib.c':('static void putc_line(char c)\n{\n    ds_native_capture_char(c);',
                 '    cli();\n    ds_native_capture_begin();\n    kprintf("K64 PANIC: ");',
                 'ds_native_panic((uint64_t)__builtin_return_address(0), sp, bp);'),
        'arch.c':('    if (!(r->cs & 3)) ds_native_exception(r);\n    shz_exit(98);',),
        'main.c':('    mem_init(&bootinfo);\n    ds_native_init();',
                  '    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);\n#ifdef SHZ_STANDALONE\n    ds_native_timer_ready();\n#endif',
                  '    sti();\n    ds_native_control();\n    if (k64_cmdline_has('),
        'gfx_fb.c':('    pci_claim(&dev, "gfx_fb (Bochs VBE)");\n    ds_native_bind(fb->lfb, fb->width, fb->height, fb->pitch, (size_t)fb->pitch * h, 0);',),
        'gfx_gop.c':('    ds_native_bind(gop.fb, b.width, b.height, b.pitch, (size_t)b.pitch * b.height, gop.rgbx);\n    return 0;\n}\n\nstatic void gop_present',),
        'gfx_input.c':('    if (dat_read(0) == 0xFA) g_info |= SHZ_INFO_KEYBOARD;\n    ds_native_keyboard_ready((g_info & SHZ_INFO_KEYBOARD) != 0);',),
        'gfx_wm.c':('int ds_native_control_prepare_gui(void) { return wm_init(); }',),
    }
    if set(base)!=set(seams):
        raise RuntimeError('incoherent integration source set')
    counts=[base[n].count(s) for n,items in seams.items()
            for s in ('#include "../dead_screen/native.h"',*items)]
    if not any(counts):
        if any('ds_native_' in s for s in base.values()):
            raise RuntimeError('partial integration has unknown native hooks')
        return False
    raw_counts=[base[n].count(name+'(') for n,items in seams.items()
                for name in sorted(set(re.findall(r'\b(ds_native_\w+)\(', '\n'.join(items))))]
    if all(c==1 for c in counts) and all(c==1 for c in raw_counts):return True
    raise RuntimeError('partial or incoherent Dead Screen integration')

def changed(base):
    """Exact actual seams; default files are read once and never written."""
    if integration_state(base):return dict(base)
    out={}
    for name in ('lib.c','arch.c','main.c','gfx_fb.c','gfx_gop.c','gfx_input.c','gfx_wm.c'):
        s=base[name]
        anchor='#include "k64.h"' if name in ('lib.c','arch.c') else '#include "proc_internal.h"' if name=='main.c' else '#include "gfx.h"'
        s=replace_once(s,anchor,anchor+'\n#include "../dead_screen/native.h"')
        if name=='lib.c':
            s=replace_once(s,'static void putc_line(char c)\n{','static void putc_line(char c)\n{\n    ds_native_capture_char(c);')
            s=replace_once(s,'    cli();\n    kprintf("K64 PANIC: ");','    cli();\n    ds_native_capture_begin();\n    kprintf("K64 PANIC: ");')
            s=replace_once(s,'    shz_exit(99);','    uint64_t sp, bp;\n    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));\n    __asm__ volatile("mov %%rbp, %0" : "=r"(bp));\n    ds_native_panic((uint64_t)__builtin_return_address(0), sp, bp);')
        elif name=='arch.c':
            s=replace_once(s,'    shz_exit(98);','    if (!(r->cs & 3)) ds_native_exception(r);\n    shz_exit(98);')
        elif name=='main.c':
            s=replace_once(s,'    mem_init(&bootinfo);','    mem_init(&bootinfo);\n    ds_native_init();')
            s=replace_once(s,'    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);','    KASSERT(shz_timer_set(VEC_TIMER, TICK_US) == 0);\n#ifdef SHZ_STANDALONE\n    ds_native_timer_ready();\n#endif')
            # The current production installer precedes the desktop branch;
            # older bare source snapshots have only the desktop branch here.
            profile='shz.setup=interactive' if 'k64_cmdline_has("shz.setup=interactive")' in s else 'shz.desktop'
            anchor='    sti();\n    if (k64_cmdline_has("'+profile+'"))'
            s=replace_once(s,anchor,'    sti();\n    ds_native_control();\n    if (k64_cmdline_has("'+profile+'"))')
        elif name=='gfx_fb.c':
            s=replace_once(s,'    pci_claim(&dev, "gfx_fb (Bochs VBE)");','    pci_claim(&dev, "gfx_fb (Bochs VBE)");\n    ds_native_bind(fb->lfb, fb->width, fb->height, fb->pitch, (size_t)fb->pitch * h, 0);')
        elif name=='gfx_gop.c':
            s=replace_once(s,'    return 0;\n}\n\nstatic void gop_present','    ds_native_bind(gop.fb, b.width, b.height, b.pitch, (size_t)b.pitch * b.height, gop.rgbx);\n    return 0;\n}\n\nstatic void gop_present')
        elif name=='gfx_input.c':
            s=replace_once(s,'    if (dat_read(0) == 0xFA) g_info |= SHZ_INFO_KEYBOARD;','    if (dat_read(0) == 0xFA) g_info |= SHZ_INFO_KEYBOARD;\n    ds_native_keyboard_ready((g_info & SHZ_INFO_KEYBOARD) != 0);')
        else:
            s=replace_once(s,'int32_t sys_ext_graphics(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)',
                'int ds_native_control_prepare_gui(void) { return wm_init(); }\n\nint32_t sys_ext_graphics(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)')
        out[name]=s
    return out

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',required=True,type=Path)
    ap.add_argument('--verify-history',action='store_true',
                    help='require exact private lab predecessor receipts; does not verify native execution')
    args=ap.parse_args()
    out=args.out.resolve()
    if not out.is_relative_to(REPO/'build') or out.exists():
        raise SystemExit('require NEW output beneath build/')
    out.mkdir(parents=True)
    logs=[];commands=[];tools={};inputs={};artifacts={};parents={};runtime={}
    history={'requested':args.verify_history,'status':'PENDING' if args.verify_history else 'NOT_REQUESTED'}
    result={'status':'FAIL','build_scope':'source-build-and-host-controls','history_verification':history,
            'native_execution':False,'win98_vmm_acceptance':False,'app_success':False}
    def run(cmd,label):
        cmd=[str(x) for x in cmd];commands.append(cmd)
        p=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,cwd=REPO)
        logfile=out/'logs'/(str(len(logs)).zfill(3)+'-'+label+'.log');logfile.parent.mkdir(exist_ok=True)
        logfile.write_bytes(p.stdout)
        logs.append({**record(logfile),'exit_code':p.returncode,'command':cmd})
        if p.returncode:
            raise RuntimeError(label+' exited '+str(p.returncode)+': '+p.stdout.decode(errors='replace')[-4000:])
        return p.stdout.decode(errors='replace')
    try:
        for name in ('gcc','clang','nasm','ld','nm','objcopy','objdump','as'):
            path=Path(shutil.which(name) or '')
            if not path.is_file():raise RuntimeError('missing compiler '+name)
            tools[name]=record(path.resolve())
            run([path,'--version'],name+'-version')
            shared=run(['ldd',path.resolve()],name+'-runtime') if name not in ('nasm',) else ''
            for raw in re.findall(r'(/[^\s()]+)',shared):
                p=Path(raw)
                if p.is_file():runtime[str(p.resolve())]=record(p.resolve())
        cc1=Path(run(['gcc','-print-prog-name=cc1'],'cc1-path').strip())
        tools['gcc-cc1']=record(cc1)
        tools['python3']=record(Path(shutil.which('python3')).resolve())
        parents=collect_history(REPO,args.verify_history)
        if args.verify_history:
            history['status']='VERIFIED'
        # Snapshot a closed include tree, not arbitrary default build outputs.
        dirs=('shizukudos/kernel64','shizukudos/kcommon','shizukudos/abi','shizukudos/win64/include',
              'shizukufs/v1/libsfs','drivers/ahci_native')
        paths={p for d in dirs for p in (REPO/d).rglob('*') if p.is_file() and p.suffix in ('.c','.h','.asm','.ld')}
        paths.update([REPO/'shizukudos/win64/pe_parse.c',REPO/'shizukudos/win64/pe_parse.h',
                      REPO/'shizukudos/supervisor/src/font8x8_basic.h',REPO/'shizukudos/kbuild.py'])
        paths.update(p for p in OWN.iterdir() if p.is_file())
        for p in sorted(paths):
            rel=p.relative_to(REPO);inputs[str(rel)]=record(p)
            dst=out/'frozen'/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dst)
        frozen=out/'frozen'
        base={n:(frozen/'shizukudos/kernel64'/n).read_text() for n in ('lib.c','arch.c','main.c','gfx_fb.c','gfx_gop.c','gfx_input.c','gfx_wm.c')}
        already_integrated=integration_state(base)
        edited=changed(base)
        result['integration_profile']='already-default-integrated' if already_integrated else 'isolated-adapter-patch'
        result['integration_patch_applied']=not already_integrated
        patch=''
        for n in edited:
            patch+=''.join(difflib.unified_diff(base[n].splitlines(True),edited[n].splitlines(True),
                    fromfile='a/shizukudos/kernel64/'+n,tofile='b/shizukudos/kernel64/'+n))
        (out/'integration.patch').write_text(patch)
        artifacts['integration_patch']=record(out/'integration.patch')
        # Host uses actual functions. Sanitizer runtime dependencies are captured
        # through compiler -MD and ldd later; native build never links them.
        host_flags=['-std=gnu11','-O2','-Wall','-Wextra','-Werror','-fno-strict-aliasing']
        local=frozen/'shizukudos/dead_screen'
        host_results=[];native_host_results=[]
        abi_exe=out/'abi-probe'
        run(['gcc',*host_flags,'-MD','-MF',out/'abi-probe.d',local/'abi_probe.c','-o',abi_exe],'abi-compile')
        result['abi']=json.loads(run([abi_exe],'abi-run'))
        for compiler,extra in (('gcc',[]),('clang',['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer'])):
            exe=out/(compiler+'-host')
            run([compiler,*host_flags,*extra,'-MD','-MF',out/(compiler+'-host.d'),local/'dead_screen.c',local/'render.c',local/'host_test.c','-o',exe],compiler+'-host-compile')
            host_results.append(json.loads(run([exe],compiler+'-host-run').strip()))
            nativetest=out/(compiler+'-native-host')
            run([compiler,*host_flags,*extra,'-DSHZ_STANDALONE','-DDS_NATIVE_HOST_TEST','-MD','-MF',out/(compiler+'-native-host.d'),
                 local/'dead_screen.c',local/'render.c',local/'native.c',local/'native_host_test.c','-o',nativetest],compiler+'-native-host-compile')
            for mode in ('exception','panic','fallback','reentry','uartfail','small','force-text','corrupt-game','nyan-pcm','nyan-pitched','nyan-fixed','nyan-silent','nyan-degrade',
                         'cross-cpu-reentry','other-cpu-first','unknown-cpu','capture-exception','capture-other-cpu','nyan-fixed-loss'):
                native_host_results.append(json.loads(run([nativetest,mode],compiler+'-native-host-'+mode).strip()))
            controltest=out/(compiler+'-control-host')
            run([compiler,*host_flags,*extra,'-DSHZ_STANDALONE','-DDS_NATIVE_HOST_TEST','-MD','-MF',out/(compiler+'-control-host.d'),
                 local/'control.c',local/'control_host_test.c','-o',controltest],compiler+'-control-host-compile')
            result.setdefault('control_host',[]).append(json.loads(run([controltest],compiler+'-control-host-run')))
            run(['ldd',exe],compiler+'-host-runtime')
            run(['ldd',nativetest],compiler+'-native-host-runtime')
        # Separate explicitly labelled host raster exports, not VM screenshots.
        preview=out/'host-render';preview.mkdir()
        run([out/'gcc-host',preview],'host-raster-export')
        # Format export of actual C raster, never editing an attached screenshot.
        from PIL import Image
        for p in sorted(preview.glob('*.ppm')):Image.open(p).save(p.with_suffix('.png'))
        # Native flags mechanically taken from exact existing builder, never imported/executed.
        tree=ast.parse((frozen/'shizukudos/kbuild.py').read_text())
        flags=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and
                   any(isinstance(t,ast.Name) and t.id=='K64_FLAGS' for t in n.targets))
        def kernel(root,name,add=False):
            dest=out/name;obj=dest/'obj';obj.mkdir(parents=True)
            kd=root/'shizukudos/kernel64';objects=[]
            for src in sorted(kd.glob('user_*.asm')):
                run(['nasm','-f','bin','-w+all','-o',obj/(src.stem+'.bin'),src],name+'-'+src.stem)
            for src in sorted(kd.glob('*.asm')):
                if src.stem.startswith('user_'):continue
                o=obj/(src.stem+'.asm.o');objects.append(o)
                run(['nasm','-f','elf64','-w+all','-I',str(obj)+'/', '-o',o,src],name+'-'+src.stem)
            cfiles=[*sorted(kd.glob('*.c')),root/'shizukudos/win64/pe_parse.c',kd/'standalone/standalone64.c',
                    root/'drivers/ahci_native/ahci.c',*sorted((root/'shizukufs/v1/libsfs').glob('*.c'))]
            if add:cfiles += [root/'shizukudos/dead_screen'/n for n in ('dead_screen.c','render.c','native.c','control.c')]
            for src in cfiles:
                o=obj/(src.stem+'.o');objects.append(o)
                run(['gcc',*flags,'-DSHZ_STANDALONE','-fmacro-prefix-map='+str(root)+'='+str(REPO),
                     '-I',root/'shizukudos','-I',kd,'-MD','-MF',o.with_suffix('.d'),'-c',src,'-o',o],name+'-'+src.stem)
            elf=dest/(name+'.elf')
            run(['ld','-m','elf_x86_64','-static','-nostdlib','-z','max-page-size=4096','-z','noexecstack',
                 '--no-warn-rwx-segments','-T',kd/'link.ld','-o',elf,*objects],name+'-link')
            if run(['nm','-u',elf],name+'-undefined').strip():raise RuntimeError('unresolved native dependencies')
            symbols=run(['nm','-n',elf],name+'-symbols');(dest/'symbols.txt').write_text(symbols)
            end=int(next(line.split()[0] for line in symbols.splitlines() if line.endswith(' __bss_end')),16)
            if end-0xffffffff80000000>0x300000:raise RuntimeError('image/bss overlaps original heap')
            binary=dest/'KERNEL64S.BIN';run(['objcopy','-O','binary',elf,binary],name+'-binary')
            dis=run(['objdump','-d','-M','intel',elf],name+'-disassembly');(dest/'disassembly.txt').write_text(dis)
            return {'elf':record(elf),'bin':record(binary),'bss_end':hex(end),'objects':[record(o) for o in objects]}
        baseline=kernel(frozen,'baseline',already_integrated)
        candidate_root=out/'patched';shutil.copytree(frozen,candidate_root)
        for n,s in edited.items():(candidate_root/'shizukudos/kernel64'/n).write_text(s)
        candidate=kernel(candidate_root,'candidate',True)
        symbols=(out/'candidate/symbols.txt').read_text()
        for seam in ('ds_native_panic','ds_native_exception','ds_native_bind','ds_key_event','ds_suika_step','ds_render',
                     'ds_native_control','ds_native_control_prepare_gui','ds_fallback_framebuffer'):
            if not re.search(r' [Tt] '+seam+r'$',symbols,re.M):raise RuntimeError('missing actual linked seam '+seam)
        direct_undefined={}
        for name in ('dead_screen','render','native'):
            obj=out/'candidate/obj'/(name+'.o')
            refs=run(['nm','-u',obj],'candidate-'+name+'-direct-imports')
            direct_undefined[name]=refs
            if re.search(r'\b(kmalloc|kzalloc|kfree|malloc|calloc|free|mutex_lock|thread_block_current|shz_time_ns)\b',refs):
                raise RuntimeError('unsafe fatal-time dependency '+name)
        result['direct_undefined']=direct_undefined
        control_disasm=run(['objdump','-d','-M','intel',out/'candidate/obj/control.o'],'native-control-disassembly')
        if not re.search(r'\bud2\b',control_disasm):raise RuntimeError('native controlled #UD opcode missing')
        # Every compiler dependency is pinned, including real installed headers.
        headers={}
        for dep in sorted(out.rglob('*.d')):
            data=dep.read_text().replace('\\\n',' ');parts=data.split(':',1)[1].split()
            for token in parts:
                p=Path(token)
                if p.is_file():headers[str(p)]=record(p)
        (out/'compiler-inputs.json').write_text(json.dumps(headers,ensure_ascii=False,indent=2)+'\n')
        for p in [out/'abi-probe',out/'gcc-host',out/'clang-host',out/'gcc-native-host',out/'clang-native-host',
                  out/'gcc-control-host',out/'clang-control-host',out/'compiler-inputs.json',*sorted((out/'host-render').glob('*'))]:
            artifacts[str(p.relative_to(out))]=record(p)
        for n in edited:
            artifacts['patched-source/'+n]=record(candidate_root/'shizukudos/kernel64'/n)
        result['patched_source_base_sha256']={n:hashlib.sha256(s.encode()).hexdigest() for n,s in base.items()}
        for key,pin in inputs.items():
            if sha(REPO/key)!=pin['sha256']:raise RuntimeError('current source changed during build '+key)
            if sha(frozen/key)!=pin['sha256']:raise RuntimeError('frozen source changed '+key)
        for pin in tools.values():
            if sha(pin['path'])!=pin['sha256']:raise RuntimeError('compiler changed '+pin['path'])
        for pin in runtime.values():
            if sha(pin['path'])!=pin['sha256']:raise RuntimeError('compiler runtime changed '+pin['path'])
        previous=REPO/'build/shizukudos/kernel64s/KERNEL64S.BIN'
        result.update(status='PASS',host=host_results,host_io_model=native_host_results,baseline=baseline,candidate=candidate,
                      existing_default_binary=record(previous) if previous.is_file() else None,
                      baseline_equals_existing=previous.is_file() and sha(previous)==baseline['bin']['sha256'],
                      ordinary_sources_unchanged=True,native_acceptance_pending=True,
                      trace_scope='actual captured addresses/registers; no unsafe unwinding; host controls are synthetic fault inputs',
                      publication_pending=True)
    except Exception as exc:
        result['failure']=str(exc)
        if history['status']=='PENDING':
            history['status']='FAILED'
    manifest={'utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'sources':inputs,'tools':tools,'tool_runtime':runtime,'parents':parents,
              'build_scope':result['build_scope'],'history_verification':history,
              'artifacts':artifacts,'logs':logs,'commands':commands,'permissions':'source edits/private local builds only; no VM/staging/default changes'}
    (out/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n')
    result['manifest']=record(out/'manifest.json')
    (out/'result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({'result':record(out/'result.json'),'status':result['status'],'failure':result.get('failure')}))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
