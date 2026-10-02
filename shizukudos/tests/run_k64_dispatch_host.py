#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded source/tool-bound actual C and ASM dispatcher foundation controls."""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / 'shizukudos/tests'
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cc',default='gcc')
    parser.add_argument('--sanitize',action='store_true')
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    tools={name:Path(shutil.which(name)).resolve() for name in (args.cc,'nasm','nm','objdump','objcopy','as','ld')}
    compiler_initial=digest(tools[args.cc])
    for name in ('cc1','collect2','as','ld'):
        reply=subprocess.run([str(tools[args.cc]),'-print-prog-name='+name],capture_output=True,text=True,timeout=10)
        (out/('compiler-tool-'+name+'.log')).write_text(reply.stdout+reply.stderr);reply.check_returncode()
        actual=reply.stdout.strip();path=Path(actual).resolve() if '/' in actual else Path(shutil.which(actual)).resolve() if shutil.which(actual) else None
        if path and path.is_file():tools['compiler_'+name]=path
        elif 'clang' not in tools[args.cc].name or name not in ('cc1','collect2'):raise RuntimeError('unresolved executed compiler tool '+name)
    if digest(tools[args.cc])!=compiler_initial:raise RuntimeError('compiler changed during tool discovery')
    tool_before={str(p):digest(p) for p in tools.values()}
    captured=out/'captured-runner.py';captured.write_bytes(Path(__file__).read_bytes())
    commands=[]
    def run(command,name,**kwargs):
        commands.append([str(v) for v in command])
        try:
            result=subprocess.run(command,capture_output=True,text=True,timeout=60,**kwargs)
        except subprocess.TimeoutExpired as e:
            stdout=e.stdout.decode(errors='replace') if isinstance(e.stdout,bytes) else e.stdout or ''
            stderr=e.stderr.decode(errors='replace') if isinstance(e.stderr,bytes) else e.stderr or ''
            result=subprocess.CompletedProcess(command,124,stdout,stderr+'\nHOST_TIMEOUT:60s\n')
        (out/(name+'.log')).write_text(result.stdout+result.stderr)
        return result
    flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-fno-builtin','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-pthread']
    if args.sanitize:flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    sources=[HERE/('test_k64_dispatch_'+name+'.c') for name in ('context','arch','entry','queue')]
    def closure(phase):
        paths=set()
        units=[(source,[],'') for source in sources]+[(sources[0],['-DSHZ_DISPATCH_HOOK_OVERRIDE'],'-override')]
        for source,defines,suffix in units:
            result=run([str(tools[args.cc]),'-std=gnu11',*defines,'-MM','-MT','dispatch',str(source)],source.stem+suffix+'-deps-'+phase)
            result.check_returncode()
            paths|={Path(v).resolve() for v in shlex.split(result.stdout.replace('\\\n','').split(':',1)[1])}
        paths|={HERE/'test_k64_dispatch_entry.c',Path(__file__).resolve(),ROOT/'shizukudos/kernel64/start.asm'}
        paths|=set((ROOT/'shizukudos/kernel64').glob('user_*.asm'))
        return {str(p.relative_to(ROOT)):digest(p) for p in sorted(paths) if p.is_relative_to(ROOT)}
    before=closure('before');results=[];artifacts={}
    override=out/'dispatch-hook-override.o'
    compile_flags=[f for f in flags if f not in ('-no-pie','-Wl,--gc-sections')]
    run([str(tools[args.cc]),*compile_flags,'-DSHZ_DISPATCH_HOOK_OVERRIDE','-c',str(sources[0]),'-o',str(override)],'dispatch-hook-override-compile').check_returncode()
    artifacts[str(override)]=digest(override)
    for name,source in (('context',sources[0]),('arch',sources[1]),('queue',sources[3])):
        extra=[str(override)] if name=='context' else []
        exe=out/name;compiled=run([str(tools[args.cc]),*flags,str(source),*extra,'-o',str(exe)],name+'-compile')
        if not compiled.returncode:
            artifacts[str(exe)]=digest(exe);result=run([str(exe)],name+'-run');print(result.stdout,end='')
            results.append({'test':'actual_C_'+name,'exit':result.returncode,'checks':'runtime'})
            if name=='queue' and not result.returncode:
                control=run([str(exe)],'queue-watchdog-control',env={**os.environ,'SHZ_DISPATCH_WATCHDOG_CONTROL':'1'})
                okay=control.returncode==124 and 'HOST_TIMEOUT_PROGRESS:' in control.stderr and 'HOST_PROGRESS_FIELDS:' in control.stdout
                results.append({'test':'watchdog_forced_handoff_diagnostic','exit':0 if okay else 1,'actual_exit':control.returncode,'scope':'controlled host-only failure at actual saved-stack handoff'})
        else:results.append({'test':'actual_C_'+name,'exit':compiled.returncode,'checks':'compile_failure'})
    obj=out/'start.o'
    for p in sorted((ROOT/'shizukudos/kernel64').glob('user_*.asm')):
        result=run([str(tools['nasm']),'-f','bin','-w+all','-o',str(out/(p.stem+'.bin')),str(p)],p.stem)
        result.check_returncode()
    result=run([str(tools['nasm']),'-f','elf64','-w+all','-I',str(out)+'/',str(ROOT/'shizukudos/kernel64/start.asm'),'-o',str(obj)],'entry-assemble')
    result.check_returncode();artifacts[str(obj)]=digest(obj)
    renamed=out/'start-host.o';run([str(tools['objcopy']),'--redefine-sym','_start=kernel_test_start',str(obj),str(renamed)],'entry-rename').check_returncode()
    exe=out/'entry';compiled=run([str(tools[args.cc]),*flags,str(HERE/'test_k64_dispatch_entry.c'),str(renamed),'-Wl,-z,noexecstack','-o',str(exe)],'entry-compile')
    if not compiled.returncode:
        artifacts[str(exe)]=digest(exe);result=run([str(exe)],'entry-run');print(result.stdout,end='');results.append({'test':'actual_ASM_window_boundaries','exit':result.returncode})
    else:results.append({'test':'actual_ASM_window_boundaries','exit':compiled.returncode})
    disasm=run([str(tools['objdump']),'-dr','-M','intel',str(obj)],'entry-disasm');disasm.check_returncode()
    no_global='g_kstack_top' not in disasm.stdout and 'g_user_rsp_scratch' not in disasm.stdout
    print(('PASS' if no_global else 'FAIL')+': actual entry object has no singleton syscall stack relocations')
    results.append({'test':'actual_ASM_no_singleton_stack','exit':0 if no_global else 1})
    symbols=run([str(tools['nm']),'-n',str(obj)],'entry-symbols');symbols.check_returncode()
    symbol_map={m.group(2):int(m.group(1),16) for line in symbols.stdout.splitlines() if (m:=re.match(r'^([0-9a-f]+) [tT] (\S+)$',line))}
    instructions=run([str(tools['objdump']),'-d','--no-show-raw-insn','-M','intel',str(obj)],'entry-instructions');instructions.check_returncode()
    text_section=instructions.stdout.split('Disassembly of section .text:',1)[-1]
    opcode={int(m.group(1),16):m.group(2).split()[0] for line in text_section.splitlines() if (m:=re.match(r'^\s*([0-9a-f]+):\s+(.+)$',line))}
    for name,label in (('prologue_before_anchor_GS','syscall_gs_window_start'),('conditional_normalization_before_C','isr_common.gs_ready'),('restored_NT_GS_before_C','syscall_gs_window_end')):
        okay=label in symbol_map and opcode.get(symbol_map[label])=='lfence'
        print(('PASS' if okay else 'FAIL')+': actual ASM speculation barrier '+name)
        results.append({'test':'actual_ASM_barrier_'+name,'exit':0 if okay else 1})
    after=closure('after');tool_after={str(p):digest(p) for p in tools.values()}
    artifacts_after={p:digest(Path(p)) for p in artifacts}
    stable=before==after and tool_before==tool_after and artifacts==artifacts_after and captured.read_bytes()==Path(__file__).read_bytes()
    status='PASS' if stable and all(r['exit']==0 for r in results) else 'FAIL'
    receipt={'status':status,'scope':'actual C logical-owner boundaries and ASM classification/disassembly; no AP or privileged entry execution','results':results,'sources_before':before,'sources_after':after,'tools_before':tool_before,'tools_after':tool_after,'artifacts_before':artifacts,'artifacts_after':artifacts_after,'inputs_stable':stable,'commands':commands}
    (out/'result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    if sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>64*1024*1024:raise RuntimeError('64MiB output budget exceeded')
    return 0 if status=='PASS' else 1
if __name__=='__main__':raise SystemExit(main())
