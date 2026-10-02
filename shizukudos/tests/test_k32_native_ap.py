#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Captured actual K32 host/ELF32 component checks; no guest execution."""
import argparse, hashlib, json, re, shutil
from pathlib import Path

def sha(b): return hashlib.sha256(b).hexdigest()
ROOT=Path(__file__).resolve().parents[2]
def validate_blob(blob):
    positions=[blob.find(bytes.fromhex(marker)) for marker in ('0fa2','f00fb1','8b6510','0f22d8')]
    order=all(value>=0 for value in positions) and positions==sorted(positions) and len(set(positions))==4
    return 0<len(blob)<0x7fc and blob[:2]==bytes.fromhex('fafc') and bytes.fromhex('0f30') not in blob and order

HELPER_SHA='adcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f'
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);p.add_argument('--baseline',action='store_true');p.add_argument('--compile-units',action='store_true');p.add_argument('--preinit-red',action='store_true');p.add_argument('--withdraw-red',action='store_true');a=p.parse_args()
    out=a.out.resolve();assert out.is_relative_to(ROOT/'build/k32-native-ap-implementation-163f') and not out.exists();out.mkdir()
    helper=ROOT/'build/k32-native-ap-implementation-163f/owned-command-helper.py';hb=helper.read_bytes();assert sha(hb)==HELPER_SHA;(out/'helper.py').write_bytes(hb)
    paths=set(ROOT.glob('shizukudos/kernel32/*.c'))|set(ROOT.glob('shizukudos/kernel32/*.h'))|set(ROOT.glob('shizukudos/kernel32/*.asm'))
    paths|={ROOT/'shizukudos/tests/test_k32_native_ap.c',Path(__file__),ROOT/'shizukudos/tests/run_k32_native_ap.py'}
    paths|=set(ROOT.glob('shizukudos/kernel32/standalone/*'))
    paths|=set(ROOT.glob('shizukudos/kernel64/standalone/*.h'))|{ROOT/'shizukudos/kernel64/standalone/boot32.c',ROOT/'shizukudos/kernel64/smp_acpi.c',ROOT/'shizukudos/kernel64/smp_acpi.h'}
    paths|=set(ROOT.glob('shizukudos/kcommon/*.h'))|set(ROOT.glob('shizukudos/abi/*.h'))|set(ROOT.glob('shizukudos/pma_bridge/*.h'))|set(ROOT.glob('shizukudos/boot_profile/*.h'))
    paths|={ROOT/'shizukudos/kbuild.py',ROOT/'shizukudos/kernel64/standalone/boot_pm.asm',ROOT/'shizukudos/kernel64/standalone/boot.ld'}
    data={str(x.relative_to(ROOT)):x.read_bytes() for x in paths if x.is_file()};before={k:sha(v) for k,v in data.items()}
    frozen=out/'source'
    for k,v in data.items():q=frozen/k;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(v)
    compilers={n:Path(shutil.which(n)).resolve() for n in ('gcc','clang')};tools={str(q):sha(q.read_bytes()) for q in compilers.values()}
    for name in ('nasm','as','ld','nm','objdump','objcopy'):
        q=Path(shutil.which(name)).resolve();tools[str(q)]=sha(q.read_bytes())
    for q in Path('/usr/lib/gcc/x86_64-linux-gnu').glob('*/cc1'):tools[str(q)]=sha(q.read_bytes())
    for q in Path('/usr/lib/llvm-21/lib/clang/21/lib/linux').glob('libclang_rt.asan*x86_64*'):
        if q.is_file():tools[str(q.resolve())]=sha(q.read_bytes())
    for q in Path('/usr/lib/gcc/x86_64-linux-gnu').glob('*/crt*.o'):tools[str(q.resolve())]=sha(q.read_bytes())
    # All bytes are frozen before generated extraction, helper execution or -MM.
    sched=data['shizukudos/kernel32/sched.c'].decode();sched=re.sub(r'^#include[^\n]*\n','',sched,flags=re.M)
    generated='#include "../kernel32/smp_native.h"\n#include "../kernel32/sched_cpu.h"\n#include "../abi/shz_sched_deadline.h"\n'+sched
    (frozen/'shizukudos/tests/generated_sched.inc').write_text(generated)
    mem=re.sub(r'^#include[^\n]*\n','',data['shizukudos/kernel32/mem.c'].decode(),flags=re.M).replace('#define PMM_BASE 0x00400000u','#define PMM_BASE 0x10000000u')
    (frozen/'shizukudos/tests/generated_mem.inc').write_text(mem)
    before['generated_mem.inc']=sha(mem.encode())
    native=data['shizukudos/kernel32/smp_native.c'].decode()
    policy=native[native.index('static int token('):native.index('int k32_ap_snapshot(')]
    (frozen/'shizukudos/tests/generated_policy.inc').write_text(policy)
    before['generated_policy.inc']=sha(policy.encode())
    before['generated_sched.inc']=sha(generated.encode())
    stack_c=r"""/* Actual ELF32 stack helpers; privileged/native admission is not executed. */
typedef unsigned u32;
extern void k32_ap_stack_enter(u32 *,u32,unsigned);
extern void k32_ap_stack_leave(u32,unsigned) __attribute__((noreturn));
static unsigned char idle[16384] __attribute__((aligned(16)));
static u32 saved,boot,entered,withdrawn;
static u32 sp(void) { u32 v;__asm__ volatile("mov %%esp,%0":"=r"(v));return v; }
static void die(u32 code) { __asm__ volatile("int $0x80"::"a"(1),"b"(code):"memory");for(;;); }
static int inside(u32 p) { return p>=(u32)idle && p<(u32)idle+sizeof idle; }
void k32_ap_idle_main(unsigned cpu)
{
    if(cpu!=1 || !inside(sp()) || inside(saved) || !saved)die(71);
    entered=1;k32_ap_stack_leave(saved,cpu);
}
void k32_ap_stack_leave_complete(unsigned cpu)
{
    u32 p=sp();if(cpu!=1 || inside(p) || p<boot-1024 || p>boot+1024 || !entered)die(72);
    withdrawn=1;
}
int test_stack(void)
{
    boot=sp();if(inside(boot))return 73; /* early destination admission is false */
    k32_ap_stack_enter(&saved,(u32)idle+sizeof idle,1);
    if(!entered || !withdrawn || inside(sp()))return 74;
    static const char message[]="K32_AP_STACK real_destination=1 real_withdrawal=1 early_entry_rejected=1; unprivileged-only\n";
    __asm__ volatile("int $0x80"::"a"(4),"b"(1),"c"(message),"d"(sizeof message-1):"memory");return 0;
}
"""
    stack_asm="BITS 32\nSECTION .text\nGLOBAL _start\nEXTERN test_stack\n_start:\n call test_stack\n mov ebx,eax\n mov eax,1\n int 0x80\nSECTION .note.GNU-stack noalloc noexec nowrite progbits\n"
    for name,body in [('stack-control.c',stack_c),('stack-entry.asm',stack_asm)]:
        (out/name).write_text(body);before[name]=sha(body.encode())
    (out/'before.json').write_text(json.dumps({'sources':before,'tools':tools,'helper':sha(hb),'capture_before_consumer':True},indent=2)+'\n')
    external_pins={}
    scope={'__file__':str(out/'helper.py'),'__name__':'captured_lifecycle'};exec(compile(hb,str(out/'helper.py'),'exec'),scope);run=scope['run_owned'];commands=[]
    def call(argv,label):
        assert all((ROOT/k).read_bytes()==v and (frozen/k).read_bytes()==v for k,v in data.items())
        assert all(sha(Path(k).read_bytes())==v for k,v in tools.items())
        assert helper.read_bytes()==hb and (out/'helper.py').read_bytes()==hb
        assert all(sha(Path(k).read_bytes())==v for k,v in external_pins.items())
        assert sha((frozen/'shizukudos/tests/generated_sched.inc').read_bytes())==before['generated_sched.inc']
        assert sha((frozen/'shizukudos/tests/generated_mem.inc').read_bytes())==before['generated_mem.inc']
        assert sha((frozen/'shizukudos/tests/generated_policy.inc').read_bytes())==before['generated_policy.inc']
        assert all(sha((out/k).read_bytes())==before[k] for k in ('stack-control.c','stack-entry.asm'))
        consumed={str(Path(v).resolve()):sha(Path(v).read_bytes()) for v in map(str,argv) if Path(v).is_file()}
        r=run(argv,timeout=30);r['consumed_files_before']=consumed
        r['consumed_files_unchanged']=all(sha(Path(k).read_bytes())==v for k,v in consumed.items())
        r['label']=label;r['timeout_seconds']=30;commands.append(r);(out/(label+'.log')).write_text(r['stdout']+r['stderr']);(out/(label+'-command.json')).write_text(json.dumps(r,indent=2)+'\n')
        assert r['consumed_files_unchanged'];return r
    okay=True
    for n,cc in compilers.items():
        flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-fno-builtin','-Wno-pointer-to-int-cast','-Wno-int-to-pointer-cast']
        if a.baseline:flags+=['-DK32_CAPABILITY_RED']
        if a.preinit_red:flags+=['-DK32_PREINIT_RED']
        if a.withdraw_red:flags+=['-DK32_WITHDRAW_RED']
        if n=='clang':flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
        unit=frozen/'shizukudos/tests/test_k32_native_ap.c';dep=call([cc,*[f for f in flags if f!='-no-pie'],'-MM',unit],n+'-MM');exe=out/(n+'-host')
        c=call([cc,*flags,unit,'-o',exe],n+'-compile');r=call([exe],n+'-run') if c['exit_code']==0 else None
        summary=re.fullmatch(r'K32_WITHDRAW_GATE rc=0 mask=1 actual_ESP_on_idle=1; actual-C host-only\n' if a.withdraw_red else r'K32_PREINIT_GATE rc=0 mask=3; actual-C host-only\n' if a.preinit_red else r'K32_AP_BASELINE public_rc=-2 ignored_ap_tick=1 online=1 checks=2 failures=0; host-only\n' if a.baseline else r'K32_AP_HOST checks=76 failures=0; host-only\n',r['stdout']) if r else None
        okay&=dep['exit_code']==0 and c['exit_code']==0 and r is not None and r['exit_code']==(1 if a.baseline or a.preinit_red or a.withdraw_red else 0) and summary is not None and not r['stderr'] and r['cleanup']['passed']
    dependencies={}
    if a.compile_units:
        units=['arch.c','sched.c','main.c','mem.c','user.c','smp_native.c','smp_firmware.c']
        # Seven real changed top-level units plus the actual native wrapper.
        for name,cc in compilers.items():
            base=['-m32','-march=i486','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-mno-sse','-mno-mmx','-msoft-float','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-ident','-fno-common','-fwrapv','-fno-strict-aliasing']
            if name=='gcc':base+=['-mpreferred-stack-boundary=2','-fno-tree-loop-distribute-patterns']
            else:base+=['-mstack-alignment=4']
            for profile in ('supervisor','standalone'):
                for unit in units:
                    flags=base+(['-DSHZ_STANDALONE'] if profile=='standalone' else [])
                    source=frozen/'shizukudos/kernel32'/unit;label=name+'-'+profile+'-'+unit[:-2]
                    dep=call([cc,*flags,'-M',source],label+'-M');okay&=dep['exit_code']==0
                    if dep['exit_code']==0:
                        import shlex
                        deps=[]
                        for value in shlex.split(dep['stdout'].replace('\\\n',' ').split(':',1)[1]):
                            q=Path(value).resolve();deps.append({'path':str(q),'sha256':sha(q.read_bytes()),'captured_project':q.is_relative_to(frozen)})
                            external_pins[str(q)]=sha(q.read_bytes())
                            if q.is_relative_to(frozen):assert str(q.relative_to(frozen)) in data
                        dependencies[label]=deps
                        (out/(label+'-precompile.json')).write_text(json.dumps(deps,indent=2)+'\n')
                        c=call([cc,*flags,'-c',source,'-o',out/(label+'.o')],label+'-compile');okay&=c['exit_code']==0
            source=frozen/'shizukudos/kernel32/standalone/native_boot32.c'
            dep=call([cc,*base,'-DSTUB_K32','-M',source],name+'-wrapper-M');okay&=dep['exit_code']==0
            if dep['exit_code']==0:
                import shlex
                deps=[]
                for value in shlex.split(dep['stdout'].replace('\\\n',' ').split(':',1)[1]):
                    q=Path(value).resolve();external_pins[str(q)]=sha(q.read_bytes());deps.append({'path':str(q),'sha256':external_pins[str(q)],'captured_project':q.is_relative_to(frozen)})
                    if q.is_relative_to(frozen):assert str(q.relative_to(frozen)) in data
                dependencies[name+'-wrapper']=deps
                (out/(name+'-wrapper-precompile.json')).write_text(json.dumps(deps,indent=2)+'\n')
            c=call([cc,*base,'-DSTUB_K32','-c',source,'-o',out/(name+'-native-wrapper.o')],name+'-wrapper-compile');okay&=c['exit_code']==0
        asm=frozen/'shizukudos/kernel32/smp_ap_trampoline.asm'
        c=call([shutil.which('nasm'),'-f','elf32','-w+all','-o',out/'native-ap.o',asm],'native-ap-assemble');okay&=c['exit_code']==0
        c=call([shutil.which('objdump'),'-r',out/'native-ap.o'],'native-ap-relocations');okay&=c['exit_code']==0 and 'RELOCATION RECORDS FOR [.rodata]' not in c['stdout']
        c=call([shutil.which('objcopy'),'--dump-section','.rodata='+str(out/'native-ap-blob.bin'),out/'native-ap.o',out/'native-ap-dump-copy.o'],'native-ap-blob');okay&=c['exit_code']==0
        if c['exit_code']==0:
            blob=(out/'native-ap-blob.bin').read_bytes()
            order=validate_blob(blob);okay&=order
            missing=blob.replace(bytes.fromhex('0fa2'),bytes.fromhex('9090'))
            old_gate_accepts_missing=(missing.find(bytes.fromhex('0fa2'))<missing.find(bytes.fromhex('f00fb1'))<missing.find(bytes.fromhex('8b6510'))<missing.find(bytes.fromhex('0f22d8')))
            mutants=[b'',blob[:2],missing,blob.replace(bytes.fromhex('f00fb1'),bytes.fromhex('909090')),blob.replace(bytes.fromhex('8b6510'),bytes.fromhex('909090')),blob.replace(bytes.fromhex('0f22d8'),bytes.fromhex('909090')),bytes.fromhex('fafc0f30')+blob[2:],blob+b'\0'*4096]
            controls={'original_pass':validate_blob(blob),'old_missing_CPUID_witness':old_gate_accepts_missing,'rejections':[not validate_blob(v) for v in mutants],'scope':'offline lexical gate only; not hardware execution'}
            okay&=controls['original_pass'] and controls['old_missing_CPUID_witness'] and len(controls['rejections'])==8 and all(controls['rejections'])
            (out/'native-ap-blob-controls.json').write_text(json.dumps(controls,indent=2)+'\n')
            (out/'native-ap-instruction-check.json').write_text(json.dumps({'length':len(blob),'sha256':sha(blob),'relocation_free':True,'CPUID_before_claim_before_ESP_before_CR3':order,'no_WRMSR':bytes.fromhex('0f30') not in blob,'native_execution':False},indent=2)+'\n')
        c=call([shutil.which('nasm'),'-f','elf32','-w+all','-o',out/'native-boot-pm.o',frozen/'shizukudos/kernel64/standalone/boot_pm.asm'],'native-boot-assemble');okay&=c['exit_code']==0
        if (out/'gcc-native-wrapper.o').exists():
            c=call([shutil.which('ld'),'-m','elf_i386','-nostdlib','-z','noexecstack','--no-warn-rwx-segments','-T',frozen/'shizukudos/kernel64/standalone/boot.ld','-o',out/'native-provider.elf',out/'native-boot-pm.o',out/'gcc-native-wrapper.o'],'native-provider-link');okay&=c['exit_code']==0
            c=call([shutil.which('nm'),'-u',out/'native-provider.elf'],'native-provider-symbols');okay&=c['exit_code']==0 and not c['stdout'].strip()
        c=call([shutil.which('nasm'),'-f','elf32','-w+all','-o',out/'stack-entry.o',out/'stack-entry.asm'],'stack-entry-assemble');okay&=c['exit_code']==0
        for name,cc in compilers.items():
            c=call([cc,'-m32','-march=i486','-O2','-Wall','-Wextra','-Werror','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-fno-stack-protector','-c',out/'stack-control.c','-o',out/(name+'-stack-control.o')],name+'-stack-compile');okay&=c['exit_code']==0
            if c['exit_code']==0:
                c=call([shutil.which('ld'),'-m','elf_i386','-nostdlib','-z','noexecstack','-o',out/(name+'-stack-control'),out/'stack-entry.o',out/(name+'-stack-control.o'),out/'native-ap.o'],name+'-stack-link');okay&=c['exit_code']==0
                if c['exit_code']==0:
                    r=call([out/(name+'-stack-control')],name+'-stack-run');okay&=r['exit_code']==0 and r['stdout']=='K32_AP_STACK real_destination=1 real_withdrawal=1 early_entry_rejected=1; unprivileged-only\n' and not r['stderr']
    stable=all((ROOT/k).read_bytes()==v and (frozen/k).read_bytes()==v for k,v in data.items()) and all(sha(Path(k).read_bytes())==v for k,v in tools.items()) and all(sha(Path(k).read_bytes())==v for k,v in external_pins.items())
    okay&=stable and all(c['cleanup']['passed'] and not c['timed_out'] for c in commands)
    artifacts={str(q.relative_to(out)):sha(q.read_bytes()) for q in out.rglob('*') if q.is_file()}
    lane=ROOT/'build/k32-native-ap-implementation-163f';size=sum(q.stat().st_size for q in lane.rglob('*') if q.is_file());assert size<96*1024*1024
    result={'status':('EXPECTED_WITHDRAW_CONTRACT_RED' if a.withdraw_red else 'EXPECTED_PREINIT_CONTRACT_RED' if a.preinit_red else 'EXPECTED_CAPABILITY_RED' if a.baseline else 'PASS') if okay else 'FAIL','inputs_unchanged':stable,'owned_bytes_before_result':size,'artifacts':artifacts,'external_header_pins':external_pins,'commands':commands,'dependencies':dependencies,'sources':before,'tools':tools,'helper':sha(hb),'capture_before_consumer':True,'external_sdk_sealed':False,'physical_ap_executed':False,'guest_executed':False}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(result['status']);return 0 if okay else 1
if __name__=='__main__':raise SystemExit(main())
