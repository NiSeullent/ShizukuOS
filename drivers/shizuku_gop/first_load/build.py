#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile source-bound readonly bootstrap and Win98 loader; no guest/install."""
import argparse,hashlib,importlib.util,json,shutil,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
def sha(b):return hashlib.sha256(b).hexdigest()
def array(name,raw):return 'static const unsigned char '+name+'[]={'+','.join(str(x) for x in raw)+'};\n'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--gop-build',type=Path,required=True);a=p.parse_args()
    out=a.out.resolve();gop=a.gop_build.resolve()
    if out.exists() or not out.is_relative_to((ROOT/'build').resolve()):p.error('fresh component --out under this workspace build required')
    names=['drivers/shizuku_gop/first_load/'+n for n in ('build.py','control.asm','contract.h','guard.c','loader.c','link.ld')]+['drivers/shizuku_gop/gop_contract.h','ntwrapper/vxd/le.py','shizukudos/abi/shz_abi.h','shizukudos/boot_profile/storage/provenance.h']
    inputs={n:(ROOT/n).read_bytes() for n in names};receipt_raw=(gop/'build-result.json').read_bytes();r=json.loads(receipt_raw)
    if r['status']!='HOST-BUILD-PASS' or r['runtime_validation']!='pending: native install/load/GDI rendering requires guest evidence':raise ValueError('actual GOP producer receipt required')
    for n,pin in r['original_inputs'].items():
        raw=(HERE.parent/n).read_bytes()
        if sha(raw)!=pin:raise ValueError('current GOP original input mismatch: '+n)
    gop_raw=(gop/'package/SHZGOP.VXD').read_bytes()
    if sha(gop_raw)!=r['artifacts']['SHZGOP.VXD']['sha256'] or len(gop_raw)!=r['artifacts']['SHZGOP.VXD']['bytes']:raise ValueError('GOP artifact binding')
    identity=hashlib.sha256()
    for name,raw in sorted(inputs.items()):identity.update(name.encode()+b'\0'+len(raw).to_bytes(8,'little')+raw)
    provider=identity.digest();out.mkdir(parents=True);work=out/'source';work.mkdir()
    for n,raw in inputs.items():target=work/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    lane=work/'drivers/shizuku_gop/first_load';(lane/'provider.h').write_text(array('shzguard_provider',provider))
    tools={n:Path(shutil.which(n)).resolve() for n in ('nasm','clang','ld','i686-w64-mingw32-gcc')};toolpins={n:sha(x.read_bytes()) for n,x in tools.items()};commands=[]
    def run(argv):commands.append([str(x) for x in argv]);subprocess.run(commands[-1],check=True)
    run([tools['nasm'],'-f','elf32',lane/'control.asm','-o',out/'control.o'])
    run([tools['clang'],'--target=i386-unknown-none-elf','-march=i486','-std=c11','-Oz','-fno-jump-tables','-ffreestanding','-fno-builtin','-fno-pic','-fno-pie','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mno-sse','-mno-mmx','-msoft-float','-mstack-alignment=4','-Wall','-Wextra','-Werror','-Wno-unused-function','-c',lane/'guard.c','-o',out/'guard.o'])
    run([tools['ld'],'-m','elf_i386','-T',lane/'link.ld','--emit-relocs','--no-undefined','-o',out/'SHZGUARD.elf',out/'control.o',out/'guard.o'])
    # Narrow existing public LE writer retains exactly internal relocations.
    spec=importlib.util.spec_from_file_location('firstload_le',work/'ntwrapper/vxd/le.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    vxd,info=module.package((out/'SHZGUARD.elf').read_bytes())
    if vxd.count(b'NTWRAP9X')!=1:raise ValueError('unique LE resident module rename')
    vxd=vxd.replace(b'NTWRAP9X',b'SHZGUARD');(out/'SHZGUARD.VXD').write_bytes(vxd)
    (lane/'expected.h').write_text(array('shzguard_expected',vxd)+array('shzgop_expected',gop_raw)+array('shzguard_expected_provider',provider))
    run([tools['i686-w64-mingw32-gcc'],'-std=c11','-Os','-Wall','-Wextra','-Werror','-march=i486','-mno-sse','-mno-mmx','-msoft-float','-ffreestanding','-fno-builtin','-fno-stack-protector','-nostdlib','-Wl,--entry,_mainCRTStartup','-Wl,--subsystem,console:4.10','-Wl,--major-os-version,4,--minor-os-version,10,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp',lane/'loader.c','-o',out/'GOPLOAD.EXE','-lkernel32'])
    for n,raw in inputs.items():
        if (ROOT/n).read_bytes()!=raw:raise ValueError('source changed during build: '+n)
    if (gop/'build-result.json').read_bytes()!=receipt_raw or (gop/'package/SHZGOP.VXD').read_bytes()!=gop_raw:raise ValueError('GOP producer mutated')
    for n,x in tools.items():
        if sha(x.read_bytes())!=toolpins[n]:raise ValueError('tool changed')
    result=dict(status='PASS_SOURCE_BUILD_NOT_EXECUTED',sources_sha256={n:sha(raw) for n,raw in inputs.items()},tools={n:dict(path=str(x),sha256=toolpins[n]) for n,x in tools.items()},provider_identity_sha256=provider.hex(),gop_receipt_sha256=sha(receipt_raw),gop_provider_identity_sha256=r['live_provider_identity_sha256'],gop_vxd_sha256=sha(gop_raw),artifacts={n:dict(bytes=(out/n).stat().st_size,sha256=sha((out/n).read_bytes())) for n in ('SHZGUARD.VXD','GOPLOAD.EXE')},commands=commands,le=info,guest_executed=False,default_changed=False,mode_changed=False,gpu_active_verified=False)
    (out/'gop-producer-receipt.json').write_bytes(receipt_raw);(out/'build-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ('status','artifacts')}))
if __name__=='__main__':main()
