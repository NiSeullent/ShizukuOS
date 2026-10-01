#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exact-source host contracts; explicit OS adapters, never a Windows/app run."""
import argparse
import hashlib
import json
import random
import re
import subprocess
import tempfile
from pathlib import Path

NEW = ['ucrt_office_legacy_math.c', 'ucrt_office_legacy_mbcs.c', 'ucrt_office_legacy_os.c']
EXPORTS = ['fabs','_mbschr','_mbsinc','_mbsdec','_mbsnbcmp','_mbsnbcpy_s','_chmod','_mktemp',
           '_resetstkoflw','_searchenv','_wgetdcwd','_wassert','system']
PATTERN = re.compile(r'^DLLAPI\s[^;{()]*?\b(\w+)\s*\(', re.M)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir',type=Path)
    args=ap.parse_args()
    w64=Path(__file__).resolve().parents[1]
    owned=[w64/'dlls/ucrtbase'/n for n in NEW]
    owned += [w64/'tests'/n for n in ['test_ucrt_legacy_host.c','test_ucrt_legacy_host.py','ucrt_legacy_host_contract.h']]
    readonly=[w64/'dlls/ucrtbase'/n for n in ['string.c','ctype.c','crtint.h','crtos.h','module.json','wctype_tab.h']]
    inputs={p:p.read_bytes() for p in owned+readonly}
    exports={n for p in owned[:3] for n in PATTERN.findall(inputs[p].decode())}
    assert exports==set(EXPORTS),exports
    aliases=exports|{n for p in readonly[:2] for n in PATTERN.findall(inputs[p].decode())}|{'abort'}
    definitions=''.join('#define %s legacy_%s\n'%(n,n) for n in sorted(aliases))
    calls=''.join('#define %s legacy_%s\n'%(n,n) for n in EXPORTS if n!='fabs')
    rng=random.Random(0x01a0f3d0cb43)
    bits=[0,1,0x8000000000000000,0x8000000000000001,0xfff0000000000000,
          0x7ff0000000000000,0xfff8000000000042,0xfff0000000000001,0x0010000000000000]
    bits += [rng.getrandbits(64) for _ in range(12000)]
    oracle='static const uint64_t absolute_vectors[]={'+','.join('UINT64_C(%d)'%x for x in bits)+'};\n'
    runs=[]
    with tempfile.TemporaryDirectory(prefix='win98-ucrt-legacy-') as folder:
        tmp=Path(folder)
        for p,data in inputs.items():
            target=tmp/p.relative_to(w64);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
        (tmp/'legacy_renames.inc').write_text(definitions)
        (tmp/'legacy_calls.inc').write_text(calls)
        (tmp/'legacy_vectors.inc').write_text(oracle)
        for cc,flags,label in [('gcc',['-O2'],'gcc'),('clang',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'],'clang-san')]:
            common=[cc,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-Wno-unused-function','-fno-builtin',*flags,'-DSHZ_HOST_TEST','-DSHZ_UCRT_LEGACY_HOST','-I',str(tmp)]
            objects=[]
            commands=[]
            for source in NEW+['string.c','ctype.c']:
                obj=tmp/(label+'-'+source+'.o')
                command=[*common,'-include',str(tmp/'legacy_renames.inc'),'-c',str(tmp/'dlls/ucrtbase'/source),'-o',str(obj)]
                built=subprocess.run(command,capture_output=True,text=True,timeout=180);commands.append(command)
                if built.returncode:raise SystemExit(built.stdout+built.stderr)
                objects.append(str(obj))
            exe=tmp/(label+'-contract')
            command=[*common,'-pthread',str(tmp/'tests/test_ucrt_legacy_host.c'),*objects,'-lm','-o',str(exe)]
            built=subprocess.run(command,capture_output=True,text=True,timeout=180);commands.append(command)
            if built.returncode:raise SystemExit(built.stdout+built.stderr)
            result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=120)
            if result.returncode:raise SystemExit(result.stdout+result.stderr)
            runs.append({'compiler':label,'commands':commands,'stdout':result.stdout,'exit_code':0,'binary_sha256':hashlib.sha256(exe.read_bytes()).hexdigest()})
        if args.output_dir:
            args.output_dir.mkdir(parents=True,exist_ok=True)
            (args.output_dir/'legacy_vectors.inc').write_text(oracle)
            (args.output_dir/'legacy_renames.inc').write_text(definitions)
    assert all(p.read_bytes()==d for p,d in inputs.items()),'Consumed source changed'
    result={'status':'HOST_GCC_AND_CLANG_SAN_PASS','runs':runs,'source_sha256':{str(p):hashlib.sha256(d).hexdigest() for p,d in inputs.items()},
            'actual_new_exports':sorted(exports),'independent_math_vectors':len(bits),'math_oracle':'glibc fabs bit-exact comparison including signed zero, infinity, subnormal and quiet/signalling NaN payloads',
            'oracle_sha256':hashlib.sha256(oracle.encode()).hexdigest(),'claims':{'host_OS_adapters':True,'actual_existing_string_and_C_locale_providers':True,'native_run':False,'application_run':False}}
    if args.output_dir:(args.output_dir/'host-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
