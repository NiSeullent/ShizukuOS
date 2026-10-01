#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify exact profile validation bodies; host API adapters, no VM execution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--output-dir',type=Path,required=True);args=ap.parse_args()
    w64=Path(__file__).resolve().parents[1]
    paths=[w64/'dlls/userenv/userenv.c',Path(__file__),Path(__file__).with_suffix('.c')]
    before={p:p.read_bytes() for p in paths};source=before[paths[0]].decode();start=source.index('/* ---- managed profile contract:');end='/* ---- end managed profile contract ---- */';body=source[start:source.index(end,start)+len(end)]
    records=[]
    with tempfile.TemporaryDirectory(prefix='win98-userenv-profile-') as temp:
        out=Path(temp);(out/'userenv_profile_production.inc').write_text(body);(out/'test.c').write_bytes(before[paths[2]])
        for compiler,flags in [('gcc',['-O2']),('clang',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])]:
            binary=out/compiler;command=[compiler,'-std=c11','-fshort-wchar','-Wall','-Wextra','-Werror',*flags,'-I',str(out),str(out/'test.c'),'-o',str(binary)]
            for argv in [command,[str(binary)]]:
                run=subprocess.run(argv,capture_output=True,text=True,timeout=60);records.append({'command':argv,'returncode':run.returncode,'stdout':run.stdout,'stderr':run.stderr})
                if run.returncode:raise SystemExit(run.stdout+run.stderr)
    assert all(p.read_bytes()==data for p,data in before.items())
    result={'status':'PASS','records':records,'source_pins':{str(p):hashlib.sha256(data).hexdigest() for p,data in before.items()},'exact_production_block_sha256':hashlib.sha256(body.encode()).hexdigest(),'limits':'Declared Windows handle/query host adapters only; no real Windows token/hive or VM/application executed','sources_unchanged':True}
    args.output_dir.mkdir(parents=True,exist_ok=False);(args.output_dir/'host-result.json').write_text(json.dumps(result,indent=2)+'\n');(args.output_dir/'production.inc').write_text(body);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
