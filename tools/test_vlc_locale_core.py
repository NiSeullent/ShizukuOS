#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual portable locale parser/geographical/NLS controls, not a guest launch."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);args=parser.parse_args();out=args.out.resolve()
    if out.exists():parser.error('fresh output required')
    sources=('src/m98_vlc_locale_core.h','src/m98_vlc_locale_core.c','src/m98_vlc_geo.inc','tests/vlc_locale_core_test.c','tools/test_vlc_locale_core.py')
    identities={s:sha(ROOT/s) for s in sources};cc=shutil.which('clang')
    if not cc:parser.error('existing Clang required')
    out.mkdir(parents=True);exe=out/'locale-core-test'
    command=[cc,'--no-default-config','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(ROOT/'src'),str(ROOT/'src/m98_vlc_locale_core.c'),str(ROOT/'tests/vlc_locale_core_test.c'),'-o',str(exe)]
    compiled=subprocess.run(command,capture_output=True,text=True,timeout=120);(out/'compile.log').write_text(compiled.stdout+compiled.stderr);compiled.check_returncode()
    run=subprocess.run([str(exe)],capture_output=True,text=True,timeout=120);(out/'host.log').write_text(run.stdout+run.stderr);run.check_returncode()
    if any(sha(ROOT/s)!=h for s,h in identities.items()):raise ValueError('source changed during run')
    snapshots=out/'source';snapshots.mkdir()
    for s in sources:shutil.copyfile(ROOT/s,snapshots/Path(s).name)
    receipt={'status':'PASS','native_executed':False,'sources':identities,'compiler':{'path':cc,'sha256':sha(Path(cc))},'command':command,'sanitizers':['address','undefined'],'actual_c_result':run.stdout,'scope':'Bounded portable numeric parser,301-record factual geo lookup and native-NLS callback decision controls; Win98 registry/UI/API execution not established.'}
    result=out/'host-result.json';result.write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'PASS','receipt':str(result),'actual_c_result':run.stdout}))
if __name__=='__main__':main()
