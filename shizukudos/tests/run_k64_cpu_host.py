#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound actual Kernel64 C and concurrent queue component checks."""
import argparse
import hashlib
import json
import shlex
import subprocess
import time
from pathlib import Path
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cc',default='gcc')
    ap.add_argument('--sanitize',action='store_true')
    ap.add_argument('--out',type=Path,required=True)
    a=ap.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    flags=['-std=gnu11','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-fno-builtin','-Wno-pointer-to-int-cast','-Wno-int-to-pointer-cast','-pthread']
    if a.sanitize: flags+=['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer']
    compiler=Path(subprocess.check_output(['which',a.cc],text=True).strip()).resolve()
    results=[]
    for name in ('test_k64_cpu_api','test_k64_runqueue'):
        source=HERE/(name+'.c');exe=a.out/name
        def closure(phase):
            cmd=[a.cc,*(f for f in flags if f!='-no-pie'),'-MM','-MT','cpu',str(source)]
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
            (a.out/(name+'-'+phase+'-deps.log')).write_text(r.stdout+r.stderr)
            r.check_returncode()
            paths={Path(p).resolve() for p in shlex.split(r.stdout.replace('\\\n','').split(':',1)[1])}
            paths={p for p in paths if p.is_relative_to(REPO)}|{Path(__file__).resolve()}
            return {str(p.relative_to(REPO)):sha(p) for p in sorted(paths)}
        before=closure('before');cc_before=sha(compiler)
        cmd=[a.cc,*flags,str(source),'-o',str(exe)]
        compiled=subprocess.run(cmd,capture_output=True,text=True,timeout=60)
        (a.out/(name+'-compile.log')).write_text(compiled.stdout+compiled.stderr)
        binary_before=sha(exe) if not compiled.returncode else None
        started=time.monotonic();timed_out=False
        try:
            run=subprocess.run([str(exe.resolve())],capture_output=True,text=True,timeout=60) if not compiled.returncode else None
        except subprocess.TimeoutExpired as error:
            timed_out=True
            stdout=error.stdout.decode(errors='replace') if isinstance(error.stdout,bytes) else error.stdout or ''
            stderr=error.stderr.decode(errors='replace') if isinstance(error.stderr,bytes) else error.stderr or ''
            run=subprocess.CompletedProcess([str(exe.resolve())],124,stdout,stderr+'\nHOST_INFRASTRUCTURE_TIMEOUT:60s\n')
        elapsed=time.monotonic()-started
        output=(run.stdout+run.stderr) if run else compiled.stdout+compiled.stderr
        (a.out/(name+'-run.log')).write_text(output);print(output,end='')
        after=closure('after');binary_after=sha(exe) if exe.exists() else None
        stable=before==after and binary_before==binary_after and cc_before==sha(compiler)
        passed=compiled.returncode==0 and run is not None and run.returncode==0 and stable and 'PASS:' in output and 'FAIL:' not in output
        results.append(dict(test=name,status='PASS' if passed else 'FAIL',command=cmd,compile_exit=compiled.returncode,run_exit=run.returncode if run else None,seconds=elapsed,host_timeout=timed_out,sources_before=before,sources_after=after,compiler=str(compiler),compiler_before=cc_before,compiler_after=sha(compiler),binary_before=binary_before,binary_after=binary_after,inputs_stable=stable))
    okay=all(r['status']=='PASS' for r in results)
    (a.out/'result.json').write_text(json.dumps(dict(status='PASS' if okay else 'FAIL',scope='host production C and logical-owner queue operations; no AP execution',tests=results),indent=2)+'\n')
    return 0 if okay else 1
if __name__=='__main__': raise SystemExit(main())
