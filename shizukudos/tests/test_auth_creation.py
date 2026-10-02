#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual production process constructor with deterministic reentrant allocation."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
FIXTURE=Path(__file__).with_suffix(".c")


def definition(data,name):
    match=re.search(r"^[^\n;{}]*\b"+name+r"\([^;{}]*\)\s*\{",data,re.M)
    if not match:raise ValueError("production definition missing: "+name)
    depth=1
    for i in range(match.end(),len(data)):
        depth+=(data[i]=="{")-(data[i]=="}")
        if not depth:return data[match.start():i+1]
    raise ValueError("unterminated production definition: "+name)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--label",default="current")
    p.add_argument("--compiler",choices=("gcc","clang","all"),default="all");p.add_argument("--recursive-only",action="store_true")
    p.add_argument("--baseline",help="local immutable Git revision for production proc.c only")
    a=p.parse_args();out=ROOT/"build/fd5c2-auth-review"/a.label
    if out.exists():raise SystemExit("fresh output label required")
    proc_path=ROOT/"shizukudos/kernel64/proc.c"
    live_proc_before=proc_path.read_bytes()
    baseline=None
    if a.baseline:
        baseline=subprocess.run(["git","rev-parse",a.baseline+"^{commit}"],cwd=ROOT,check=True,capture_output=True,text=True,timeout=10).stdout.strip()
        baseline_proc=subprocess.run(["git","show",baseline+":shizukudos/kernel64/proc.c"],cwd=ROOT,check=True,capture_output=True,timeout=10).stdout
    pending=[FIXTURE,Path(__file__).resolve(),proc_path]
    sources={}
    while pending:
        f=pending.pop().resolve();rel=f.relative_to(ROOT)
        if rel in sources:continue
        data=baseline_proc if baseline and f==proc_path else f.read_bytes();sources[rel]=data
        pending.extend(f.parent/s.decode() for s in re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"',data,re.M))
    proc=sources[Path("shizukudos/kernel64/proc.c")].decode()
    declarations=proc.split("#define MAX_PROCS",1)[1].split("static uint64_t syscalls;",1)[0]
    fixture=sources[FIXTURE.relative_to(ROOT)].decode().replace("/* @PRODUCTION_PROCESS_DECLARATIONS@ */","#define MAX_PROCS"+declarations)
    fixture=fixture.replace("/* @PRODUCTION_PROCESS_CREATE@ */",definition(proc,"process_create_empty"))
    snap=out/"source"
    for rel,data in sources.items():
        target=snap/rel;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(data)
    unit=snap/FIXTURE.relative_to(ROOT);unit.write_text(fixture)
    results=[]
    for compiler in (["gcc","clang"] if a.compiler=="all" else [a.compiler]):
        cc=shutil.which(compiler)
        if not cc:raise SystemExit("compiler missing: "+compiler)
        exe=out/(compiler+"-creation");flags=["-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror"]
        if compiler=="clang":flags += ["-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"]
        command=[cc,*flags,str(unit),"-o",str(exe)]
        built=subprocess.run(command,capture_output=True,text=True,timeout=30)
        (out/(compiler+"-compile.log")).write_text(built.stdout+built.stderr)
        row={"compiler":compiler,"command":command,"compile_exit":built.returncode}
        if not built.returncode:
            ran=subprocess.run([str(exe),*(["recursive"] if a.recursive_only else [])],capture_output=True,text=True,timeout=15,env=dict(os.environ,ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"))
            (out/(compiler+"-run.log")).write_text(ran.stdout+ran.stderr);row["run_exit"]=ran.returncode
            row["binary_sha256"]=hashlib.sha256(exe.read_bytes()).hexdigest();print(compiler,ran.stdout+ran.stderr,end="")
        else:print(built.stderr)
        results.append(row)
    stable=all((ROOT/f).read_bytes()==(live_proc_before if baseline and ROOT/f==proc_path else data) for f,data in sources.items())
    if baseline:
        stable=stable and subprocess.run(["git","show",baseline+":shizukudos/kernel64/proc.c"],cwd=ROOT,check=True,capture_output=True,timeout=10).stdout==baseline_proc
    receipt={"source_sha256":{str(f):hashlib.sha256(data).hexdigest() for f,data in sources.items()},"source_stable":stable,"results":results,
             "baseline_commit":baseline,"generated_fixture_sha256":hashlib.sha256(unit.read_bytes()).hexdigest(),"scope":"actual process constructor; VM/heap/object/IRQ/reentrant-boundary adapters; no actual scheduler or VMM proof"}
    (out/"result.json").write_text(json.dumps(receipt,indent=2)+"\n")
    return 0 if stable and all(r.get("run_exit",1)==0 for r in results) else 1


if __name__=="__main__":raise SystemExit(main())
