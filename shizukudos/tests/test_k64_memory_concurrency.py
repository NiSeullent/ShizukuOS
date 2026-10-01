#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile frozen actual mem/provider bytes and require concurrent ownership controls."""
import argparse
import hashlib
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
def sha(data): return hashlib.sha256(data).hexdigest()
def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--out",type=Path,required=True)
    args=parser.parse_args();out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
    paths=set(ROOT.rglob("*.h"))
    paths.update(ROOT/n for n in ("shizukudos/kernel64/mem.c","shizukudos/kernel64/smp_boot.c","shizukudos/tests/test_k64_memory_concurrency.c","shizukudos/tests/test_k64_pmm_owner.c","shizukudos/tests/test_k64_memory_concurrency.py"))
    captured={str(p.relative_to(ROOT)):p.read_bytes() for p in paths if "build" not in p.relative_to(ROOT).parts}
    frozen=out/"source"
    for name,data in captured.items():
        p=frozen/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
    runs=[];dependencies={};dependency_before={};compiler_commands=[]
    def bind(path):
        path=Path(path).resolve()
        if path.is_file() and str(path) not in dependency_before:
            data=path.read_bytes();dependency_before[str(path)]=sha(data)
            copy=out/"external-dependencies"/str(path).lstrip("/")
            copy.parent.mkdir(parents=True,exist_ok=True);copy.write_bytes(data)
    def runtime_dependencies(binary):
        ldd=Path(shutil.which("ldd")).resolve();bind(ldd);bind("/bin/bash")
        result=subprocess.run([str(ldd),str(binary)],capture_output=True,text=True)
        (out/(Path(binary).name+".runtime-deps.log")).write_text(result.stdout+result.stderr)
        if result.returncode:
            raise SystemExit("runtime dependency discovery failed: "+str(binary))
        for name in re.findall(r"(/[\w./+_-]+)\s+\(",result.stdout):bind(name)
    bind(sys.executable)
    for mode,compiler,extra in (("gcc","gcc",[]),("asan-ubsan","clang",["-fsanitize=address,undefined","-fno-omit-frame-pointer"])):
        binary=out/mode
        compiler=str(Path(shutil.which(compiler)).resolve());bind(compiler)
        command=[compiler,"-std=gnu11","-O1","-g","-Wall","-Wextra","-Werror","-pthread","-mgeneral-regs-only","-mno-red-zone","-ffunction-sections","-fdata-sections",*extra,str(frozen/"shizukudos/tests/test_k64_memory_concurrency.c"),"-Wl,--gc-sections","-o",str(binary)]
        # Discover the exact compiler/linker inputs and actual system headers
        # before compilation. Archive their bytes and check them afterwards.
        trace=subprocess.run(command+["-###"],capture_output=True,text=True,check=True)
        (out/(mode+".tool-trace.log")).write_text(trace.stderr)
        for line in trace.stderr.splitlines():
            try: tokens=shlex.split(line)
            except ValueError: continue
            for token in tokens:
                if token.startswith("/"): bind(token)
        for program in ("as","ld","cc1","collect2"):
            named=subprocess.run([compiler,"-print-prog-name="+program],capture_output=True,text=True,check=True).stdout.strip()
            candidate=Path(named) if named.startswith("/") else Path(shutil.which(named) or named)
            if candidate.is_file():bind(candidate)
        # ldd reports transitive loader dependencies for the compiler/tool
        # executables, including the linker and assembler omitted by GCC's
        # relative command names in -### output.
        for name in list(dependency_before):
            data=Path(name).read_bytes()[:18]
            if data[:4]==b"\x7fELF" and int.from_bytes(data[16:18],"little") in (2,3):
                runtime_dependencies(name)
        for name in ("libc.so","libc.so.6","libgcc.a","libgcc_s.so","libpthread.a","libm.so","libm.so.6"):
            named=subprocess.run([compiler,"-print-file-name="+name],capture_output=True,text=True,check=True).stdout.strip()
            if named.startswith("/"):bind(named)
        depfile=out/(mode+".deps")
        preflight=[item for item in command[:-2] if not item.startswith("-Wl,")]+["-M","-MF",str(depfile)]
        subprocess.run(preflight,capture_output=True,text=True,check=True)
        names=shlex.split(depfile.read_text().replace("\\\n"," ").split(":",1)[1])
        dependencies[mode]=names
        for name in names:
            if not Path(name).is_relative_to(frozen):bind(name)
        compiler_commands.append(command)
        if any(sha(Path(p).read_bytes())!=h for p,h in dependency_before.items()):
            raise SystemExit("compiler/header bytes changed before build")
        build=subprocess.run(command,capture_output=True,text=True);(out/(mode+".compile.log")).write_text(build.stdout+build.stderr)
        if build.returncode==0:runtime_dependencies(binary)
        for case in ("concurrent","reservations","bounds","identity","heap-negatives","heap-fences","observer"):
            try:
                run=subprocess.run([str(binary),case],capture_output=True,text=True,timeout=30) if build.returncode==0 else None
                code=run.returncode if run else None;output=run.stdout+run.stderr if run else ""
            except subprocess.TimeoutExpired as error:
                code=None;output="TIMEOUT: "+str(error)
            (out/(mode+"-"+case+".log")).write_text(output)
            runs.append({"mode":mode,"case":case,"compile_exit":build.returncode,"exit":code,"output":output,"command":command})
        wrapper=out/(mode+"-pmm-owner")
        wrapper_command=[str(frozen/"shizukudos/tests/test_k64_pmm_owner.c") if item.endswith("/test_k64_memory_concurrency.c") else str(wrapper) if item==str(binary) else item for item in command]
        wrapped=subprocess.run(wrapper_command,capture_output=True,text=True)
        if wrapped.returncode==0:runtime_dependencies(wrapper)
        (out/(mode+"-pmm-owner.compile.log")).write_text(wrapped.stdout+wrapped.stderr)
        observed=subprocess.run([str(wrapper)],capture_output=True,text=True,timeout=30) if wrapped.returncode==0 else None
        output=observed.stdout+observed.stderr if observed else ""
        (out/(mode+"-pmm-owner.log")).write_text(output)
        runs.append({"mode":mode,"case":"legacy-observer-entry","compile_exit":wrapped.returncode,"exit":observed.returncode if observed else None,"output":output,"command":wrapper_command})
    stable=all((ROOT/name).read_bytes()==data and (frozen/name).read_bytes()==data for name,data in captured.items())
    external_stable=all(sha(Path(p).read_bytes())==h for p,h in dependency_before.items())
    result={"scope":"actual mem.c/provider; pinned real host CPUID map, IRQ/CR3/direct-map boundaries only; no native AP claim","status":"PASS" if stable and external_stable and all(row["compile_exit"]==row["exit"]==0 for row in runs) else "FAIL","sources_sha256":{n:sha(b) for n,b in sorted(captured.items())},"external_dependencies_sha256":dependency_before,"compiler_dependency_files":dependencies,"executed_source":"frozen captured private source copy","sources_unchanged":stable,"external_dependencies_unchanged":external_stable,"runs":runs}
    (out/"result.json").write_text(json.dumps(result,indent=2)+"\n");print(json.dumps({n:v for n,v in result.items() if n!="sources_sha256"},indent=2));return 0 if result["status"]=="PASS" else 1
if __name__=="__main__": raise SystemExit(main())
