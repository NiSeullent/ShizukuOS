#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded capacity/normal-path checks of exact MoveFileExW function bytes.

Requires explicit --production-source and a fresh --output-dir under build/.
CAPACITY rejects the original source at compile time because its destination
array cannot cover its converter buffer. It never runs the original function.
GREEN applies the exact-preimage unified patch in memory, then runs ordinary
valid-path/lifecycle checks and compiles with the installed Win64 SDK. No guest,
native Windows executable, invalid buffer, download, or peer edit occurs.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = "0ceafb9186cf370c2f1b5bdcfec166e6a5aa6a2c67e6c2b77ab3c748d0ccd415"
RESERVE, BUDGET, RAM, RSS = 20*1024**3, 8*1024**2, 6*1024**3, 512*1024**2
FALSE = {"native_Windows_execution": False, "guest_execution": False,
         "modern_app_functionality_verified": False, "OS_acceptance_verified": False}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical input: "+str(path))
    with path.open("rb") as f:
        before = os.fstat(f.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size <= 1024**2, "nonregular/oversized source")
        data = f.read(1024**2+1)
        after = os.fstat(f.fileno())
    require(len(data) == before.st_size and all(getattr(before,k)==getattr(after,k)
            for k in ("st_dev","st_ino","st_size","st_mtime_ns","st_ctime_ns")), "source changed during read")
    return data


def stream_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024**2), b""):
            h.update(chunk)
    return h.hexdigest()


def available():
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1])*1024
    raise ValueError("cannot measure available memory")


def members(directory):
    result = {}
    if not directory.exists():
        return result
    for path in directory.rglob("*"):
        require(not path.is_symlink(), "unexpected output symlink")
        if path.is_file():
            result[str(path.relative_to(directory))] = {"bytes":path.stat().st_size,"sha256":stream_sha(path)}
    return result


def group_rss(group):
    total = 0
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            fields = (directory/"stat").read_text().rsplit(")",1)[1].split()
            if int(fields[2]) == group:
                total += next((int(line.split()[1])*1024 for line in (directory/"status").read_text().splitlines()
                               if line.startswith("VmRSS:")),0)
        except (OSError,ValueError,IndexError):
            continue
    return total


def extract(source, signature):
    start = source.find(signature)
    require(start >= 0 and source.find(signature,start+1)<0,"missing/ambiguous production function")
    # Frozen candidate functions have no brace-bearing literals/comments.
    opening = source.index("{",start)
    level = 0
    for i in range(opening,len(source)):
        if source[i] == "{": level += 1
        elif source[i] == "}":
            level -= 1
            if not level:
                return source[start:i+1]+"\n"
    raise ValueError("unterminated function")


def apply_exact(source, patch):
    rows = patch.splitlines(keepends=True)
    require(rows[:2] == ["--- a/shizukudos/win64/kernel32/k32_file.c\n",
                         "+++ b/shizukudos/win64/kernel32/k32_file.c\n"],"unexpected patch target")
    original = source.splitlines(keepends=True)
    output, position, i = [],0,2
    while i < len(rows):
        m = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n",rows[i])
        require(m is not None,"malformed patch hunk")
        at = int(m[1])-1;old_n=int(m[2] or 1);new_n=int(m[4] or 1)
        require(position <= at <= len(original),"overlapping patch")
        output.extend(original[position:at]);position=at;i+=1;old_seen=new_seen=0
        while i<len(rows) and not rows[i].startswith("@@ "):
            row=rows[i];require(row[:1] in (" ","+","-"),"unsupported patch row")
            if row[0] in " -":
                require(position<len(original) and original[position]==row[1:],"patch preimage mismatch")
                position+=1;old_seen+=1
            if row[0] in " +":output.append(row[1:]);new_seen+=1
            i+=1
        require(old_seen==old_n and new_seen==new_n,"patch hunk count mismatch")
    output.extend(original[position:]);return "".join(output)


def deps(path):
    text=path.read_text().replace("\\\n","")
    require(":" in text,"malformed compiler dependencies")
    return sorted({Path(s).resolve(strict=True) for s in shlex.split(text.split(":",1)[1])})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-source",type=Path,required=True)
    parser.add_argument("--output-dir",type=Path,required=True)
    parser.add_argument("--phase",choices=("capacity","green"),required=True)
    parser.add_argument("--red-evidence",type=Path,help="exact passed compile-time CAPACITY receipt for GREEN")
    parser.add_argument("--cc",default="clang")
    parser.add_argument("--win64-cc",default="x86_64-w64-mingw32-gcc")
    args=parser.parse_args()
    started=time.monotonic()
    source_path=args.production_source.resolve(strict=True)
    original=read(source_path);require(sha(original)==PREIMAGE,"production preimage is not approved")
    test=ROOT/"tests/movefileex_path_bounds_host.c"
    runner=Path(__file__).resolve()
    inputs={str(p):sha(read(p)) for p in (source_path,test,runner)}
    out=args.output_dir.absolute()
    require(out.resolve()==out and ROOT/"build" in out.parents,"output must be canonical and under own build")
    require(not out.exists(),"fresh output required; historical outputs are preserved")
    # Capacity and GREEN share the parent8MiB admission with preserved failures.
    base=out.parent
    marker=base/"ownership.json"
    if base.exists():
        require(marker.is_file() and not marker.is_symlink(),"missing RED ownership receipt")
        ownership=json.loads(read(marker))
        require(ownership=={"kind":"movefileex-bounds","production_preimage_sha256":PREIMAGE},"wrong output owner")
        old=members(base)
    else:
        require(args.phase=="capacity","GREEN needs an owned capacity parent")
        old={}
    if args.phase=="green":
        require(args.red_evidence is not None,"GREEN requires explicit passed RED evidence")
        red_path=args.red_evidence.resolve(strict=True)
        require(base in red_path.parents,"RED evidence must belong to the same8MiB parent")
        red=json.loads(read(red_path))
        require(red.get("passed") is True and red.get("phase")=="capacity","actual compile-time capacity evidence required")
        require(red["source_before"]==inputs,"test/runner/source changed after RED")
    free=shutil.disk_usage(ROOT).free;memory=available()
    require(free>=RESERVE+BUDGET,"disk reserve+8MiB admission failed")
    require(memory>=RAM,"6GiB memory admission failed")
    cc=Path(shutil.which(args.cc) or "").resolve(strict=True)
    require(cc.is_file(),"host compiler unavailable")
    wincc=None
    if args.phase=="green":
        wincc=Path(shutil.which(args.win64_cc) or "").resolve(strict=True)
        require(wincc.is_file(),"Win64 compiler unavailable")
    base.mkdir(parents=True,exist_ok=True)
    if not marker.exists():marker.write_text(json.dumps({"kind":"movefileex-bounds","production_preimage_sha256":PREIMAGE},indent=2)+"\n")
    out.mkdir()
    record={"schema":1,"phase":args.phase,"passed":False,"source_before":inputs,
            "production_preimage_sha256":PREIMAGE,"steps":[],"resources":{"reserve_bytes":RESERVE,
            "shared_output_budget_bytes":BUDGET,"memory_floor_bytes":RAM,"RSS_limit_bytes":RSS,
            "CPU_seconds_per_child":60,"aggregate_wall_seconds_limit":90,"admitted_free_bytes":free,
            "admitted_available_memory_bytes":memory,"sampled_RSS_high_water_bytes":0,
            "lowest_sampled_free_bytes":free},**FALSE}
    compilers=[cc]+([wincc] if wincc is not None else [])
    record["compiler_executable_sha256"]={str(p):stream_sha(p) for p in compilers}
    environment={"PATH":os.defpath,"LC_ALL":"C","LANG":"C","ASAN_OPTIONS":"detect_leaks=1:halt_on_error=1",
                 "UBSAN_OPTIONS":"halt_on_error=1:print_stacktrace=1"}
    def guard():
        free_now=shutil.disk_usage(ROOT).free
        record["resources"]["lowest_sampled_free_bytes"]=min(record["resources"]["lowest_sampled_free_bytes"],free_now)
        require(free_now>=RESERVE,"disk reserve crossed")
        require(available()>=RAM,"available memory floor crossed")
        require(time.monotonic()-started<90,"aggregate 90s timeout")
        require(sum(p.stat().st_size for p in base.rglob("*") if p.is_file())<=BUDGET,"shared output budget crossed")
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU,(60,60))
        resource.setrlimit(resource.RLIMIT_FSIZE,(BUDGET,BUDGET))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    def run(argv,expected=0):
        guard();index=len(record["steps"])+1
        stdout=out/(str(index)+".stdout.log");stderr=out/(str(index)+".stderr.log")
        with stdout.open("xb") as so,stderr.open("xb") as se:
            process=subprocess.Popen([str(a) for a in argv],stdout=so,stderr=se,cwd=out,env=environment,
                                     start_new_session=True,preexec_fn=limits)
            try:
                while process.poll() is None:
                    guard();rss=group_rss(process.pid)
                    record["resources"]["sampled_RSS_high_water_bytes"]=max(record["resources"]["sampled_RSS_high_water_bytes"],rss)
                    require(rss<=RSS,"owned process group RSS crossed512MiB");time.sleep(.05)
            except BaseException:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait();raise
        row={"argv":[str(a) for a in argv],"returncode":process.returncode,"expected_returncode":expected,
             "controlled_environment":environment,"stdout":{"path":str(stdout),"sha256":stream_sha(stdout)},
             "stderr":{"path":str(stderr),"sha256":stream_sha(stderr)}}
        record["steps"].append(row)
        require(process.returncode==expected,"unexpected command result: "+str(argv[0]))
        guard();return stdout.read_text(errors="replace"),stderr.read_text(errors="replace")
    try:
        (out/"host-source.c").write_bytes(read(test))
        (out/"runner-source.py").write_bytes(read(runner))
        source=original.decode("utf-8")
        if args.phase=="green":
            patch=ROOT/"patches/kernel32/movefileex-path-bounds.patch"
            inputs[str(patch)]=sha(read(patch));source=apply_exact(source,read(patch).decode())
        (out/"production-full.c").write_text(source)
        functions={"production_converter.inc":extract(source,"NTSTATUS k32_dos_to_nt("),
                   "production_movefileex.inc":extract(source,"K32API BOOL WINAPI MoveFileExW(")}
        for name,body in functions.items():(out/name).write_text(body)
        record["exact_extracted_function_sha256"]={k:sha(v.encode()) for k,v in functions.items()}
        record["tested_full_source_sha256"]=sha(source.encode())
        normal=out/"host";san=out/"host-sanitized"
        flags=["-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function","-O1","-g",
               "-DCAPACITY_CONSISTENCY","-I",out]
        if args.phase=="capacity":
            stdout,stderr=run([cc,*flags,test,"-o",normal],1)
            require("rename name buffer covers converter buffer" in stderr and "static assertion failed" in stderr,
                    "original compile did not fail for exact capacity mismatch")
            record["capacity"]={"original_destination_WCHARs":300,"converter_buffer_WCHARs":320,
                "actual_compile_returncode":1,"historical_original_function_executed":False,
                "scope":"Compile-time array-size consistency on exact extracted production bytes. No memory-error or crash reproduction."}
        else:
            run([cc,*flags,test,"-o",normal])
            stdout,stderr=run([normal,"--all"])
            require(re.search(r"PASS \d+ production function host checks",stdout) and not stderr.strip(),"host controls missing")
            record["host_stdout"]=stdout
            run([cc,*flags,"-fsanitize=address,undefined","-fno-omit-frame-pointer",test,"-o",san])
            stdout,stderr=run([san,"--all"])
            require(stdout==record["host_stdout"] and not stderr.strip(),"sanitizer control result differs")
            record["sanitizer_stdout"]=stdout
            sdk=out/"win64-sdk.c"
            sdk.write_text('#include "k32.h"\nstatic void cwd_init(void) { }\n#include "production_converter.inc"\n'
                           '#define open_path k32_open_path\n#include "production_movefileex.inc"\n'
                           '_Static_assert(sizeof(WCHAR)==2 && sizeof(HANDLE)==8,"Win64 SDK widths");\n'
                           '_Static_assert(__builtin_types_compatible_p(__typeof__(&MoveFileExW),BOOL (WINAPI *)(LPCWSTR,LPCWSTR,DWORD)),"official WINAPI signature");\n'
                           '_Static_assert(ERROR_FILENAME_EXCED_RANGE==206,"official SDK error");\n')
            sdkflags=["-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function",
                      "-I",source_path.parent,"-I",out]
            run([wincc,*sdkflags,"-M",sdk,"-MF",out/"sdk-before.d"])
            dependency_paths=deps(out/"sdk-before.d")
            sdkpins={str(p):stream_sha(p) for p in dependency_paths}
            run([wincc,*sdkflags,"-c",sdk,"-MD","-MF",out/"sdk-after.d","-o",out/"win64-sdk.o"])
            require(dependency_paths==deps(out/"sdk-after.d"),"actual SDK dependencies changed")
            require(sdkpins=={str(p):stream_sha(p) for p in dependency_paths},"SDK dependency bytes changed")
            record["SDK_dependencies_before_and_after"]=sdkpins
            record["controlled_length_scope"]="Real converter299/300/301 remain accepted; controlled302..319 are ordinary capacity-compatible stub outputs. Defensive reported321 uses a valid short buffer, rejects before any copy/syscall. Counted names need no NUL in the request."
        require(all(members(base).get(p)==value for p,value in old.items()),"historical RED evidence changed")
        record["outputs_before_receipt"]=members(out)
        require(record["compiler_executable_sha256"]=={str(p):stream_sha(p) for p in compilers},"compiler bytes changed")
        if args.phase=="green":
            require(sdkpins=={str(p):stream_sha(p) for p in dependency_paths},"late SDK dependency drift")
        require(inputs=={p:sha(read(Path(p))) for p in inputs},"late production/test/runner/patch source drift")
        record["source_after"]=dict(inputs)
        guard();record["passed"]=True
    except BaseException as error:
        record["error"]=str(error)
        raise
    finally:
        record["resources"]["aggregate_wall_seconds"]=time.monotonic()-started
        record["resources"]["sampling_limit"]="50ms RSS/disk/memory samples are not an atomic reservation. Only this newly owned child group is killed on guard failure."
        (out/"result.json").write_text(json.dumps(record,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"phase":args.phase,"passed":record["passed"],"receipt":str(out/"result.json"),**FALSE}))


if __name__=="__main__":
    main()
