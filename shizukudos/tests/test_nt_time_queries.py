#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Frozen actual-body NT time/info/UP-affinity host contracts; no guest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time
ROOT = Path(__file__).resolve().parents[2]
FILES = ["kernel64/proc_internal.h", "kernel64/ipc.h", "kernel64/ntsys.h", "kernel64/k64.h",
         "kernel64/sched_cpu.h", "kernel64/smp_boot.c", "kernel64/smp_boot.h",
         "kernel64/objects.c", "kernel64/ipc_core.c", "kernel64/sched.c", "kernel64/sysk32_proc.c",
         "win64/kernel32/k32_procinfo.c", "win64/kernel32/k32_misc.c", "win64/kernel32/k32_steam_state.c",
         "tests/test_nt_time_queries.c", "tests/test_nt_time_queries.py"]
UNITS = ["kernel64/objects.c", "kernel64/ipc_core.c", "kernel64/sched.c", "kernel64/sysk32_proc.c",
         "win64/kernel32/k32_procinfo.c", "win64/kernel32/k32_misc.c", "win64/kernel32/k32_steam_state.c"]

def sha(data):
    return hashlib.sha256(data).hexdigest()


def block_end(source, start):
    # C lexical braces; quoted strings and comments cannot terminate a body.
    depth, state, i = 0, "code", start
    while i < len(source):
        c, nxt = source[i], source[i:i+2]
        if state == "code":
            if nxt in ("/*", "//"):
                state = "comment" if nxt == "/*" else "line"; i += 2; continue
            if c in ("'", '"'):
                state = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
        elif state == "comment" and nxt == "*/":
            state = "code"; i += 2; continue
        elif state == "line" and c == "\n":
            state = "code"
        elif state in ("'", '"'):
            if c == "\\":
                i += 2; continue
            if c == state:
                state = "code"
        i += 1
    raise ValueError("unterminated production C body")


def function(source, name, optional=False):
    match = re.search(r"^[A-Za-z_][^\n;{}]*\b" + re.escape(name) + r"\s*\([^;{}]*?\)\s*\{", source, re.M)
    if not match:
        if optional:
            return ""
        raise ValueError("missing production function " + name)
    return source[match.start():block_end(source, source.index("{", match.start()))]


def case(source, label):
    match = re.search(r"^    case " + re.escape(label) + r":", source, re.M)
    if not match:
        raise ValueError("missing production case " + label)
    end = re.search(r"^    (?:case |default:)", source[match.end():], re.M)
    if not end:
        raise ValueError("missing following production case")
    return source[match.start():match.end() + end.start()]



def command_admitted(record):
    """A timeout/interrupt can never be admitted, even with leader status zero."""
    return (record.get("returncode") == 0 and record.get("leader_reaped", False)
            and not any(record.get(k, False) for k in
                        ("timed_out", "interrupted", "refused", "execution_error", "cleanup_failed")))


def owned_group_live_members(pgid):
    """Linux read-only group inspection; zombies await their owning OS reaper."""
    live = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid and fields[0] not in ("Z", "X"):
                live.append(int(entry.name))
        except FileNotFoundError:
            pass                         # the observed process already exited
    return live


def run_owned(argv, timeout=115, term_grace=1, kill_wait=3):
    """Own one new session/group. Abort cleanup is bounded and always kills it.

    The normal 115-second deadline plus at most 1+3 seconds of cleanup stays
    below 120 seconds. Only this attempt's group is signaled. The leader status
    remains factual; command_admitted separately rejects timeout/interrupt.
    """
    record = {"returncode": None, "stdout": "", "stderr": "", "timed_out": False,
              "interrupted": False, "execution_error": False, "cleanup_failed": False,
              "group_term_attempted": False, "group_kill_attempted": False,
              "leader_reaped": False, "owned_group_live_members": []}
    proc = None
    def group_signal(sig):
        key = "group_term_attempted" if sig == signal.SIGTERM else "group_kill_attempted"
        record[key] = True
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as e:
            record["cleanup_failed"] = True
            record["stderr"] += "\ngroup signal failed: " + str(e)
    try:
        proc = subprocess.Popen(list(map(str, argv)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, errors="replace", start_new_session=True)
        record["owned_group"] = proc.pid
        record["stdout"], record["stderr"] = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        record["timed_out"] = True
    except KeyboardInterrupt:
        record["interrupted"] = True
    except Exception as e:
        record["execution_error"] = True
        record["stderr"] += "\ncommand exception: " + type(e).__name__ + ": " + str(e)
    finally:
        if proc is not None and any(record[k] for k in ("timed_out", "interrupted", "execution_error")):
            group_signal(signal.SIGTERM)
            try:
                record["stdout"], record["stderr"] = proc.communicate(timeout=term_grace)
            except subprocess.TimeoutExpired:
                pass
            except KeyboardInterrupt:
                record["interrupted"] = True
            except Exception as e:
                record["cleanup_failed"] = True
                record["stderr"] += "\nTERM wait failed: " + str(e)
            finally:
                # A TERM handler can reap the leader with status zero and close
                # inherited pipes while a descendant ignores TERM. Never use
                # leader status or communicate completion to skip group KILL.
                group_signal(signal.SIGKILL)
            deadline = time.monotonic() + kill_wait
            while time.monotonic() < deadline:
                try:
                    record["stdout"], record["stderr"] = proc.communicate(timeout=min(.1, max(.001, deadline-time.monotonic())))
                    live = owned_group_live_members(proc.pid)
                    record["owned_group_live_members"] = live
                    if proc.returncode is not None and not live:
                        break
                    time.sleep(min(.01, max(0, deadline-time.monotonic())))
                except subprocess.TimeoutExpired:
                    pass
                except KeyboardInterrupt:
                    record["interrupted"] = True
                    group_signal(signal.SIGKILL)
                except Exception as e:
                    record["cleanup_failed"] = True
                    record["stderr"] += "\nKILL wait failed: " + str(e)
                    break
            else:
                record["cleanup_failed"] = True
                record["stderr"] += "\nbounded owned-group cleanup deadline"
            # Poll is nonblocking; no unbounded wait remains on a refusal path.
            proc.poll()
        if proc is not None:
            record["returncode"] = proc.returncode
            record["leader_reaped"] = proc.returncode is not None
        if record["timed_out"]:
            record["stderr"] += "\nbounded command timeout (" + str(timeout) + " seconds)"
        if record["interrupted"]:
            record["stderr"] += "\ncommand interrupted; owned-group cleanup attempted"
    record["admitted"] = command_admitted(record)
    return record

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-units", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists(): parser.error("fresh output directory required")
    out.mkdir(parents=True)
    result = {"status": "FAIL", "scope": "Actual selected private query/setter and eight frontend getter/setter bodies; complete production schemas; actual handle/ref/detach/process-free, accounting, queues, cycles and CPU identity; explicit host IRQ/copy/clock/static-allocation and controlled live_threads-entry departure adapters",
              "guest_executed": False, "native_windows98_verified": False, "full_runtime_built": False,
              "ap_executed": False, "hardware_context_switch_executed": False,
              "source_sha256": {}, "compiler_sha256": {}, "artifacts_sha256": {}, "records": []}
    snapshots, compiler_bytes, compilers, artifacts = {}, {}, {}, {}
    def save(): (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    def pin(path):
        artifacts[path] = path.read_bytes()
        result["artifacts_sha256"][str(path.relative_to(out))] = sha(artifacts[path])
    def stable():
        try:
            return all(p.read_bytes() == b for p,b in snapshots.items()) and all(
                compilers[n].read_bytes() == b for n,b in compiler_bytes.items()) and all(
                p.read_bytes() == b for p,b in artifacts.items())
        except OSError:
            return False
    def run(argv, name):
        argv = list(map(str, argv))
        attempt = {"name": name, "command": argv, "state": "running", "admitted": False}
        result["records"].append(attempt); save()  # retain a pending FAIL on abrupt interruption
        if not stable():
            attempt.update(returncode=125, stdout="", stderr="input changed; refused", refused=True,
                           timed_out=False, interrupted=False, leader_reaped=False)
        else:
            attempt.update(run_owned(argv))
        attempt["state"] = "complete"
        log = out / (name + ".log"); log.write_text(attempt["stdout"] + attempt["stderr"]); pin(log)
        attempt["admitted"] = command_admitted(attempt)
        save(); print(name, attempt["returncode"], (attempt["stdout"] + attempt["stderr"])[-1900:], flush=True)
        if attempt.get("interrupted"):
            raise InterruptedError("owned command interrupted; terminal attempt preserved")
        effective = 0 if attempt["admitted"] else (attempt["returncode"] or 125)
        return effective, attempt["stdout"]
    save()
    try:
        paths = [ROOT / "shizukudos" / f for f in FILES]
        paths += sorted((ROOT / "shizukudos").rglob("*.h"))
        snapshots = {p: p.read_bytes() for p in dict.fromkeys(paths)}
        result["source_sha256"] = {str(p.relative_to(ROOT)): sha(b) for p,b in snapshots.items()}
        for p,b in snapshots.items():
            f=out / "frozen" / p.relative_to(ROOT); f.parent.mkdir(parents=True,exist_ok=True); f.write_bytes(b); pin(f)
        for n in ["gcc", "clang"] + (["x86_64-w64-mingw32-gcc"] if args.compile_units else []):
            compilers[n] = Path(shutil.which(n)).resolve(); compiler_bytes[n] = compilers[n].read_bytes()
            result["compiler_sha256"][n] = sha(compiler_bytes[n])
        sources = {p.name: b.decode() for p,b in snapshots.items() if p.suffix == ".c"}
        pieces = [function(sources["smp_boot.c"], n) for n in ["initial_apic_id", "shz_smp_this_cpu"]]
        pieces.append(re.search(r"^typedef struct[^\n]+queue_guard_t;", sources["sched.c"], re.M)[0])
        for filename,names in [("sched.c", ["sched_cpu_identity", "bsp_scheduler_owner", "queue_enter", "queue_leave", "thread_pointer_valid", "ready_enqueue_locked", "ready_enqueue", "ready_remove", "thread_current", "ticks_now", "rdtsc", "thread_slot"]),
                               ("objects.c", ["ob_ref", "ob_deref", "handle_insert", "handle_lookup", "handle_ref", "handle_close", "thread_object_detach"]),
                               ("ipc_core.c", ["ipc_ref_handle", "ipc_ref_process", "ipc_handle_closed"])]:
            pieces += [function(sources[filename],n) for n in names]
        pieces.append("void ipc_object_free(kobject_t *o) { switch (o->type) {\n" + case(sources["ipc_core.c"], "OB_PROCESS") + "default: break; } }\n")
        # Definition-only aliases preserve the exact bodies. The entry adapters
        # record held references and inject departure only if there is no outer guard.
        pieces += ["#define thread_cycles_now production_thread_cycles_now", function(sources["sched.c"], "thread_cycles_now"), "#undef thread_cycles_now", "static uint64_t thread_cycles_now(thread_t *t) { observe_thread_snapshot(t); return production_thread_cycles_now(t); }"]
        k=sources["sysk32_proc.c"]
        pieces += [function(k,"prepare_time_epoch",optional=True), function(k,"tick_to_filetime"), function(k,"proc_of_handle"), function(k,"thread_account_exit")]
        pieces.append(re.search(r"^struct times[^\n]+", k, re.M)[0])
        pieces += [function(k,"ref_query_object",optional=True), function(k,"thread_times"), "#define live_threads production_live_threads", function(k,"live_threads"), "#undef live_threads", "static unsigned live_threads(process_t *p,uint64_t *ut,uint64_t *kt,uint64_t *cyc) { observe_process_snapshot(p); depart_at_live_entry(p); return production_live_threads(p,ut,kt,cyc); }", function(k,"put_out"), function(k,"set_process_affinity_mask",optional=True)]
        pieces.append("static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen) { switch(cls) {\n" + "\n".join(case(k,c) for c in ["K32Q_THREAD_TIMES","K32Q_THREAD_SETTINGS","K32Q_PROCESS_TIMES","K32Q_PROCESS_INFO"]) + "default: return STATUS_INVALID_INFO_CLASS; } }")
        sc=case(k,"K32S_PROCESS_AFFINITY") if re.search(r"^    case K32S_PROCESS_AFFINITY:",k,re.M) else ""
        pieces.append("static int32_t host_set(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len) { switch(cls) {\n" + sc + "default: return STATUS_INVALID_INFO_CLASS; } }")
        # Frontend bodies consume actual frozen nt.h numeric definitions, after
        # the private kernel dispatcher has consumed its actual enum. This
        # avoids a shared test constant masking a frontend/wire mismatch.
        nt=snapshots[ROOT/"shizukudos/win64/include/nt.h"].decode()
        for name in ["K32Q_THREAD_TIMES","K32Q_PROCESS_TIMES","K32Q_PROCESS_INFO","K32S_PROCESS_AFFINITY"]:
            m=re.search(r"^#define "+name+r"[^\n]+",nt,re.M)
            if m: pieces.append(m[0])
        pi=sources["k32_procinfo.c"]
        pieces.append(re.search(r"^typedef struct[^\n]+k32_times;",pi,re.M)[0])
        pieces += [function(pi,n) for n in ["to_ft","fail_st","fail_err","GetProcessTimes","GetThreadTimes","QueryProcessCycleTime","QueryThreadCycleTime","process_info","GetProcessHandleCount","IsWow64Process"]]
        pieces += [function(sources["k32_misc.c"],"GetProcessAffinityMask"), function(sources["k32_steam_state.c"],"SetProcessAffinityMask")]
        f=out/"production.inc"; f.write_text("\n\n".join(pieces)+"\n"); pin(f)
        ipc=snapshots[ROOT/"shizukudos/kernel64/ipc.h"].decode()
        definitions=[]
        for name in ["THREAD_QUERY_INFORMATION","THREAD_QUERY_LIMITED_INFORMATION","THREAD_SET_INFORMATION","PROCESS_QUERY_INFORMATION","PROCESS_QUERY_LIMITED_INFORMATION","PROCESS_SET_INFORMATION"]:
            m=re.search(r"^#define "+name+r"[^\n]+",ipc,re.M)
            if m: definitions.append(m[0])
            elif name=="THREAD_QUERY_LIMITED_INFORMATION": definitions.append("#define THREAD_QUERY_LIMITED_INFORMATION 0x0800u /* pre-implementation ABI only */")
            else: raise ValueError("missing access constant "+name)
        definitions += re.findall(r"enum \{ K32[QS]_[^;]+;",k)
        if not re.search(r"K32S_PROCESS_AFFINITY\s*=",k): definitions.append("#define K32S_PROCESS_AFFINITY 14 /* pre-implementation ABI only */")
        f=out/"api-layout.inc"; f.write_text("\n".join(definitions)+"\n"); pin(f)
        schema=snapshots[ROOT/"shizukudos/kernel64/proc_internal.h"].decode()
        a=schema.index("/* ---- virtual address descriptors ---- */"); z=block_end(schema,schema.index("{",schema.index("struct process {",a)))
        ipc=snapshots[ROOT/"shizukudos/kernel64/ipc.h"].decode()
        # The unchanged full I/O context schema is needed by handle-close's
        # unrelated branches; those branches are explicit refusal adapters.
        m=re.search(r"typedef struct \{[^{}]*\} ioctx_t;",ipc,re.S)
        f=out/"process-layout.inc"; f.write_text(schema[a:z]+";\n"+(m[0]+"\n" if m else "")); pin(f)
        schema=snapshots[ROOT/"shizukudos/kernel64/k64.h"].decode()
        a=schema.index("typedef struct thread thread_t;"); z=block_end(schema,schema.index("{",schema.index("struct thread {",a)))
        f=out/"thread-layout.inc"; f.write_text(schema[a:z]+";\n"+re.search(r"^#define TICK_US[^\n]+",schema,re.M)[0]+"\n"); pin(f)
        save(); passed=True
        fixture=out/"frozen/shizukudos/tests/test_nt_time_queries.c"
        for name,flags in [("gcc",["-O2"]),("clang",["-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"])]:
            binary=out/("nt-time-queries-"+name)
            rc,_=run([compilers[name],"-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-unused-parameter",*flags,"-I",out,"-I",out/"frozen/shizukudos/kernel64",fixture,"-o",binary],"compile-"+name)
            passed &= rc==0
            if rc==0:
                pin(binary)
                for mode in ["normal","clock-zero","clock-wrap"]:
                    rc,stdout=run([binary,mode],"run-"+name+"-"+mode)
                    m=re.search(r"NT_TIME_QUERIES_HOST: (\d+) checks, (\d+) failures",stdout)
                    result["records"][-1].update(checks=int(m[1]) if m else None,failures=int(m[2]) if m else None)
                    passed &= rc==0 and bool(m) and int(m[2])==0; save()
        if args.compile_units:
            for rel in UNITS:
                src=out/"frozen/shizukudos"/rel; obj=out/(src.stem+".o")
                win=rel.startswith("win64/")
                flags=["-O2","-Wall","-Wextra","-Werror","-ffreestanding","-fno-builtin","-fno-stack-protector","-mno-red-zone","-fno-ident","-fno-tree-loop-distribute-patterns"]
                flags += ["-Wno-unused-function","-Wno-unused-parameter","-Wno-cast-function-type"] if win else ["-m64","-march=x86-64","-std=gnu11","-fno-pic","-fno-pie","-mcmodel=kernel","-mgeneral-regs-only","-fwrapv","-fno-strict-aliasing"]
                rc,_=run([compilers["x86_64-w64-mingw32-gcc" if win else "gcc"],*flags,"-c",src,"-o",obj],"freestanding-"+src.stem)
                passed &= rc==0
                if rc==0: pin(obj)
        result["inputs_stable"]=stable(); result["status"]="PASS" if passed and result["inputs_stable"] and all(command_admitted(r) for r in result["records"]) else "FAIL"
    except (Exception, KeyboardInterrupt) as e:
        result["interrupted"]=isinstance(e,(KeyboardInterrupt,InterruptedError))
        result["setup_error"]=type(e).__name__+": "+str(e)
        result["inputs_stable"]=stable(); print(result["setup_error"],flush=True)
    save()
    return 0 if result["status"]=="PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
