#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Frozen actual-body process memory and working-set query host contracts."""
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
         "kernel64/objects.c", "kernel64/ipc_core.c", "kernel64/proc.c", "kernel64/mem.c", "kernel64/vad.c",
         "kernel64/sched.c", "kernel64/sysk32_proc.c", "kernel64/sysk32.c",
         "win64/kernel32/k32_procinfo.c", "win64/kernel32/k32_core.c",
         "win64/ntdll/ntdll_main.c", "tests/test_nt_full_queries.py",
         "tests/test_nt_memory_queries.c", "tests/test_nt_memory_queries.py"]
UNITS = ["kernel64/sysk32_proc.c", "kernel64/mem.c", "kernel64/vad.c", "kernel64/proc.c",
         "kernel64/objects.c", "kernel64/ipc_core.c", "kernel64/sysk32.c", "win64/kernel32/k32_procinfo.c"]
SDK_DIR = Path("/usr/x86_64-w64-mingw32/sys-root/mingw/include")
SDKS = [SDK_DIR / n for n in ("winnt.h", "winbase.h", "psapi.h", "processthreadsapi.h")]

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


def struct_typedef(source, tag, final):
    m = re.search(r"typedef (?:struct|enum|union) " + re.escape(tag) + r"\s*\{", source)
    if not m:
        raise ValueError("missing production schema " + tag)
    end = source.index(";", block_end(source, source.index("{", m.start()))) + 1
    body = source[m.start():end]
    if final not in body:
        raise ValueError("unexpected production schema terminator " + tag)
    return body


def extract(sources, headers, emit, record):
    pieces = []
    def take(filename, name, optional=False):
        body = function(sources[filename], name, optional)
        if body:
            record["selected_body_sha256"][filename + ":" + name] = sha(body.encode())
        return body
    pieces += [take("objects.c", n) for n in
               ["ob_ref", "ob_deref", "handle_insert", "handle_lookup", "handle_ref", "handle_close", "handles_close_all"]]
    pieces += [take("ipc_core.c", n) for n in ["ipc_ref_handle", "ipc_ref_process", "ipc_handle_closed"]]
    freecase = case(sources["ipc_core.c"], "OB_PROCESS")
    record["selected_body_sha256"]["ipc_core.c:OB_PROCESS-free"] = sha(freecase.encode())
    pieces.append("void ipc_object_free(kobject_t *o) { switch(o->type) {\n" + freecase + "default: break; } }")
    # Entry wrappers only observe an actual query/provider boundary. The
    # unchanged provider body always executes; no page or VAD result is mocked.
    pieces += [take("mem.c", n) for n in ["kernel_pml4", "table_at", "walk", "vm_map", "vm_unmap", "vm_protect", "vm_new_space"]]
    pieces += ["#define vm_lookup production_vm_lookup", take("mem.c", "vm_lookup"), "#undef vm_lookup",
               "uint64_t vm_lookup(uint64_t root,uint64_t va,uint64_t *flags) { depart_at_lookup(root); observe_walk(root); ++walk_context; uint64_t r=production_vm_lookup(root,va,flags); --walk_context; return r; }"]
    pieces += [take("mem.c", n) for n in ["free_level", "vm_free_space", "count_level"]]
    pieces += ["#define vm_count_user_pages production_vm_count_user_pages", take("mem.c", "vm_count_user_pages"), "#undef vm_count_user_pages",
               "uint64_t vm_count_user_pages(uint64_t root) { observe_walk(root); ++walk_context; uint64_t r=production_vm_count_user_pages(root); --walk_context; return r; }"]
    pieces += [take("vad.c", n) for n in ["vad_init", "vad_destroy", "vad_insert_at", "vad_remove_at", "vad_lower"]]
    pieces += ["#define vad_find production_vad_find", take("vad.c", "vad_find"), "#undef vad_find",
               "vad_t *vad_find(process_t *p,uint64_t a) { observe_vad(p); vad_t *v=production_vad_find(p,a); depart_at_vad(p); return v; }",
               take("vad.c", "vad_split")]
    pieces += [take("proc.c", n) for n in ["process_slot", "process_teardown"]]
    k = sources["sysk32_proc.c"]
    pieces += [take("sysk32_proc.c", n) for n in ["ref_query_object", "proc_of_handle", "live_threads", "private_commit", "all_commit", "system_commit"]]
    pieces += ["#define sample_peaks production_sample_peaks", take("sysk32_proc.c", "sample_peaks"), "#undef sample_peaks",
               "static void sample_peaks(process_t *p) { ++inside_sample; production_sample_peaks(p); --inside_sample; }"]
    pieces += [take("sysk32_proc.c", n) for n in ["vlock_find", "vlocks_drop", "k32_before_unmap", "put_out"]]
    labels = ["K32Q_PROCESS_INFO", "K32Q_SYSTEM_PERF", "K32Q_PROCESS_MEMORY", "K32Q_WORKING_SET_EX"]
    cases = []
    for label in labels:
        if re.search(r"^    case " + label + ":", k, re.M):
            body = case(k, label); cases.append(body)
            record["selected_body_sha256"]["sysk32_proc.c:" + label] = sha(body.encode())
    # The baseline unknown-class behavior comes from its actual dispatcher.
    query = take("sysk32_proc.c", "k32_query")
    fallback = re.search(r"    default:\s*return STATUS_INVALID_INFO_CLASS;", query)
    if not fallback:
        raise ValueError("unexpected actual query fallback")
    pieces.append("static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen) { switch(cls) {\n" + "\n".join(cases) + fallback[0] + " } }")
    # Kernel enums and frontend macros are independently consumed in order.
    definitions = []
    for name in ["PROCESS_QUERY_INFORMATION", "PROCESS_QUERY_LIMITED_INFORMATION", "PROCESS_SET_INFORMATION", "PROCESS_VM_READ"]:
        definitions.append(re.search(r"^#define " + name + r"[^\n]+", headers["ipc.h"], re.M)[0])
    definitions += re.findall(r"enum \{ K32Q_[^;]+;", k)
    definitions.append(re.search(r"^#define MAX_PROCS[^\n]+", sources["proc.c"], re.M)[0])
    definitions.append(re.search(r"^#define MAX_VLOCKS[^\n]+", k, re.M)[0])
    definitions.append(re.search(r"^typedef struct[^\n]+vlock_t;[^\n]*", k, re.M)[0])
    definitions += [re.search(r"^#define " + name + r"[^\n]+", headers["k64.h"], re.M)[0]
                    for name in ["PAGE_SIZE", "USER_TOP", "USER_MIN", "PT_P", "PT_W", "PT_U", "PT_NX", "PT_PWT", "PT_PCD"]]
    emit("api-layout.inc", "\n".join(definitions) + "\n")
    nt = headers["nt.h"]
    for name in labels:
        m = re.search(r"^#define " + name + r"[^\n]+", nt, re.M)
        if m:
            pieces.append(m[0])
    pi = sources["k32_procinfo.c"]
    pieces += [take("k32_core.c", "k32_nt_error")]
    pieces += [take("k32_procinfo.c", n) for n in
               ["fail_st", "fail_err", "process_info", "GetProcessInformation", "K32GetProcessMemoryInfo", "K32QueryWorkingSetEx"]]
    emit("production.inc", "\n\n".join(pieces) + "\n")
    schema = headers["proc_internal.h"]
    a = schema.index("/* ---- virtual address descriptors ---- */")
    z = block_end(schema, schema.index("{", schema.index("struct process {", a)))
    io = re.search(r"typedef struct \{[^{}]*\} ioctx_t;", headers["ipc.h"], re.S)[0]
    emit("process-layout.inc", schema[a:z] + ";\n" + io + "\n")
    schema = headers["k64.h"]
    a = schema.index("typedef struct thread thread_t;")
    z = block_end(schema, schema.index("{", schema.index("struct thread {", a)))
    emit("thread-layout.inc", schema[a:z] + ";\n")
    psapi = headers["sdk-psapi.h"]
    sdk = headers["sdk-processthreadsapi.h"]
    layouts = [struct_typedef(psapi, tag, final) for tag, final in
               [("_PROCESS_MEMORY_COUNTERS", "PROCESS_MEMORY_COUNTERS"), ("_PROCESS_MEMORY_COUNTERS_EX", "PROCESS_MEMORY_COUNTERS_EX"),
                ("_PSAPI_WORKING_SET_EX_BLOCK", "PSAPI_WORKING_SET_EX_BLOCK"), ("_PSAPI_WORKING_SET_EX_INFORMATION", "PSAPI_WORKING_SET_EX_INFORMATION")]]
    layouts += ["typedef PROCESS_MEMORY_COUNTERS *PPROCESS_MEMORY_COUNTERS;"]
    layouts += [struct_typedef(sdk, tag, final) for tag, final in
                [("_PROCESS_INFORMATION_CLASS", "PROCESS_INFORMATION_CLASS"), ("_APP_MEMORY_INFORMATION", "APP_MEMORY_INFORMATION"),
                 ("_MEMORY_PRIORITY_INFORMATION", "MEMORY_PRIORITY_INFORMATION"), ("_PROCESS_POWER_THROTTLING_STATE", "PROCESS_POWER_THROTTLING_STATE"),
                 ("PROCESS_PROTECTION_LEVEL_INFORMATION", "PROCESS_PROTECTION_LEVEL_INFORMATION"), ("_MACHINE_ATTRIBUTES", "MACHINE_ATTRIBUTES"),
                 ("_PROCESS_MACHINE_INFORMATION", "PROCESS_MACHINE_INFORMATION")]]
    layouts += [re.search(r"^#define PROCESS_POWER_THROTTLING_CURRENT_VERSION[^\n]+", sdk, re.M)[0]]
    layouts += [re.search(r"^#define PROTECTION_LEVEL_NONE[^\n]+", headers["sdk-winbase.h"], re.M)[0],
                re.search(r"^#define IMAGE_FILE_MACHINE_AMD64[^\n]+", headers["sdk-winnt.h"], re.M)[0]]
    emit("sdk-layout.inc", "\n".join(layouts).replace("__C89_NAMELESS", "") + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-units", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists(): parser.error("fresh output directory required")
    out.mkdir(parents=True)
    result = {"status": "FAIL", "scope": "Actual selected Q3/Q7/Q8/Q9 and memory/working-set/AppMemoryInfo wrappers; actual ref/handle/close/final process-free, process_teardown, VAD lookup/growth/destruction and page-table map/walk/lookup/count/free bodies; complete production schemas and selected SDK layouts; explicit host IRQ/copy/physical-frame/heap/CR3/invlpg/loader-IPC hooks and storage-publication adapters; controlled outermost sample restore and actual VAD/page-lookup seams",
              "guest_executed": False, "native_windows98_verified": False, "full_runtime_built": False,
              "ap_executed": False, "smp_lifetime_verified": False, "native_allocator_uaf_verified": False,
              "whole_batch_atomicity_claimed": False, "q7_app_memory_atomicity_claimed": False,
              "external_toolchain_closure_sealed": False,
              "source_sha256": {}, "compiler_sha256": {}, "artifacts_sha256": {}, "selected_body_sha256": {}, "records": []}
    snapshots, compiler_bytes, compilers, artifacts = {}, {}, {}, {}
    def save(): (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    def pin(path):
        artifacts[path] = path.read_bytes()
        result["artifacts_sha256"][str(path.relative_to(out))] = sha(artifacts[path])
    def emit(name, text):
        f = out / name; f.write_text(text); pin(f)
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
        result["records"].append(attempt); save()
        if not stable():
            attempt.update(returncode=125, stdout="", stderr="input changed; refused", refused=True,
                           timed_out=False, interrupted=False, leader_reaped=False)
        else:
            attempt.update(run_owned(argv))
        attempt["state"] = "complete"
        log = out / (name + ".log"); log.write_text(attempt["stdout"] + attempt["stderr"]); pin(log)
        attempt["admitted"] = command_admitted(attempt)
        save(); print(name, attempt["returncode"], (attempt["stdout"] + attempt["stderr"])[-4000:], flush=True)
        if attempt.get("interrupted"):
            raise InterruptedError("owned command interrupted; terminal attempt preserved")
        return 0 if attempt["admitted"] else (attempt["returncode"] or 125), attempt["stdout"]
    save()
    try:
        paths = [ROOT / "shizukudos" / f for f in FILES] + sorted((ROOT / "shizukudos").rglob("*.h"))
        paths.extend(SDKS)
        snapshots = {p: p.read_bytes() for p in dict.fromkeys(paths)}
        for p,b in snapshots.items():
            rel = str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else "external-sdk/" + p.name
            result["source_sha256"][rel] = sha(b)
            f=out / "frozen" / rel; f.parent.mkdir(parents=True,exist_ok=True); f.write_bytes(b); pin(f)
        for n in ["gcc", "clang"] + (["x86_64-w64-mingw32-gcc"] if args.compile_units else []):
            compilers[n] = Path(shutil.which(n)).resolve(); compiler_bytes[n] = compilers[n].read_bytes()
            result["compiler_sha256"][n] = sha(compiler_bytes[n])
        c_inputs = [p for p in snapshots if p.suffix == ".c"]
        if len({p.name for p in c_inputs}) != len(c_inputs):
            raise ValueError("selected C basenames collide; canonical source binding required")
        sources = {p.name:snapshots[p].decode() for p in c_inputs}
        helper_source = snapshots[ROOT/"shizukudos/tests/test_nt_full_queries.py"].decode()
        runner_source = snapshots[ROOT/"shizukudos/tests/test_nt_memory_queries.py"].decode()
        def owned_block(s):
            return s[s.index("def command_admitted("):s.index("def struct_typedef(")]
        if owned_block(helper_source) != owned_block(runner_source):
            raise ValueError("owned-group producer helper differs from frozen corrected predecessor")
        result["owned_group_helper_sha256"] = sha(owned_block(runner_source).encode())
        # Do not select by basename across rglob: win64/tests/hostshim/nt.h
        # is a different file from the production wire header.
        header_paths = {"nt.h":"win64/include/nt.h", "ipc.h":"kernel64/ipc.h",
                        "proc_internal.h":"kernel64/proc_internal.h", "k64.h":"kernel64/k64.h"}
        headers = {name:snapshots[ROOT/"shizukudos"/rel].decode() for name,rel in header_paths.items()}
        result["selected_header_sha256"] = {"shizukudos/"+rel:sha(snapshots[ROOT/"shizukudos"/rel]) for rel in header_paths.values()}
        headers.update({"sdk-"+p.name:snapshots[p].decode() for p in SDKS})
        extract(sources, headers, emit, result)
        save(); passed=True
        fixture=out/"frozen/shizukudos/tests/test_nt_memory_queries.c"
        for name,flags in [("gcc",["-O2"]),("clang",["-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"])]:
            binary=out/("nt-memory-queries-"+name)
            rc,_=run([compilers[name],"-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-unused-parameter",*flags,"-I",out,"-I",out/"frozen/shizukudos/kernel64",fixture,"-o",binary],"compile-"+name)
            passed &= rc==0
            if rc==0:
                pin(binary)
                rc,stdout=run([binary],"run-"+name)
                m=re.search(r"NT_MEMORY_QUERIES_HOST: (\d+) checks, (\d+) failures",stdout)
                result["records"][-1].update(checks=int(m[1]) if m else None,failures=int(m[2]) if m else None)
                passed &= rc==0 and bool(m) and int(m[2])==0; save()
        if args.compile_units:
            for rel in UNITS:
                src=out/"frozen/shizukudos"/rel; obj=out/(src.stem+".o"); win=rel.startswith("win64/")
                flags=["-O2","-Wall","-Wextra","-Werror","-ffreestanding","-fno-builtin","-fno-stack-protector","-mno-red-zone","-fno-ident","-fno-tree-loop-distribute-patterns"]
                flags += ["-Wno-unused-function","-Wno-unused-parameter","-Wno-cast-function-type"] if win else ["-m64","-march=x86-64","-std=gnu11","-fno-pic","-fno-pie","-mcmodel=kernel","-mgeneral-regs-only","-fwrapv","-fno-strict-aliasing"]
                rc,_=run([compilers["x86_64-w64-mingw32-gcc" if win else "gcc"],*flags,"-c",src,"-o",obj],"freestanding-"+src.stem)
                passed &= rc==0
                if rc==0: pin(obj)
        result["inputs_stable"]=stable()
        result["status"]="PASS" if passed and result["inputs_stable"] and all(command_admitted(r) for r in result["records"]) else "FAIL"
    except (Exception, KeyboardInterrupt) as e:
        result["interrupted"]=isinstance(e,(KeyboardInterrupt,InterruptedError))
        result["setup_error"]=type(e).__name__+": "+str(e)
        result["inputs_stable"]=stable(); print(result["setup_error"],flush=True)
    save()
    return 0 if result["status"]=="PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
