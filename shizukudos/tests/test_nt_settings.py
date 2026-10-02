#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Frozen actual-body process/thread settings host contracts (stored metadata only)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import signal
import subprocess
import time
ROOT = Path(__file__).resolve().parents[2]
FILES = ["kernel64/proc_internal.h", "kernel64/ipc.h", "kernel64/ntsys.h", "kernel64/k64.h",
         "kernel64/objects.c", "kernel64/ipc_core.c", "kernel64/ipc_proc.c", "kernel64/proc.c",
         "kernel64/vad.c", "kernel64/sched.c", "kernel64/sysk32_proc.c",
         "win64/kernel32/k32_procinfo.c", "win64/kernel32/k32_core.c", "win64/kernel32/k32_sysinfo.c",
         "win64/ntdll/ntdll_main.c", "win64/ntdll/ipc_ntdll.c",
         "tests/test_nt_memory_queries.py", "tests/test_nt_settings.c", "tests/test_nt_settings.py"]
UNITS = ["kernel64/sysk32_proc.c", "kernel64/objects.c", "kernel64/ipc_core.c",
         "kernel64/ipc_proc.c", "kernel64/proc.c", "kernel64/sched.c",
         "win64/kernel32/k32_procinfo.c", "win64/ntdll/ipc_ntdll.c"]
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
    # The only observer wrappers enter before/after an actual selected body.
    # Every lookup/ref/close/detach/accounting result comes from these bodies.
    pieces += ["#define ob_ref production_ob_ref", take("objects.c", "ob_ref"), "#undef ob_ref",
               "void ob_ref(kobject_t *o) { observe_ref_publication(o); production_ob_ref(o); }"]
    pieces += [take("objects.c", n) for n in
               ["ob_deref", "handle_insert", "handle_lookup", "handle_ref", "handle_close",
                "handles_close_all", "thread_object_detach"]]
    pieces += [take("ipc_core.c", n) for n in ["ipc_ref_handle", "ipc_ref_process", "ipc_handle_closed"]]
    freecase = case(sources["ipc_core.c"], "OB_PROCESS")
    record["selected_body_sha256"]["ipc_core.c:OB_PROCESS-free"] = sha(freecase.encode())
    pieces.append("void ipc_object_free(kobject_t *o) { switch(o->type) {\n" + freecase + "default: break; } }")
    pieces += [take("vad.c", "vad_destroy"), take("proc.c", "thread_must_die"),
               take("sched.c", "ticks_now"), take("sched.c", "thread_slot")]
    pieces += ["#define thread_cycles_now production_thread_cycles_now",
               take("sched.c", "thread_cycles_now"), "#undef thread_cycles_now",
               "uint64_t thread_cycles_now(thread_t *t) { ++cycle_calls; return production_thread_cycles_now(t); }"]
    k = sources["sysk32_proc.c"]
    pieces += [take("sysk32_proc.c", n) for n in
               ["prepare_time_epoch", "tick_to_filetime", "ref_query_object", "proc_of_handle", "thread_account_exit"]]
    times = re.search(r"^struct times \{[^\n]+\};", k, re.M)
    if not times:
        raise ValueError("missing actual time schema")
    record["selected_schema_sha256"]["sysk32_proc.c:times"] = sha(times[0].encode())
    pieces.append(times[0])
    # Emit the entire unchanged legacy body, even when candidate Q12 no longer
    # calls it. Baseline settings must use its real cycle/accounting providers.
    pieces += [take("sysk32_proc.c", n) for n in ["thread_times", "live_threads", "put_out"]]
    for name in ["ref_settings_object", "query_thread_settings", "set_process_settings", "set_thread_settings"]:
        body = take("sysk32_proc.c", name, optional=True)
        if body:
            pieces.append(body)
    query = take("sysk32_proc.c", "k32_query")
    fallback = re.search(r"    default:\s*return STATUS_INVALID_INFO_CLASS;", query)
    if not fallback:
        raise ValueError("unexpected actual query fallback")
    query_labels = ["K32Q_PROCESS_INFO", "K32Q_THREAD_SETTINGS", "K32Q_PROCESS_SETTINGS",
                    "K32Q_THREAD_SETTINGS_STRICT"]
    cases = []
    for label in query_labels:
        if re.search(r"^    case " + label + ":", k, re.M):
            body = case(query, label)
            cases.append(body)
            record["selected_body_sha256"]["sysk32_proc.c:" + label] = sha(body.encode())
    pieces.append("static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen) { switch(cls) {\n"
                  + "\n".join(cases) + fallback[0] + " } }")
    setter = take("sysk32_proc.c", "k32_set")
    fallback = re.search(r"    default:\s*return STATUS_INVALID_INFO_CLASS;", setter)
    if not fallback:
        raise ValueError("unexpected actual setter fallback")
    # Current source groups the five selected classes into two compound rows.
    # Admit either grouped or individual candidate rows, each emitted once.
    wanted = {"K32S_PROCESS_MEM_PRIORITY", "K32S_PROCESS_POWER",
              "K32S_THREAD_BOOST", "K32S_THREAD_MEM_PRIORITY", "K32S_THREAD_POWER"}
    matches = list(re.finditer(r"^    (?:case [^\n]+|default:)", setter, re.M))
    scases = []
    for i, m in enumerate(matches):
        end = matches[i+1].start() if i+1 < len(matches) else setter.rfind("}")
        labels = set(re.findall(r"case (K32S_[A-Z_]+):", m[0]))
        if labels & wanted:
            if labels - wanted:
                raise ValueError("selected setter row includes an unselected class")
            body = setter[m.start():end]
            scases.append(body)
            record["selected_body_sha256"]["sysk32_proc.c:" + "+".join(sorted(labels))] = sha(body.encode())
    if set(re.findall(r"case (K32S_[A-Z_]+):", "\n".join(scases))) != wanted:
        raise ValueError("missing selected actual setter row")
    pieces.append("static int32_t host_set(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len) { switch(cls) {\n"
                  + "\n".join(scases) + fallback[0] + " } }")
    definitions = []
    for name in ["PROCESS_QUERY_INFORMATION", "PROCESS_QUERY_LIMITED_INFORMATION", "PROCESS_SET_INFORMATION",
                 "THREAD_QUERY_INFORMATION", "THREAD_QUERY_LIMITED_INFORMATION", "THREAD_SET_INFORMATION"]:
        m = re.search(r"^#define " + name + r"[^\n]+", headers["ipc.h"], re.M)
        if not m:
            raise ValueError("missing actual right " + name)
        definitions.append(m[0])
    # Absent baseline SET_LIMITED constant is an oracle literal, not a skipped
    # test. Candidate named constant is independently checked by the fixture.
    m = re.search(r"^#define THREAD_SET_LIMITED_INFORMATION[^\n]+", headers["ipc.h"], re.M)
    if m:
        definitions += [m[0], "#define HOST_HAS_SET_LIMITED 1"]
    else:
        definitions += ["#define HOST_HAS_SET_LIMITED 0"]
    definitions += re.findall(r"enum \{ K32[QS]_[^;]+;", k)
    definitions += [re.search(r"^#define MAX_PROCS[^\n]+", sources["proc.c"], re.M)[0],
                    re.search(r"^#define TICK_US[^\n]+", headers["k64.h"], re.M)[0],
                    re.search(r"^#define TICK_100NS[^\n]+", k, re.M)[0]]
    cache_fields = ["last_boost_disabled", "last_mem_priority", "last_power_control", "last_power_state"]
    present = [bool(re.search(r"\b" + n + r"\b", headers["proc_internal.h"])) for n in cache_fields]
    if any(present) and not all(present):
        raise ValueError("partial actual settings-cache schema")
    definitions += ["#define HOST_HAS_SETTINGS_CACHE " + str(int(all(present)))]
    emit("api-layout.inc", "\n".join(definitions) + "\n")
    # Canonical frontend constants, whole wrappers and schemas are independently
    # bound; hostshim headers cannot override the production wire definitions.
    for macro in re.findall(r"^#define K32[QS]_[^\n]+", headers["nt.h"], re.M):
        pieces.append(macro)
    pi = sources["k32_procinfo.c"]
    pieces += [re.search(r"^#define THROTTLE_VALID[^\n]+", pi, re.M)[0]]
    pieces += re.findall(r"^#define SHZ_Thread[^\n]+", pi, re.M)
    local = re.search(r"^typedef struct \{[^\n]+SHZ_THREAD_POWER_THROTTLING_STATE;", pi, re.M)[0]
    pieces.append(local)
    record["selected_schema_sha256"]["k32_procinfo.c:SHZ_THREAD_POWER_THROTTLING_STATE"] = sha(local.encode())
    pieces += [take("k32_core.c", "k32_nt_error")]
    pieces += [take("k32_procinfo.c", n) for n in
               ["fail_st", "fail_err", "process_info", "GetThreadPriorityBoost", "SetThreadPriorityBoost",
                "GetProcessInformation", "SetProcessInformation", "GetThreadInformation", "SetThreadInformation", "Wow64GetThreadContext"]]
    pieces += [take("k32_sysinfo.c", "GetThreadGroupAffinity")]
    # Pin the real translation provider/table. The C boundary adapter executes
    # only the selected pinned rows, including BOTH terminating statuses.
    table = sources["ntdll_main.c"]
    a = table.index("static const struct { NTSTATUS status; ULONG error; } status_map[]")
    b = table.index("\n};", a) + 3
    record["selected_body_sha256"]["ntdll_main.c:status_map"] = sha(table[a:b].encode())
    take("ntdll_main.c", "RtlNtStatusToDosError")
    emit("production.inc", "\n\n".join(pieces) + "\n")
    schema = headers["proc_internal.h"]
    a = schema.index("/* ---- virtual address descriptors ---- */")
    z = block_end(schema, schema.index("{", schema.index("struct process {", a)))
    io = re.search(r"typedef struct \{[^{}]*\} ioctx_t;", headers["ipc.h"], re.S)[0]
    proc_layout = schema[a:z] + ";\n" + io + "\n"
    emit("process-layout.inc", proc_layout)
    record["selected_schema_sha256"]["complete_process_objects_ioctx"] = sha(proc_layout.encode())
    schema = headers["k64.h"]
    a = schema.index("typedef struct thread thread_t;")
    z = block_end(schema, schema.index("{", schema.index("struct thread {", a)))
    thread_layout = schema[a:z] + ";\n"
    emit("thread-layout.inc", thread_layout)
    record["selected_schema_sha256"]["complete_TCB"] = sha(thread_layout.encode())
    sdk = headers["sdk-processthreadsapi.h"]
    layouts = [struct_typedef(sdk, tag, final) for tag, final in
               [("_PROCESS_INFORMATION_CLASS", "PROCESS_INFORMATION_CLASS"), ("_APP_MEMORY_INFORMATION", "APP_MEMORY_INFORMATION"),
                ("_MEMORY_PRIORITY_INFORMATION", "MEMORY_PRIORITY_INFORMATION"),
                ("_PROCESS_POWER_THROTTLING_STATE", "PROCESS_POWER_THROTTLING_STATE"),
                ("_THREAD_POWER_THROTTLING_STATE", "THREAD_POWER_THROTTLING_STATE"),
                ("PROCESS_PROTECTION_LEVEL_INFORMATION", "PROCESS_PROTECTION_LEVEL_INFORMATION"),
                ("_MACHINE_ATTRIBUTES", "MACHINE_ATTRIBUTES"), ("_PROCESS_MACHINE_INFORMATION", "PROCESS_MACHINE_INFORMATION")]]
    layouts += [struct_typedef(headers["sdk-winbase.h"], "_THREAD_INFORMATION_CLASS", "THREAD_INFORMATION_CLASS"),
                struct_typedef(headers["sdk-winnt.h"], "_GROUP_AFFINITY", "GROUP_AFFINITY")]
    for name in ["WOW64_SIZE_OF_80387_REGISTERS", "WOW64_MAXIMUM_SUPPORTED_EXTENSION"]:
        layouts.append(re.search(r"^#define " + name + r"[^\n]+", headers["sdk-winnt.h"], re.M)[0])
    layouts += [struct_typedef(headers["sdk-winnt.h"], "_WOW64_FLOATING_SAVE_AREA", "WOW64_FLOATING_SAVE_AREA"),
                "#pragma pack(push,4)", struct_typedef(headers["sdk-winnt.h"], "_WOW64_CONTEXT", "WOW64_CONTEXT"), "#pragma pack(pop)"]
    for name in ["PROCESS_POWER_THROTTLING_CURRENT_VERSION", "PROCESS_POWER_THROTTLING_EXECUTION_SPEED",
                 "THREAD_POWER_THROTTLING_CURRENT_VERSION", "THREAD_POWER_THROTTLING_EXECUTION_SPEED"]:
        layouts.append(re.search(r"^#define " + name + r"[^\n]+", sdk, re.M)[0])
    layouts += [re.search(r"^#define PROTECTION_LEVEL_NONE[^\n]+", headers["sdk-winbase.h"], re.M)[0],
                re.search(r"^#define IMAGE_FILE_MACHINE_AMD64[^\n]+", headers["sdk-winnt.h"], re.M)[0]]
    sdk_layout = "\n".join(layouts).replace("__C89_NAMELESS", "") + "\n"
    emit("sdk-layout.inc", sdk_layout)
    record["selected_schema_sha256"]["SDK_settings_and_group"] = sha(sdk_layout.encode())

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-units", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists(): parser.error("fresh output directory required")
    out.mkdir(parents=True)
    result = {"status": "FAIL", "scope": "Selected actual Q12/Q13/optional strict Q19, five setters and whole public settings/boost/group-affinity/Wow64-context wrappers; real ref/handle/close/detach/final process-free plus legacy time/cycle/accounting bodies, complete schemas and four SDK inputs; explicit IRQ/caller-copy/static storage/heap-quarantine/current/clock/status/unused IPC adapters and bounded null-pseudo child isolation. Stored metadata only",
              "guest_executed": False, "native_windows98_verified": False, "full_runtime_built": False,
              "ap_executed": False, "smp_lifetime_verified": False, "native_allocator_uaf_verified": False, "real_boost_power_eviction_behavior_claimed": False, "platform_system_headers_sealed": False,
              "whole_batch_atomicity_claimed": False, "q7_app_memory_atomicity_claimed": False,
              "external_toolchain_closure_sealed": False,
              "source_sha256": {}, "compiler_sha256": {}, "artifacts_sha256": {}, "selected_body_sha256": {}, "selected_schema_sha256": {}, "records": []}
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
        started=time.monotonic()
        attempt = {"name": name, "command": argv, "state": "running", "admitted": False, "started_unix": time.time()}
        result["records"].append(attempt); save()
        if not stable():
            attempt.update(returncode=125, stdout="", stderr="input changed; refused", refused=True,
                           timed_out=False, interrupted=False, leader_reaped=False)
        else:
            attempt.update(run_owned(argv))
        attempt["state"] = "complete"
        attempt["elapsed_seconds"]=time.monotonic()-started
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
        result["compiler_paths"] = {n:str(p) for n,p in compilers.items()}
        result["absolute_input_sha256"] = {str(p):sha(b) for p,b in snapshots.items()}
        if len({p.name for p in c_inputs}) != len(c_inputs):
            raise ValueError("selected C basenames collide; canonical source binding required")
        sources = {p.name:snapshots[p].decode() for p in c_inputs}
        helper_source = snapshots[ROOT/"shizukudos/tests/test_nt_memory_queries.py"].decode()
        runner_source = snapshots[ROOT/"shizukudos/tests/test_nt_settings.py"].decode()
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
        fixture=out/"frozen/shizukudos/tests/test_nt_settings.c"
        for name,flags in [("gcc",["-O2"]),("clang",["-O1","-g","-fsanitize=address,undefined","-fno-sanitize-recover=all","-fno-omit-frame-pointer"])]:
            binary=out/("nt-settings-"+name)
            rc,_=run([compilers[name],"-std=c11","-Wall","-Wextra","-Werror","-Wno-unused-function","-Wno-unused-parameter",*flags,"-I",out,"-I",out/"frozen/shizukudos/kernel64",fixture,"-o",binary],"compile-"+name)
            passed &= rc==0
            if rc==0:
                pin(binary)
                rc,stdout=run([binary],"run-"+name)
                m=re.search(r"NT_SETTINGS_HOST: (\d+) checks, (\d+) failures",stdout)
                result["records"][-1].update(checks=int(m[1]) if m else None,failures=int(m[2]) if m else None)
                passed &= rc==0 and bool(m) and int(m[2])==0; save()
        if args.compile_units:
            for rel in UNITS:
                src=out/"frozen/shizukudos"/rel; obj=out/(src.stem+".o"); win=rel.startswith("win64/")
                flags=["-O2","-Wall","-Wextra","-Werror","-ffreestanding","-fno-builtin","-fno-stack-protector","-mno-red-zone","-fno-ident","-fno-tree-loop-distribute-patterns"]
                flags += ["-Wno-unused-function","-Wno-unused-parameter","-Wno-cast-function-type","-I",out/"frozen/shizukudos/win64/include"] if win else ["-m64","-march=x86-64","-std=gnu11","-fno-pic","-fno-pie","-mcmodel=kernel","-mgeneral-regs-only","-fwrapv","-fno-strict-aliasing"]
                compiler = compilers["x86_64-w64-mingw32-gcc" if win else "gcc"]
                rc,dep=run([compiler,*flags,"-MM",src],"dependencies-"+src.stem)
                passed &= rc==0
                if rc==0:
                    rule=dep.replace("\\\n"," ")
                    tokens=shlex.split(rule.split(":",1)[1]) if ":" in rule else []
                    deps={Path(t).resolve() for t in tokens}
                    frozen_inputs={out/"frozen"/(str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else "external-sdk/"+p.name) for p in snapshots}
                    missing=sorted(str(p) for p in deps if p not in frozen_inputs)
                    if src not in deps or missing:
                        raise ValueError("unfrozen selected local dependency " + rel + ": " + repr(missing))
                    result.setdefault("dependency_proofs", {})[rel]={"dependencies": sorted(str(p) for p in deps), "selected_source_present": True, "missing": []}
                    save()
                rc,_=run([compiler,*flags,"-c",src,"-o",obj],"freestanding-"+src.stem)
                passed &= rc==0
                if rc==0: pin(obj)
        result["inputs_stable"]=stable()
        result["status"]="PASS" if passed and result["inputs_stable"] and all(command_admitted(r) for r in result["records"]) else "FAIL"
    except (Exception, KeyboardInterrupt) as e:
        result["interrupted"]=isinstance(e,(KeyboardInterrupt,InterruptedError))
        result["setup_error"]=type(e).__name__+": "+str(e)
        result["inputs_stable"]=stable(); print(result["setup_error"],flush=True)
    # Include partial compiler outputs on FAIL; result.json is the separately
    # self-hashed receipt, never a recursive member of its own artifact map.
    try:
        result["terminal_sources_sha256"]={str(p):sha(p.read_bytes()) for p in snapshots}
        for p in sorted(out.rglob("*")):
            if p.is_file() and p != out/"result.json" and p not in artifacts:
                pin(p)
        actual={str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p != out/"result.json"}
        result["artifact_inventory_complete"]=actual==set(result["artifacts_sha256"])
        result["inputs_stable"]=stable()
        if not result["artifact_inventory_complete"] or not result["inputs_stable"]:
            result["status"]="FAIL"
    except OSError as e:
        result["inventory_error"]=type(e).__name__+": "+str(e)
        result["status"]="FAIL"
    save()
    return 0 if result["status"]=="PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
