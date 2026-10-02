#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded host contracts over exact production bodies, with frozen evidence.

No full kernel/runtime build, network, guest or native Windows acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FILES = ["kernel64/proc_internal.h", "kernel64/ipc.h", "kernel64/proc.c", "kernel64/objects.c",
         "kernel64/ipc_proc.c", "kernel64/sysk32_proc.c", "kernel64/sysx.c", "win64/kernel32/k32_core.c",
         "win64/kernel32/k32_misc.c", "kernel64/sched.c", "kernel64/ipc_core.c", "kernel64/ntsys.h",
         "kernel64/smp_boot.c", "kernel64/k64.h", "kernel64/sched_cpu.h", "kernel64/smp_boot.h",
         "win64/kernel32/k32_procinfo.c",
         "kcommon/nt_sched_policy.h", "tests/test_nt_thread_priority.c", "tests/test_nt_thread_priority.py"]


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-units", action="store_true", help="compile only eight actual priority translation units")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("a fresh output directory is required")
    out.mkdir(parents=True)
    paths = [ROOT / "shizukudos" / name for name in FILES]
    # Freeze the complete local header closure used by the seven units. The
    # actual unit compiles below consume these copies, never a live checkout.
    paths.extend(sorted((ROOT / "shizukudos").rglob("*.h")))
    paths = list(dict.fromkeys(paths))
    snapshots = {p: p.read_bytes() for p in paths}
    artifacts = {}
    for p, data in snapshots.items():
        f = out / "frozen" / p.relative_to(ROOT); f.parent.mkdir(parents=True, exist_ok=True); f.write_bytes(data)
        artifacts[f] = data
    sources = {p.name: data.decode() for p, data in snapshots.items() if p.suffix == ".c"}
    pieces = [function(sources["smp_boot.c"], name) for name in ("initial_apic_id", "shz_smp_this_cpu")]
    pieces.append(re.search(r"^typedef struct[^\n]+queue_guard_t;", sources["sched.c"], re.M)[0])
    for filename, names in [
        ("sched.c", ["sched_cpu_identity", "bsp_scheduler_owner", "sched_owner_context", "sched_cpu_register", "queue_enter", "queue_leave",
                      "thread_pointer_valid", "ready_enqueue_locked", "ready_enqueue", "ready_remove", "thread_current",
                      "thread_set_sched_policy", "thread_get_sched_policy"]),
        ("ipc_core.c", ["ipc_ref_handle", "ipc_ref_process"]),
        ("ipc_proc.c", ["ref_thread", "attached_thread", "sys_query_thread"]),
        ("objects.c", ["ob_ref", "ob_deref", "thread_object_detach"]),
        ("proc.c", ["thread_must_die", "release_thread_user_memory", "start_thread_common"]),
    ]:
        if filename == "ipc_proc.c":
            pieces.append(re.search(r"^struct thread_basic[^\n]+", sources[filename], re.M)[0])
        pieces.extend(function(sources[filename], n) for n in names)
    pieces.extend(function(sources["sched.c"], n) for n in ("sched_switch_complete", "reap_user_zombies", "thread_reap_exited"))
    pieces.append("void ipc_object_free(kobject_t *o) { switch (o->type) {\n" +
                  case(sources["ipc_core.c"], "OB_PROCESS") + "default: break; } }\n")
    pieces.append(function(sources["sysk32_proc.c"], "ref_query_object", optional=True))
    pieces.extend(function(sources["sysk32_proc.c"], n) for n in ("proc_of_handle", "live_threads", "put_out"))
    pieces.append(function(sources["ipc_proc.c"], "sys_query_process"))
    pieces.append(function(sources["ipc_proc.c"], "sys_set_thread", optional=True))
    pieces.append(function(sources["sysk32_proc.c"], "ipc_set_process_priority_class", optional=True))
    pieces.append(function(sources["sysk32_proc.c"], "set_process_priority_class", optional=True))
    pieces.append(function(sources["ipc_proc.c"], "sys_set_process_priority", optional=True))
    pieces.append(function(sources["ipc_proc.c"], "ipc_proc_syscall"))
    pieces.append("static int32_t host_generic_syscall(process_t *p, struct regs *r, uint32_t num, "
                  "uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4) { switch(num) {\n" +
                  case(sources["sysx.c"], "SYS_NtQueryInformationThread") +
                  case(sources["sysx.c"], "SYS_NtSetInformationThread") +
                  case(sources["sysx.c"], "SYS_NtQueryInformationProcess") +
                  case(sources["sysx.c"], "SYS_NtSetInformationProcess") +
                  "default: return STATUS_INVALID_INFO_CLASS; } }\n")
    pieces.append("static int32_t host_k32_query(process_t *cur, uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen) "
                  "{ switch(cls) {\n" + case(sources["sysk32_proc.c"], "K32Q_PROCESS_INFO") +
                  "default: return STATUS_INVALID_INFO_CLASS; } }\n")
    pieces.append("static int32_t host_k32_set(process_t *cur, uint64_t cls,uint64_t h,uint64_t buf,uint64_t len) "
                  "{ switch(cls) {\n" + case(sources["sysk32_proc.c"], "K32S_PRIORITY_CLASS") +
                  "default: return STATUS_INVALID_INFO_CLASS; } }\n")
    for filename, names in [("k32_core.c", ["GetThreadPriority", "SetThreadPriority"]),
                            ("k32_misc.c", ["SetThreadAffinityMask"])]:
        pieces.extend(function(sources[filename], n) for n in names)
    procinfo = sources["k32_procinfo.c"]
    background = re.search(r"^static volatile LONG g_background;[^\n]*", procinfo, re.M)
    if background:
        pieces.append(background[0])
    pieces.extend(function(procinfo, n, optional=n == "is_self") for n in
                  ("fail_st", "fail_err", "process_info", "is_self", "GetPriorityClass", "SetPriorityClass"))
    generated = out / "production.inc"; generated.write_text("\n\n".join(pieces) + "\n")
    artifacts[generated] = generated.read_bytes()
    schema = snapshots[ROOT / "shizukudos/kernel64/proc_internal.h"].decode()
    start = schema.index("struct kobject {")
    layout = out / "object-layout.inc"
    layout.write_text(schema[start:block_end(schema, schema.index("{", start))] + ";\n")
    artifacts[layout] = layout.read_bytes()
    # Include the complete unchanged production process/VAD/handle/object
    # declarations, rather than a priority-only process substitute.
    start = schema.index("/* ---- virtual address descriptors ---- */")
    end = block_end(schema, schema.index("{", schema.index("struct process {", start)))
    layout = out / "process-layout.inc"
    ipc_schema = snapshots[ROOT / "shizukudos/kernel64/ipc.h"].decode()
    clock_schema = snapshots[ROOT / "shizukudos/kernel64/k64.h"].decode()
    layout.write_text(schema[start:end] + ";\n" +
                      re.search(r"^struct ipc_ustr[^\n]+", ipc_schema, re.M)[0] + "\n" +
                      re.search(r"^#define TICK_US[^\n]+", clock_schema, re.M)[0] + "\n")
    artifacts[layout] = layout.read_bytes()
    # Use the actual complete TCB layout and scheduler types/constants. Host
    # process/handle/IRQ/TLS boundaries remain explicitly modeled by the fixture.
    schema = snapshots[ROOT / "shizukudos/kernel64/k64.h"].decode()
    start = schema.index("typedef struct thread thread_t;")
    end = block_end(schema, schema.index("{", schema.index("struct thread {", start)))
    layout = out / "thread-layout.inc"
    layout.write_text(schema[start:end] + ";\n")
    artifacts[layout] = layout.read_bytes()
    compilers = {n: Path(shutil.which(n)).resolve() for n in ["gcc", "clang"] +
                 (["x86_64-w64-mingw32-gcc"] if args.compile_units else [])}
    compiler_bytes = {n: p.read_bytes() for n, p in compilers.items()}
    result = {"status": "FAIL", "scope": "Actual NT process/thread dispatch/wrapper/init/retarget, native queue/policy/identity/reclaim/ref/free bodies and complete TCB/process/object schemas with host platform adapters",
              "guest_executed": False, "native_windows98_verified": False, "full_runtime_built": False,
              "ap_executed": False, "hardware_context_switch_executed": False,
              "source_sha256": {str(p.relative_to(ROOT)): sha(b) for p,b in snapshots.items()},
              "compiler_sha256": {n: sha(b) for n,b in compiler_bytes.items()},
              "records": [], "artifacts_sha256": {str(p.relative_to(out)): sha(b) for p,b in artifacts.items()}}

    def stable():
        return all(p.read_bytes() == b for p,b in snapshots.items()) and all(
            compilers[n].read_bytes() == b for n,b in compiler_bytes.items()) and all(
            p.read_bytes() == b for p,b in artifacts.items())

    def run(argv, name):
        argv = list(map(str, argv))
        if not stable():
            r = subprocess.CompletedProcess(argv, 125, "", "source/compiler/artifact changed; refused")
        else:
            try:
                r = subprocess.run(argv, text=True, capture_output=True, timeout=30)
            except subprocess.TimeoutExpired:
                r = subprocess.CompletedProcess(argv, 124, "", "bounded 30-second timeout")
        (out / (name + ".log")).write_text(r.stdout + r.stderr)
        result["records"].append({"name": name, "command": argv, "returncode": r.returncode,
                                  "stdout": r.stdout, "stderr": r.stderr})
        print(name, r.returncode, (r.stdout + r.stderr)[-1600:], flush=True)
        return r

    def pin(p):
        artifacts[p] = p.read_bytes(); result["artifacts_sha256"][str(p.relative_to(out))] = sha(artifacts[p])

    passed = True
    fixture = out / "frozen/shizukudos/tests/test_nt_thread_priority.c"
    for name, flags in [("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                              "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])]:
        binary = out / ("nt-thread-priority-" + name)
        r = run([compilers[name], "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                 "-Wno-unused-parameter", *flags, "-I", out, "-I", out / "frozen/shizukudos/kernel64",
                 "-I", out / "frozen/shizukudos/kcommon", fixture, "-o", binary], "compile-" + name)
        passed = passed and r.returncode == 0
        if r.returncode == 0:
            pin(binary); r = run([binary], "run-" + name)
            count = re.search(r"NT_THREAD_PRIORITY_HOST: (\d+) checks, (\d+) failures", r.stdout)
            result["records"][-1]["checks"] = int(count[1]) if count else None
            result["records"][-1]["failures"] = int(count[2]) if count else None
            passed = passed and r.returncode == 0 and bool(count) and int(count[2]) == 0
    if args.compile_units:
        # Compile real translation units only, never link or rebuild a runtime.
        for rel in FILES:
            if rel not in FILES[2:9] + ["win64/kernel32/k32_procinfo.c"] or not rel.endswith(".c"):
                continue
            src = out / "frozen/shizukudos" / rel; obj = out / (src.stem + ".o")
            flags = ["-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                     "-mno-red-zone", "-fno-ident", "-fno-tree-loop-distribute-patterns"]
            win = rel.startswith("win64/")
            if win:
                flags += ["-Wno-unused-function", "-Wno-unused-parameter", "-Wno-cast-function-type"]
            else:
                flags += ["-m64", "-march=x86-64", "-std=gnu11", "-fno-pic", "-fno-pie", "-mcmodel=kernel",
                          "-mgeneral-regs-only", "-fwrapv", "-fno-strict-aliasing"]
            r = run([compilers["x86_64-w64-mingw32-gcc" if win else "gcc"], *flags, "-c", src, "-o", obj],
                    "freestanding-" + src.stem)
            passed = passed and r.returncode == 0
            if r.returncode == 0:
                pin(obj)
    result["inputs_stable"] = stable()
    result["status"] = "PASS" if passed and result["inputs_stable"] else "FAIL"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
