#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual IPC/fallback duplicate bodies and complete production object compilation."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def function(source, signature):
    start = source.index(signature); i = source.index("{", start); level = 0; state = "code"
    while i < len(source):
        c, pair = source[i], source[i:i + 2]
        if state == "line":
            if c == "\n": state = "code"
        elif state == "comment":
            if pair == "*/": state = "code"; i += 1
        elif state in ("string", "char"):
            if c == "\\": i += 1
            elif c == ('"' if state == "string" else "'"): state = "code"
        elif pair == "//": state = "line"; i += 1
        elif pair == "/*": state = "comment"; i += 1
        elif c == '"': state = "string"
        elif c == "'": state = "char"
        elif c == "{": level += 1
        elif c == "}":
            level -= 1
            if not level: return source[start:i + 1] + "\n"
        i += 1
    raise ValueError("unterminated production function")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "proc-stage", "out"): parser.add_argument("--" + name, type=Path, required=True)
    a = parser.parse_args(); repo, stage, out = a.repo.resolve(), a.proc_stage.resolve(), a.out.resolve()
    if out.exists(): raise ValueError("new owned output required")
    out.mkdir(parents=True)
    relative = "shizukudos/kernel64/ipc_proc.c"
    changed = (relative, "shizukudos/kernel64/sysx.c")
    modified = (*changed, "shizukudos/win64/tests/t_sec_access.c", "shizukudos/kernel64/ipc_section_security.h")
    names = (relative, "shizukudos/kernel64/objects.c", "shizukudos/kernel64/ipc_core.c", "shizukudos/kernel64/ipc_section.c",
             "shizukudos/kernel64/ipc_section_security.h", "shizukudos/kernel64/sysx.c", "shizukudos/kernel64/syscall.c",
             "shizukudos/win64/tests/t_sec_access.c")
    base_file = stage / "BASE-SOURCE.json"
    base = json.loads(base_file.read_text()) if base_file.exists() else {name: sha(repo / name) for name in names}
    pinned = {name: sha(stage / name) for name in names}
    for name in names:
        if sha(repo / name) not in (base[name], pinned[name]): raise ValueError("root differs from BASE/current stage: " + name)
        if name not in modified and pinned[name] != base[name]: raise ValueError("undelegated support source was modified: " + name)
    sources = {name: (stage / name).read_text() for name in names}
    selections = [("shizukudos/kernel64/objects.c", name) for name in (
        "int32_t handle_insert(", "int32_t handle_ref(", "int32_t handle_close(")]
    selections += [("shizukudos/kernel64/ipc_core.c", name) for name in (
        "int32_t ipc_give_handle(", "int32_t ipc_ref_handle(", "int32_t ipc_ref_process(")]
    selections += [("shizukudos/kernel64/ipc_section.c", "int32_t ipc_section_duplicate_access("),
                   (relative, "static uint32_t handle_flags_of("), (relative, "static int32_t sys_duplicate(")]
    bodies = "\n".join(function(sources[name], signature) for name, signature in selections)
    fixture = Path(__file__).with_name("duplicate_access_host.c")
    (out / "actual_section_security.h").write_bytes((stage / "shizukudos/kernel64/ipc_section_security.h").read_bytes())
    generated = out / "actual_duplicate_host.c"
    code = fixture.read_text().replace("/* ACTUAL_OBJECT_AND_IPC_FUNCTIONS */", bodies)
    legacy = sources["shizukudos/kernel64/sysx.c"]
    helpers = "\n".join(function(legacy, name) for name in (
        "static int32_t give_handle(", "static kobject_t *object_for_handle_access("))
    code = code.replace("/* ACTUAL_LEGACY_SYSX_HELPERS */", helpers)
    code = code.replace("/* ACTUAL_LEGACY_SYSX_DUPLICATE_CASE */", function(legacy, "case SYS_NtDuplicateObject:"))
    generated.write_text(code)
    rows = []
    for compiler, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                   "-fno-strict-aliasing", *extra, str(generated), "-o", str(out / compiler)]
        start = time.monotonic(); build = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (compiler + "-build.log")).write_text(build.stdout + build.stderr)
        row = {"compiler": compiler, "command": command, "build_exit_code": build.returncode}
        if not build.returncode:
            run = subprocess.run([str(out / compiler)], capture_output=True, text=True, timeout=30)
            (out / (compiler + "-run.log")).write_text(run.stdout + run.stderr)
            row.update(run_exit_code=run.returncode, stdout=run.stdout)
        row["elapsed_seconds"] = round(time.monotonic() - start, 3); rows.append(row)
    kr = json.loads((repo / "build/shizukudos/kernels-build-result.json").read_text())
    for source in changed:
        originals = [c for ent in kr["kernels"].values() for c in ent["commands"] if str(repo / source) in c and "-c" in c]
        if len(originals) != 2: raise ValueError("native+standalone actual object commands required: " + source)
        for number, original in enumerate(originals):
            command = list(original); command[command.index(str(repo / source))] = str(stage / source)
            stem = Path(source).stem + "-" + str(number)
            command[command.index("-o") + 1] = str(out / (stem + ".o"))
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (out / (stem + "-object.log")).write_text(run.stdout + run.stderr)
            rows.append({"whole_production_object": source, "command": command, "exit_code": run.returncode})
    result = {"schema": "shizuku-section-duplicate-host/1", "source_sha256": pinned, "base_sha256": base,
              "fixture_sha256": sha(fixture), "runner_sha256": sha(Path(__file__)), "generated_source_sha256": sha(generated),
              "actual_body_selections": selections, "results": rows,
              "source_before_after_match": pinned == {name: sha(stage / name) for name in names},
              "VM_executed": False, "actual_T_SEC_ACCESS_guest_verified": False,
              "actual_empty_DACL_READ_CONTROL_guest_fixture_sha256": pinned["shizukudos/win64/tests/t_sec_access.c"],
              "routing": "syscall.c -> ipc_syscall_override -> ipc_core route -> ipc_proc_syscall -> sys_duplicate",
              "legacy_sysx_fallback_fixed": True}
    result["status"] = "PASS_ACTUAL_PRODUCTION_DUPLICATE_BODY_HOST" if all(row.get("exit_code", row.get("run_exit_code", -1)) == 0 for row in rows) and result["source_before_after_match"] else "FAIL_ACTUAL_BODY_HOST"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for row in rows: print(json.dumps({k: v for k, v in row.items() if k != "command"}))
    print(result["status"])
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__": raise SystemExit(main())
