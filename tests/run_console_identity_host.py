#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile unchanged production bodies plus isolated host adapters; never run a VM."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True


def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()


def function(source, signature):
    start = source.index(signature)
    at = source.index("{", start); level = 0; state = "code"; i = at
    while i < len(source):
        c, nxt = source[i], source[i:i + 2]
        if state == "line":
            if c == "\n": state = "code"
        elif state == "comment":
            if nxt == "*/": state = "code"; i += 1
        elif state in ("string", "char"):
            if c == "\\": i += 1
            elif c == ('"' if state == "string" else "'"): state = "code"
        elif nxt == "//": state = "line"; i += 1
        elif nxt == "/*": state = "comment"; i += 1
        elif c == '"': state = "string"
        elif c == "'": state = "char"
        elif c == "{": level += 1
        elif c == "}":
            level -= 1
            if not level: return source[start:i + 1] + "\n"
        i += 1
    raise ValueError("unbounded production function")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--console-stage", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args(); repo, stage, out = a.repo.resolve(), a.console_stage.resolve(), a.out.resolve()
    if out.exists(): raise ValueError("new owned output required")
    out.mkdir(parents=True)
    files = ["shizukudos/kernel64/sysfile.c", "shizukudos/win64/kernel32/k32_file.c"]
    base_file = stage / "BASE-SOURCE.json"
    base = json.loads(base_file.read_text()) if base_file.exists() else {name: sha(repo / name) for name in files}
    for name in files:
        if sha(repo / name) not in (base[name], sha(stage / name)):
            raise ValueError("root is neither declared console BASE nor exact integrated source")
    pinned = {name: sha(stage / name) for name in files}
    kernel = (stage / files[0]).read_text(); k32 = (stage / files[1]).read_text()
    volume = (repo / "shizukudos/kernel64/sysk32.c").read_text()
    kernel_bodies = kernel[kernel.index("struct basicinfo "):kernel.index("static int32_t sys_set_info_file(")]
    kernel_bodies += "\n".join(function(volume, name) for name in (
        "static int32_t put_result(", "static uint32_t put_utf16_ascii(", "static int32_t sys_query_volume("))
    k32_bodies = "\n".join(function(k32, name) for name in ("int k32_console_handle(", "BOOL k32_console_check("))
    console_constructor = function(kernel, "kobject_t *console_object(")
    create_body = function(kernel, "static int32_t sys_create_file(")
    console_route = function(create_body, 'if (!strcmp(path, "\\\\??\\\\CONOUT$")')
    fixture = Path(__file__).with_name("console_identity_host.c")
    source = fixture.read_text().replace("/* PRODUCTION_KERNEL_QUERY_BODIES */", kernel_bodies)
    source = source.replace("/* PRODUCTION_KERNEL32_CONSOLE_BODIES */", k32_bodies)
    source = source.replace("/* PRODUCTION_CONSOLE_CONSTRUCTOR */", console_constructor)
    source = source.replace("/* PRODUCTION_CONSOLE_OPEN_ROUTE */", console_route)
    generated = out / "actual_production_console_host.c"; generated.write_text(source)
    rows = []
    for compiler, extra in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        command = [compiler, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing",
                   *extra, str(generated), "-o", str(out / compiler)]
        start = time.monotonic(); build = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (compiler + "-build.log")).write_text(build.stdout + build.stderr)
        row = {"compiler": compiler, "command": command, "build_exit_code": build.returncode}
        if not build.returncode:
            run = subprocess.run([str(out / compiler)], capture_output=True, text=True, timeout=30)
            (out / (compiler + "-run.log")).write_text(run.stdout + run.stderr)
            row.update(run_exit_code=run.returncode, stdout=run.stdout, elapsed_seconds=round(time.monotonic() - start, 3))
        rows.append(row)
    # Use exactly the root completed build's compile flags, changing only the
    # input source and owned object output. Header paths retain the real ABI.
    kr = json.loads((repo / "build/shizukudos/kernels-build-result.json").read_text())
    wr = json.loads((repo / "build/shizukudos/win64/build-result.json").read_text())
    commands = [c for ent in kr["kernels"].values() for c in ent["commands"]]
    for name in files:
        selected = [c for c in commands if str(repo / name) in c and "-c" in c]
        if name.startswith("shizukudos/win64/"):
            linked = wr["commands"]["kernel32"]
            if str(repo / name) not in linked: raise ValueError("source absent from actual kernel32 build")
            selected = [[*linked[:linked.index("-shared")], "-I", str(repo / "shizukudos/win64/include"),
                         "-I", str(repo / "shizukudos/win64/kernel32"), "-c", str(repo / name), "-o", "owned-placeholder"]]
        if not selected: raise ValueError("actual production object command absent from receipt")
        for number, original in enumerate(selected):
            command = list(original); command[command.index(str(repo / name))] = str(stage / name)
            command[command.index("-o") + 1] = str(out / (Path(name).stem + "-" + str(number) + ".o"))
            run = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (out / (Path(name).stem + "-" + str(number) + "-object.log")).write_text(run.stdout + run.stderr)
            rows.append({"whole_production_object": name, "command": command, "exit_code": run.returncode})
    result = {"schema": "shizuku-console-identity-host/1", "source_sha256": pinned, "root_base_sha256": base,
              "native_volume_source_sha256": sha(repo / "shizukudos/kernel64/sysk32.c"),
              "fixture_sha256": sha(fixture), "runner_sha256": sha(Path(__file__)), "generated_source_sha256": sha(generated),
              "results": rows, "VM_executed": False, "actual_guest_T_E1_KERNEL32_verified": False,
              "source_before_after_match": pinned == {name: sha(stage / name) for name in files}}
    result["status"] = "PASS_HOST_PRODUCTION_BODY_AND_OBJECT_COMPILE" if all(row.get("exit_code", row.get("run_exit_code", -1)) == 0 for row in rows) and result["source_before_after_match"] else "FAIL_HOST_EVIDENCE"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    for row in rows:
        print(json.dumps({k: v for k, v in row.items() if k != "command"}))
    print(result["status"])
    return 0 if result["status"].startswith("PASS_") else 1


if __name__ == "__main__": raise SystemExit(main())
