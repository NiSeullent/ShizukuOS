#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded actual W64 admission, account-launch controls and freestanding proof."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
BUDGET, RESERVE, LOG_LIMIT = 8 << 20, 17 << 30, 256 << 10
RECEIPT_LIMIT = 64 << 10
UNITS = ("sysk32_auth", "ldr", "subsys64", "ipc_proc", "autorun")
EXTRACT = {
    "LOADER_CREATE": ("ldr.c", "ldr_create_process_ex"),
    "THREAD_RESUME": ("sched.c", "thread_resume"),
    "THREAD_MUST_DIE": ("proc.c", "thread_must_die"),
    "PROCESS_TERMINATE": ("proc.c", "process_terminate"),
    "PROCESS_ATTACH_PARENT": ("saw.c", "process_attach_parent"),
    "PROC_WAIT": ("proc.c", "proc_wait"),
    "THREAD_CREATOR_RELEASE": ("sched.c", "thread_creator_release"),
    "THREAD_OBJECT_DETACH": ("objects.c", "thread_object_detach"),
    "IPC_WAKE_TO_DIE": ("ipc_core.c", "ipc_wake_to_die"),
    "REAP_USER_ZOMBIES": ("sched.c", "reap_user_zombies"),
    "THREAD_REAP_PROCESS": ("sched.c", "thread_reap_process"),
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reserve_receipt(path):
    # Allocate actual storage before commands. It counts toward the owned
    # budget and remains available if the subsequent reserve check fails.
    with path.open("xb") as stream:
        stream.write(b"\0" * RECEIPT_LIMIT)
        stream.flush()


def write_receipt(path, receipt):
    encoded = (json.dumps(receipt, indent=2) + "\n").encode()
    if len(encoded) > RECEIPT_LIMIT:
        original_error = str(receipt.get("error", ""))[:2048]
        receipt.update(status="FAIL", error="structured receipt exceeded reserved 64 KiB", receipt_truncated=True)
        minimal = {"status": "FAIL", "error": receipt["error"], "receipt_truncated": True,
                   "original_error": original_error, "oversized_receipt_bytes": len(encoded),
                   "components_requested": receipt.get("components_requested", {}),
                   "components_built": receipt.get("components_built", {}),
                   "command_count": len(receipt.get("commands", [])),
                   "scope": str(receipt.get("scope", ""))[:512],
                   "output_budget_bytes": BUDGET, "disk_reserve_bytes": RESERVE}
        encoded = (json.dumps(minimal, indent=2) + "\n").encode()
    if len(encoded) > RECEIPT_LIMIT:
        raise RuntimeError("minimal receipt exceeds reserved storage")
    # No failing free-space/budget gate is repeated here. This overwrites and
    # truncates only the already allocated owned receipt, preserving logs.
    with path.open("r+b") as stream:
        stream.write(encoded); stream.truncate(); stream.flush()


def definition(data, name):
    # Preserve offsets while hiding comment/quote contents from signature and
    # brace recognition; return the exact original source slice, never a rewrite.
    masked, index, state = list(data), 0, "code"
    while index < len(data):
        c, following = data[index], data[index:index + 2]
        if state == "code":
            if following in ("//", "/*"):
                state = "line" if following == "//" else "comment"
                masked[index:index + 2] = [" ", " "]; index += 2; continue
            if c in ("\"", "'"): state = c; masked[index] = " "
        elif state == "line":
            if c == "\n": state = "code"
            else: masked[index] = " "
        elif state == "comment":
            if following == "*/":
                masked[index:index + 2] = [" ", " "]; state = "code"; index += 2; continue
            if c != "\n": masked[index] = " "
        else:
            if c != "\n": masked[index] = " "
            if c == "\\" and index + 1 < len(data):
                index += 1
                if data[index] != "\n": masked[index] = " "
            elif c == state: state = "code"
        index += 1
    code = "".join(masked)
    signature = r"^[^\n;{}()]*\b" + re.escape(name) + r"\([^;{}]*\)\s*\{"
    matches = [m for m in re.finditer(signature, code, re.M)
               if code[:m.start()].count("{") == code[:m.start()].count("}")]
    match = matches[0] if len(matches) == 1 else None
    if not match:
        raise ValueError("production definition missing: " + name)
    depth, index = 1, match.end()
    while index < len(data):
        c = code[index]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if not depth: return data[match.start():index + 1]
        index += 1
    raise ValueError("unterminated production definition: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--host-only", action="store_true",
                        help="fixture-only continuation; retain an earlier pinned native-object receipt")
    args = parser.parse_args(); out = args.out.resolve()
    if out.exists() or not out.parent.is_dir() or not out.is_relative_to(ROOT / "build"):
        parser.error("fresh project build output with an existing parent required")
    if shutil.disk_usage(out.parent).free < RESERVE + BUDGET:
        parser.error("17 GiB reserve plus output budget required")
    out.mkdir()
    receipt_path = out / "result.json"
    reserve_receipt(receipt_path)
    commands, tools, sources = [], {}, {}
    receipt = {"status": "FAIL", "commands": commands,
               "scope": "actual W64 consumers and authority; named production constructor/scheduler/lifetime bodies; host PE/VM/hardware adapters",
               "actual_windows_execution": False, "actual_native_VMM_delivery": False,
               "native_account_authentication": False, "account_persistence": False,
               "external_toolchain_and_system_header_closure_complete": False,
               "whole_kernel_or_release_acceptance": False,
               "freestanding_units_requested": [] if args.host_only else list(UNITS),
               "components_requested": {"host_admission": True, "auth_positive": True,
                                        "freestanding_kernel64": not args.host_only},
               "output_budget_bytes": BUDGET, "disk_reserve_bytes": RESERVE}
    receipt["receipt_reserved_bytes"] = RECEIPT_LIMIT

    def size():
        return sum(p.stat().st_size for p in out.rglob("*") if p.is_file())

    def limit(extra=0):
        used = size() + extra
        if used > BUDGET or shutil.disk_usage(out).free < RESERVE + max(0, BUDGET - size()):
            raise RuntimeError("owned output budget or disk reserve exceeded")

    def run(name, command, timeout=120):
        command = [str(value) for value in command]
        row = {"name": name, "command": command, "timeout_seconds": timeout}; commands.append(row)
        print("running " + name, flush=True)
        log = out / (name + ".log")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1",
                   ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        limit(); started = time.monotonic()
        with log.open("wb") as stream:
            child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            selector = selectors.DefaultSelector(); selector.register(child.stdout, selectors.EVENT_READ)
            logged = 0
            try:
                while selector.get_map() or child.poll() is None:
                    limit()
                    if time.monotonic() - started > timeout:
                        raise RuntimeError("owned command timeout: " + name)
                    for key, _ in selector.select(.05):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            selector.unregister(key.fileobj); continue
                        remaining = LOG_LIMIT - logged
                        stream.write(data[:remaining]); stream.flush()
                        logged += min(remaining, len(data))
                        if len(data) > remaining:
                            raise RuntimeError("owned command log exceeded 256 KiB: " + name)
                child.wait()
            finally:
                # Custody includes descendants even if the leader already
                # exited and a helper closed its inherited output pipe.
                try: os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                child.wait(); row.update(returncode=child.returncode, log=log.name)
                selector.close(); child.stdout.close()
        row.update(returncode=child.returncode, log=log.name, log_sha256=digest(log),
                   elapsed_seconds=time.monotonic() - started)
        if child.returncode:
            raise RuntimeError(name + " failed: " + log.read_text(errors="replace")[-4096:])
        return log.read_text(errors="replace")

    def pin(name, selected=None):
        path = Path(selected or shutil.which(name) or name).resolve()
        if not path.is_file(): raise RuntimeError("missing tool: " + name)
        tools[name] = {"path": str(path), "sha256": digest(path)}
        return str(path)

    try:
        compilers = {name: pin(name) for name in ("gcc", "clang")}
        pin("python", sys.executable); pin("git")
        for name in ("cc1", "collect2", "as", "ld"):
            printed = run("gcc-" + name, [compilers["gcc"], "-print-prog-name=" + name]).strip()
            pin("gcc-" + name, printed if Path(printed).is_absolute() else shutil.which(printed))
        receipt["checkout_commit"] = run("checkout-commit", [tools["git"]["path"], "rev-parse", "HEAD"]).strip()
        pending = [Path(__file__).resolve(), Path(__file__).with_suffix(".c"),
                   ROOT / "docs/ADR_NATIVE_ANONYMOUS_CREATE_ADMISSION.md", ROOT / "shizukudos/kbuild.py",
                   ROOT / "shizukudos/tests/test_auth_kernel.c"]
        pending += [ROOT / "shizukudos/kernel64" / (name + ".c") for name in UNITS]
        pending += [ROOT / "shizukudos/kernel64" / name for name, _ in EXTRACT.values()]
        pending += [ROOT / "shizukudos/accounts" / name for name in ("account.c", "kdf.c", "sha256.c")]
        contents = {}
        while pending:
            path = pending.pop().resolve(); rel = path.relative_to(ROOT)
            if str(rel) in contents: continue
            data = path.read_bytes(); contents[str(rel)] = data
            pending.extend(path.parent / name.decode() for name in
                           re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M))
        sources = {name: hashlib.sha256(data).hexdigest() for name, data in sorted(contents.items())}
        receipt.update(source_before=sources, tool_before=tools)
        frozen = out / "source-snapshot"
        for name, data in contents.items():
            limit(len(data)); target = frozen / name
            target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(data)
        fixture_rel = str(Path(__file__).with_suffix(".c").relative_to(ROOT))
        fixture = contents[fixture_rel].decode(); bodies = {}
        for tag, (filename, name) in EXTRACT.items():
            marker = "/* @PRODUCTION_" + tag + "@ */"
            if fixture.count(marker) != 1: raise RuntimeError("expected one production marker: " + tag)
            body = definition(contents["shizukudos/kernel64/" + filename].decode(), name)
            bodies[tag] = {"source": "shizukudos/kernel64/" + filename, "function": name,
                           "sha256": hashlib.sha256(body.encode()).hexdigest()}
            fixture = fixture.replace(marker, body)
        generated = frozen / "shizukudos/tests/generated_native_create_admission.c"
        limit(len(fixture.encode())); generated.write_text(fixture)
        receipt.update(production_definitions=bodies, generated_fixture_sha256=digest(generated))
        flags = None
        for node in ast.parse(contents["shizukudos/kbuild.py"]).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "K64_FLAGS" for t in node.targets):
                flags = ast.literal_eval(node.value)
        if not flags: raise RuntimeError("literal production K64_FLAGS missing")
        account_sources = [frozen / "shizukudos/accounts" / name for name in ("account.c", "kdf.c", "sha256.c")]
        for cc, profile in (("gcc", ["-O2"]), ("clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                      "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
            common = ["-std=gnu11", "-Wall", "-Wextra", "-Werror", *profile]
            binary = out / ("admission-" + cc)
            run(cc + "-admission-compile", [compilers[cc], *common, "-pthread", "-ffunction-sections",
                "-fdata-sections", generated, *account_sources, "-Wl,--gc-sections", "-o", binary])
            pinned = digest(binary); output = run(cc + "-admission-run", [binary])
            if "PASS" not in output or digest(binary) != pinned:
                raise RuntimeError("admission oracle or binary stability failed")
            commands[-1].update(binary_sha256=pinned, binary_sha256_after=digest(binary), output=output.strip())
            # Existing complete account dispatcher fixture, unchanged; its loader/hardware adapters remain declared.
            binary = out / ("auth-positive-" + cc)
            run(cc + "-auth-positive-compile", [compilers[cc], *common,
                frozen / "shizukudos/tests/test_auth_kernel.c", *account_sources, "-o", binary])
            pinned = digest(binary); output = run(cc + "-auth-positive-run", [binary])
            if "trusted enrollment, fresh launch" not in output or "PASS" not in output or digest(binary) != pinned:
                raise RuntimeError("existing account-launch oracle or binary stability failed")
            commands[-1].update(binary_sha256=pinned, binary_sha256_after=digest(binary), output=output.strip())
            effective = [f for f in flags if not (cc == "clang" and f == "-fno-tree-loop-distribute-patterns")]
            for name in (() if args.host_only else UNITS):
                obj = out / (cc + "-" + name + ".o")
                run(cc + "-native-" + name, [compilers[cc], *effective, "-I", frozen / "shizukudos",
                    "-I", frozen / "shizukudos/kernel64", "-c", frozen / "shizukudos/kernel64" / (name + ".c"), "-o", obj])
                commands[-1]["object_sha256"] = digest(obj)
        receipt.update(source_after={name: digest(ROOT / name) for name in sources},
                       tool_after={name: {"path": v["path"], "sha256": digest(Path(v["path"]))} for name, v in tools.items()})
        stable = sources == receipt["source_after"] and tools == receipt["tool_after"]
        stable = stable and all(digest(frozen / name) == value for name, value in sources.items())
        limit()
        receipt.update(inputs_unchanged=stable, status="PASS" if stable else "FAIL")
    except BaseException as error:
        receipt["error"] = str(error)
        if sources:
            receipt["source_after"] = {name: digest(ROOT / name) for name in sources}
            receipt["inputs_unchanged"] = sources == receipt["source_after"]
    receipt["components_built"] = {
        "host_admission": sum(row["name"].endswith("-admission-compile") and row.get("returncode") == 0
                              for row in commands) == 2,
        "auth_positive": sum(row["name"].endswith("-auth-positive-compile") and row.get("returncode") == 0
                             for row in commands) == 2,
        "freestanding_kernel64": not args.host_only and
            sum("-native-" in row["name"] and row.get("returncode") == 0 for row in commands) == 2 * len(UNITS)}
    receipt.update(bytes_before_receipt=size(), disk_free_bytes_after=shutil.disk_usage(out).free)
    write_receipt(receipt_path, receipt)
    print(receipt["status"] + ": " + str(out / "result.json"), flush=True)
    if "error" in receipt: print(receipt["error"], file=sys.stderr)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
