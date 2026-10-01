#!/usr/bin/env python3
"""Link a real-WTF archive runtime caller; build and imports are separate gates.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Does not execute a PE or start a guest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from iewebkit_build_win98 import audit
from core_archive_receipt import create as archive_snapshot, file_pin, private_path, FLOOR

IMMUTABLE_ARCHIVE_FIELDS = (
    "archive", "member_inventory_sha256", "extra_object_inventory_sha256",
    "compiler_input_inventory_sha256", "configuration", "source_basis",
    "toolchain", "tools", "compiled_sources", "inspector",
)


def immutable_snapshot(path):
    value = json.loads(path.read_text())
    if not value["ninja_order_verified"] or not value["before_after_unchanged"]:
        raise ValueError("Incomplete actual archive provenance snapshot")
    # core-build.json is mutable progress context, never an immutable link input.
    return {name: value[name] for name in IMMUTABLE_ARCHIVE_FIELDS}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def allocator_input(work, build, allocator, entries, pin):
    """Require the reviewed real source port and its explicit C profile."""
    cache = (build / "CMakeCache.txt").read_text().splitlines()
    source_rows = [line.split("=", 1)[1] for line in cache
                   if line.startswith("CMAKE_HOME_DIRECTORY:INTERNAL=")]
    if len(source_rows) != 1:
        raise ValueError("Actual allocator build source root is ambiguous")
    source_root = private_path(Path(source_rows[0]), work)
    patch = HERE / pin["patch"]
    if digest(patch) != pin["patch_sha256"]:
        raise ValueError("Reviewed allocator source patch changed")
    source_pins = []
    for row in pin["files"]:
        source_pin = file_pin(private_path(source_root / row["path"], work))[0]
        if source_pin["sha256"] != row["after_sha256"]:
            raise ValueError("Actual allocator source does not match its reviewed after pin")
        source_pins.append(source_pin)
    candidates = []
    for entry in entries:
        argv = entry.get("arguments") or shlex.split(entry["command"])
        if argv.count("-o") != 1:
            continue
        emitted = Path(argv[argv.index("-o") + 1])
        if not emitted.is_absolute():
            emitted = Path(entry["directory"]) / emitted
        if emitted.resolve() == allocator.resolve():
            candidates.append((entry, argv))
    if len(candidates) != 1:
        raise ValueError("Actual standalone allocator compile command is ambiguous")
    entry, argv = candidates[0]
    actual_source = Path(entry["file"])
    if not actual_source.is_absolute():
        actual_source = Path(entry["directory"]) / actual_source
    if actual_source.resolve() != source_root / "Source/bmalloc/mimalloc/mimalloc/src/static.c":
        raise ValueError("Standalone allocator object did not select the genuine static.c")
    definitions, undefines = [], []
    for index, token in enumerate(argv):
        if token in ("-D", "-U"):
            value = argv[index + 1] if index + 1 < len(argv) else ""
            kind = token
        elif token.startswith(("-D", "-U")):
            kind, value = token[:2], token[2:]
        else:
            continue
        if value.split("=", 1)[0] == "IEWEBKIT_WIN9X":
            (definitions if kind == "-D" else undefines).append(value)
    if definitions != ["IEWEBKIT_WIN9X=1"] or undefines:
        raise ValueError("Actual standalone allocator command omitted or overrides the Win9x profile")
    return {"pin": str(HERE / "core_allocator_pin.json"), "patch": file_pin(patch)[0],
            "source_pins": source_pins, "source": str(actual_source),
            "argv_sha256": hashlib.sha256(json.dumps(argv, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest(), "profile_gate_passed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--diagnostic", action="store_true",
                        help="New closed-handle checkpoint/direct-COFF-abort caller; preserves original v5")
    args = parser.parse_args()
    work = args.work.resolve()
    build = work / "build-jsc-win9x"
    output = private_path(args.output, work, exists=False)
    if output.exists():
        raise FileExistsError("Preserve the existing linked fixture and receipt")
    reserve = (256 + 128 if args.diagnostic else 64) * 1024 ** 2
    if shutil.disk_usage(work).free < FLOOR + reserve:
        raise ValueError("Preserve the 20 GiB host floor plus the bounded native-link budget")
    output.mkdir(parents=True, mode=0o700)
    source = HERE / ("core_wtf_diagnostic.cpp" if args.diagnostic else "core_wtf_native.cpp")
    extra_sources = [HERE / "src/core_Win9xDiagnosticLog.h"] if args.diagnostic else []
    compile_database = build / "compile_commands.json"
    initial = {}

    def read_pinned_json(path):
        key = str(path.resolve())
        initial[key] = file_pin(path)
        value = json.loads(path.read_text())
        if file_pin(path) != initial[key]:
            raise ValueError("JSON input changed while being read: " + str(path))
        return value

    runtime_validator = HERE / "core_build.py"
    for path in (source, Path(__file__), HERE / "core_archive_receipt.py", runtime_validator,
                 build / "cmakeconfig.h", build / "CMakeCache.txt", *extra_sources):
        initial[str(path.resolve())] = file_pin(path)
    entries = read_pinned_json(compile_database)
    baseline = read_pinned_json(args.baseline)
    entry = next(item for item in entries if item["file"].endswith("/win/RunLoopWin.cpp"))
    command = shlex.split(entry["command"])
    obj = output / "WTFNAT.o"
    command[command.index("-o") + 1] = str(obj)
    command[command.index("-c") + 1] = str(source)
    archives = [build / "lib/libWTF.a", build / "lib/libbmalloc.a"]
    # bmalloc's real CMake interface propagates this object-library member
    # separately; thin libbmalloc.a alone does not contain its mi_* definitions.
    allocator = build / "Source/bmalloc/mimalloc/mimalloc/CMakeFiles/mimalloc-obj.dir/src/static.c.obj"
    allocator_pin_path = HERE / "core_allocator_pin.json"
    allocator_pin = read_pinned_json(allocator_pin_path)
    allocator_binding = allocator_input(work, build, allocator, entries, allocator_pin)
    for row in [*allocator_binding["source_pins"], allocator_binding["patch"]]:
        path = Path(row["path"])
        snapshot = file_pin(path)
        if snapshot[0] != row:
            raise ValueError("Allocator source or patch changed after profile validation")
        initial[str(path.resolve())] = snapshot
    icu = work / "icu-work/prefix-x86-win9x/lib"
    archives += [icu / name for name in ("libsicuin.a", "libsicuuc.a", "libsicudt.a")]
    for path in [*archives, allocator]:
        if not path.is_file():
            raise FileNotFoundError("Complete actual archive build first: " + str(path))
    binary = output / "WTFNAT.EXE"
    # Reuse the engine builder's genuine paired-source validator. Pin its
    # source across import and link so cached Python code cannot silently drift.
    from core_build import runtime_link_input, run as bounded_run
    if file_pin(runtime_validator) != initial[str(runtime_validator.resolve())]:
        raise ValueError("Runtime validator changed during import")
    runtime_obj, runtime_binding = runtime_link_input(args.runtime)
    build_context = read_pinned_json(work / "core-build.json")
    # This receipt is progress context; it changes during bounded subprocess
    # execution and is not one of the immutable source/compiler link inputs.
    initial.pop(str((work / "core-build.json").resolve()))
    budget = build_context["disk_budget_bytes"]
    runtime_inputs = runtime_binding.get("input_pins")
    if not isinstance(runtime_inputs, list) or not runtime_inputs:
        raise ValueError("Paired runtime validator must expose its complete immutable input pins")
    for row in runtime_inputs:
        snapshot = file_pin(Path(row["path"]))
        if snapshot[0]["sha256"] != row["sha256"]:
            raise ValueError("Validated runtime input changed before native link")
        initial[str(Path(row["path"]).resolve())] = snapshot
    link = [command[0], "-mwindows", "-static", "-static-libgcc", "-static-libstdc++", "-Wl,--gc-sections",
            "-Wl,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0",
            str(obj), str(allocator), str(runtime_obj), "-Wl,--start-group", *map(str, archives), "-Wl,--end-group",
            "-ldbghelp", "-lshlwapi", "-lwinmm", "-latomic", "-lws2_32", "-ladvapi32", "-luser32", "-lole32", "-luuid",
            "-o", str(binary)]
    if args.diagnostic:
        link.insert(1, "-Wl,--wrap=abort")
    report = {"schema": "iewebkit-real-wtf-linked-native-v1", "source": str(source),
              "source_sha256": initial[str(source.resolve())][0]["sha256"],
              "configuration_sha256": initial[str((build / "cmakeconfig.h").resolve())][0]["sha256"],
              "compile_database_sha256": initial[str(compile_database.resolve())][0]["sha256"],
              "archives": [{"path": str(path), "sha256": digest(path)} for path in archives],
              "allocator_object": {"path": str(allocator), "sha256": digest(allocator)},
              "allocator_profile": allocator_binding,
              "runtime": runtime_binding,
              "baseline": {"path": str(args.baseline),
                           "sha256": initial[str(args.baseline.resolve())][0]["sha256"]},
              "commands": [], "guest_execution": "NOT-VERIFIED", "full_engine_or_renderer": False,
              "link_provenance_passed": False, "thin_archive_snapshots": {"pre": [], "post": []}}
    if args.diagnostic:
        report["diagnostic_scope"] = {"closed_checkpoint_handles": True,
            "wrapper": "GNU --wrap=abort redirects direct COFF _abort references to ___wrap_abort",
            "system_crt_internal_aborts_intercepted": False,
            "phase_and_actual_return_pc": True, "engine_behavior_modified": False}
    receipt = output / "WTFNAT.receipt.json"
    def save():
        receipt.write_text(json.dumps(report, indent=2) + "\n")

    try:
        immutable_paths = [source, Path(__file__), HERE / "core_archive_receipt.py", args.baseline,
                           compile_database, build / "cmakeconfig.h", build / "CMakeCache.txt",
                           allocator, runtime_obj, runtime_validator, allocator_pin_path,
                           Path(allocator_binding["patch"]["path"]), *archives[2:]]
        immutable_paths += [Path(row["path"]) for row in allocator_binding["source_pins"]]
        immutable_paths += [Path(row["path"]) for row in runtime_inputs]
        immutable_paths += extra_sources
        before = {str(path.resolve()): file_pin(path) for path in immutable_paths}
        for path, snapshot in initial.items():
            if before[path] != snapshot:
                raise ValueError("Input changed after native command selection: " + path)
        report["archives"] = [file_pin(path)[0] for path in archives]
        report["allocator_object"] = before[str(allocator.resolve())][0]
        report["runtime"]["object_sha256"] = before[str(runtime_obj.resolve())][0]["sha256"]
        report["immutable_link_inputs"] = [row[0] for row in before.values()]
        for archive, name in zip(archives[:2], ("wtf", "bmalloc")):
            path = output / ("pre-" + name + "-members.json")
            item = archive_snapshot(work, archive, path, extra_objects=[allocator] if name == "wtf" else [])
            report["thin_archive_snapshots"]["pre"].append(item)
            save()
        for phase, argv in (("compile", command), ("link", link)):
            if args.diagnostic and shutil.disk_usage(work).free < FLOOR + 128 * 1024 ** 2:
                raise ValueError("Preserve the diagnostic link's 128 MiB remaining host margin")
            if phase == "link" and file_pin(obj) != before[str(obj.resolve())]:
                raise ValueError("Actual caller object changed before native link")
            step_receipt = {}
            try:
                bounded_run(argv, work, "wtf-native-" + output.name + "-" + phase,
                            step_receipt, budget, timeout=120)
            finally:
                steps = [item for item in step_receipt.get("steps", []) if item.get("argv") == argv]
                if steps:
                    report["commands"].append({"phase": phase, **steps[-1]})
                save()
            if phase == "compile":
                before[str(obj.resolve())] = file_pin(obj)
                report["caller_object"] = before[str(obj.resolve())][0]
                report["immutable_link_inputs"] = [row[0] for row in before.values()]
                save()
        for archive, name in zip(archives[:2], ("wtf", "bmalloc")):
            path = output / ("post-" + name + "-members.json")
            item = archive_snapshot(work, archive, path, extra_objects=[allocator] if name == "wtf" else [])
            report["thin_archive_snapshots"]["post"].append(item)
            save()
        for pre, post in zip(report["thin_archive_snapshots"]["pre"], report["thin_archive_snapshots"]["post"]):
            if immutable_snapshot(Path(pre["receipt"])) != immutable_snapshot(Path(post["receipt"])):
                raise ValueError("Thin member/source/compiler/config inputs changed across the link")
        for path, snapshot in before.items():
            if file_pin(Path(path)) != snapshot:
                raise ValueError("Actual native link input changed across compile/link: " + path)
        final_runtime_obj, final_runtime_binding = runtime_link_input(args.runtime)
        if final_runtime_obj != runtime_obj or final_runtime_binding != runtime_binding:
            raise ValueError("Validated paired runtime changed across the native link")
        report["link_provenance_passed"] = True
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
        if binary.is_file():
            report["binary"] = {"path": str(binary), "sha256": digest(binary),
                                "static_gate_passed": False, "provenance_gate_passed": False}
        save()
        raise
    report["binary"] = audit(binary, baseline)
    if args.diagnostic:
        nm = shutil.which("i686-w64-mingw32-nm")
        objdump = shutil.which("i686-w64-mingw32-objdump")
        if not nm or not objdump:
            raise ValueError("Existing exact COFF diagnostic inspection tools required")
        names = subprocess.run([nm, "-n", str(binary)], check=True, capture_output=True,
                               text=True, timeout=30).stdout
        if not re.search(r"^[0-9a-f]+ T ___wrap_abort$", names, re.M):
            raise ValueError("The x86 COFF abort wrapper is not linked")
        rows = []
        for name in ("___wrap_abort", "___cxa_thread_atexit", "___emutls_get_address"):
            argv = [objdump, "-d", "--disassemble=" + name, str(binary)]
            inspected = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30).stdout
            log = output / ("diagnostic-" + name + ".txt")
            log.write_text(inspected)
            rows.append({"symbol": name, "argv": argv, "log": str(log), "log_sha256": digest(log),
                         "wrapped_calls": len(re.findall(r"call\s+[^\n]+<___wrap_abort>", inspected)),
                         "forward_real_abort": bool(re.search(r"(?:call|jmp)\s+[^\n]+<_abort>", inspected))})
        if not rows[0]["forward_real_abort"] or not all(row["wrapped_calls"] for row in rows[1:]):
            raise ValueError("Actual COFF disassembly does not establish wrapper routing and unchanged real abort")
        report["abort_wrapper_audit"] = {"passed": True, "symbols": rows,
            "tools": [file_pin(Path(nm))[0], file_pin(Path(objdump))[0]],
            "coverage": "Observed direct genuine cxa/emutls abort sites; no system DLL internal abort claim"}
    report["binary"]["path"] = str(binary)
    report["binary"]["provenance_gate_passed"] = True
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"receipt": str(receipt), "sha256": digest(receipt),
                      "binary_sha256": digest(binary), "static_gate_passed": report["binary"]["static_gate_passed"]}))
    if not report["binary"]["static_gate_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
