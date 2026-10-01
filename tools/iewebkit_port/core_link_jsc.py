#!/usr/bin/env python3
"""Link the genuine JavaScriptCore C API GUI caller and audit its imports.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Completes no engine provider and starts no guest or network operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import stat
import subprocess
import sys
import types

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))


def load_tool_bundle():
    # Pin the bootstrap before executing it, then load every helper from that
    # bundle's already captured bytes. A cached Python import is not provenance.
    path = HERE / "core_tool_snapshot.py"
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 1024 ** 2:
            raise ValueError("Snapshot bootstrap must be a bounded regular file")
        data = b""
        while len(data) <= 1024 ** 2:
            block = os.read(descriptor, 65536)
            if not block:
                break
            data += block
        after = os.fstat(descriptor)
        named = path.stat(follow_symlinks=False)
    finally:
        os.close(descriptor)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_size,
                             item.st_mtime_ns, item.st_ctime_ns)
    if (len(data) != before.st_size or identity(before) != identity(after)
            or identity(named) != identity(after)):
        raise ValueError("Snapshot bootstrap changed while being captured")
    module = types.ModuleType("_jsc_snapshot_bootstrap")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    bundle = module.engine_bundle(builder=True, driver=True)
    if bundle.snapshots["core_tool_snapshot"][0] != data:
        raise ValueError("Snapshot bootstrap changed before helper loading")
    return bundle


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def profile_digest(profile):
    return hashlib.sha256(json.dumps(profile, sort_keys=True,
        separators=(",", ":")).encode("ascii")).hexdigest()


DEPENDENCY_TARGET = "83bd-jsc-caller-inputs"


def caller_dependency_command(command):
    if command.count("-o") != 1 or command.count("-c") != 1:
        raise ValueError("Caller dependency query requires one genuine compile source/output")
    if any(token.startswith("-M") for token in command):
        raise ValueError("Preserve caller input: unsupported existing dependency output options")
    output_index = command.index("-o")
    if output_index + 1 == len(command):
        raise ValueError("Missing caller compiler output operand")
    result = [token for index, token in enumerate(command)
              if index not in (output_index, output_index + 1) and token != "-c"]
    return [*result, "-M", "-MT", DEPENDENCY_TARGET]


def caller_dependency_paths(text, cwd):
    prefix = DEPENDENCY_TARGET + ":"
    if (not isinstance(text, str) or len(text.encode()) > 2 * 1024 ** 2
            or not text.startswith(prefix) or not text.endswith("\n")
            or any(char in text for char in ("\x00", "$", "\x1b"))):
        raise ValueError("Require bounded complete genuine caller compiler dependencies")
    words = shlex.split(text[len(prefix):].replace("\\\n", " "))
    if not words or len(words) > 20000:
        raise ValueError("Caller compiler dependency set is empty or oversized")
    paths = [Path(os.path.abspath(Path(word) if Path(word).is_absolute() else Path(cwd) / word))
             for word in words]
    return list(dict.fromkeys(paths))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--iewebkit-repo", type=Path, required=True)
    args = parser.parse_args()
    tools = load_tool_bundle()
    builder = tools.modules["core_build"]
    check_space, run, runtime_link_input = builder.check_space, builder.run, builder.runtime_link_input
    inspector = tools.modules["core_archive_receipt"]
    archive_receipt, file_pin = inspector.create, inspector.file_pin
    private_path, FLOOR = inspector.private_path, inspector.FLOOR
    validate_build_profile = tools.modules["core_jsc_profile_gate"].validate_build_profile
    allocator_input = tools.modules["core_link_wtf"].allocator_input
    immutable_snapshot = tools.modules["core_link_wtf"].immutable_snapshot
    work = args.work.resolve()
    build = work / "build-jsc-win9x"
    output = private_path(args.output, work, exists=False)
    if output.exists() or not output.is_relative_to(work) or output.is_relative_to(build):
        raise ValueError("Preserve existing engine output; use a new private caller directory")
    initial = {}

    def observe(path):
        path = Path(path)
        # Distinct declared aliases may resolve to the same installed header or
        # driver. Bind both paths instead of treating alias spelling as drift.
        key = os.path.abspath(path)
        snapshot = file_pin(path)
        if key in initial and initial[key] != snapshot:
            raise ValueError("JSC caller input changed during command selection: " + str(path))
        initial[key] = snapshot
        return snapshot[0]

    def read_pinned_json(path):
        before = observe(path)
        value = json.loads(Path(path).read_text())
        if observe(path) != before:
            raise ValueError("JSC caller JSON changed while being read: " + str(path))
        return value

    core = read_pinned_json(work / "core-build.json")
    if not core.get("jsc"):
        raise ValueError("Complete and bind the actual upstream jsc executable build first")
    actual_jsc = private_path(Path(core["jsc"]["path"]), work)
    if actual_jsc != build / "bin/jsc.exe" or observe(actual_jsc)["sha256"] != core["jsc"]["sha256"]:
        raise ValueError("Completed upstream JSC executable changed after its build receipt")
    budget = core["disk_budget_bytes"]
    check_space(work, budget)
    if shutil.disk_usage(work).free < FLOOR + 128 * 1024 ** 2:
        raise ValueError("Preserve the 20 GiB host floor plus the bounded real JSC link budget")
    runtime_obj, runtime = runtime_link_input(args.runtime)
    if runtime != core.get("runtime_link_input"):
        raise ValueError("Use the same genuine runtime as the completed JSC source build")
    profile = core.get("jsc_build_profile")
    if (not profile or not profile.get("profile_gate_passed")
            or core["jsc"].get("build_profile_sha256") != profile_digest(profile)
            or core["jsc"].get("runtime_receipt_sha256") != runtime["receipt_sha256"]):
        raise ValueError("The completed JSC executable is not bound to this actual configured profile/runtime")
    source_root = private_path(Path(profile["source"]), work)
    validate_build_profile(work, source_root, args.iewebkit_repo, runtime_obj, expected=profile)
    source = HERE / "core_jsc_native.cpp"
    compile_database = build / "compile_commands.json"
    for path in (source, Path(__file__), HERE / "core_build.py", HERE / "core_archive_receipt.py",
                 HERE / "core_jsc_profile_gate.py", HERE / "core_link_wtf.py",
                 HERE.parent / "iewebkit_build_win98.py", build / "cmakeconfig.h", build / "CMakeCache.txt"):
        observe(path)
    for row in tools.inputs:
        pin = observe(Path(row["path"]))
        if pin["sha256"] != row["sha256"] or pin["bytes"] != row["bytes"]:
            raise ValueError("An executing helper differs from its loaded source snapshot")
    entries = read_pinned_json(compile_database)
    baseline = read_pinned_json(args.baseline)
    candidates = [item for item in entries if Path(item["file"]).resolve() == source_root / "Source/JavaScriptCore/jsc.cpp"]
    if len(candidates) != 1:
        raise ValueError("The genuine upstream JSC caller compile command is ambiguous")
    entry = candidates[0]
    command = entry.get("arguments") or shlex.split(entry["command"])
    if command.count("-o") != 1 or command.count("-c") != 1:
        raise ValueError("The genuine JSC compile command has ambiguous source/output operands")
    obj = output / "JSCNAT.o"
    command[command.index("-o") + 1] = str(obj)
    command[command.index("-c") + 1] = str(source)
    dependency_command = caller_dependency_command(command)
    dependency_file = output / "JSCNAT.d"
    command = [*command, "-MD", "-MF", str(dependency_file), "-MT", DEPENDENCY_TARGET]
    archives = [build / "lib/libJavaScriptCore.a", build / "lib/libWTF.a", build / "lib/libbmalloc.a"]
    allocator = build / "Source/bmalloc/mimalloc/mimalloc/CMakeFiles/mimalloc-obj.dir/src/static.c.obj"
    allocator_pin = read_pinned_json(HERE / "core_allocator_pin.json")
    allocator_binding = allocator_input(work, build, allocator, entries, allocator_pin)
    for row in [*allocator_binding["source_pins"], allocator_binding["patch"]]:
        if observe(Path(row["path"])) != row:
            raise ValueError("The actual allocator source or patch changed after its profile gate")
    icu = work / "icu-work/prefix-x86-win9x/lib"
    archives += [icu / name for name in ("libsicuin.a", "libsicuuc.a", "libsicudt.a")]
    for path in [*archives, allocator]:
        if not path.is_file():
            raise FileNotFoundError("Preserve missing real engine dependency: " + str(path))
    runtime_inputs = runtime.get("input_pins")
    if not isinstance(runtime_inputs, list) or not runtime_inputs:
        raise ValueError("The paired runtime is missing its complete immutable compiler/source input pins")
    for row in runtime_inputs:
        if observe(Path(row["path"]))["sha256"] != row["sha256"]:
            raise ValueError("An actual paired-runtime input changed before JSC caller link")
    for row in profile["inputs"]:
        if observe(Path(row["path"])) != row:
            raise ValueError("The configured actual JSC profile changed before caller link")
    for path in [allocator, runtime_obj, *archives]:
        observe(path)
    binary = output / "JSCNAT.EXE"
    link = [command[0], "-mwindows", "-static", "-static-libgcc", "-static-libstdc++", "-Wl,--gc-sections",
            "-Wl,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0",
            str(obj), str(allocator), str(runtime_obj), "-Wl,--start-group", *map(str, archives), "-Wl,--end-group",
            "-ldbghelp", "-lshlwapi", "-lwinmm", "-latomic", "-lws2_32", "-ladvapi32", "-luser32", "-lole32", "-luuid",
            "-o", str(binary)]
    process_cwd = Path.cwd().resolve(strict=True)
    driver_guard = tools.modules["core_link_driver_inputs"]
    driver_selection = driver_guard.select_link_inputs(link, cwd=process_cwd)
    traced_link = driver_guard.traced_link_argv(link, cwd=process_cwd)
    for row in driver_selection["input_pins"]:
        if observe(Path(row["path"])) != row:
            raise ValueError("An actual implicitly selected CRT/runtime/linker input changed")
    report = {"schema": "iewebkit-genuine-jsc-c-api-gui-link-v2", "source": str(source),
              "source_sha256": initial[str(source.resolve())][0]["sha256"],
              "configuration_sha256": initial[str((build / "cmakeconfig.h").resolve())][0]["sha256"],
              "compile_database_sha256": initial[str(compile_database.resolve())][0]["sha256"],
              "core_build_receipt_sha256": initial[str((work / "core-build.json").resolve())][0]["sha256"],
              "actual_jsc": core["jsc"], "jsc_build_profile": profile,
              "loaded_tool_inputs": tools.inputs,
              "archives": [file_pin(path)[0] for path in archives],
              "allocator": initial[str(allocator.resolve())][0], "allocator_profile": allocator_binding,
              "runtime": runtime, "baseline": initial[str(args.baseline.resolve())][0],
              "implicit_driver_selection": driver_selection,
              "native_execution": "NOT-VERIFIED", "engine_provider": False, "document_rendering": False,
              "link_provenance_passed": False, "member_binding_gate": "FAIL"}
    receipt = output / "JSCNAT.receipt.json"
    report["thin_member_bindings"] = []
    # Progress JSON is mutable; the completed executable and effective profile
    # remain immutable inputs. Do not compare a progress-only receipt rewrite.
    initial.pop(str((work / "core-build.json").resolve()))
    output.mkdir(parents=True, mode=0o700)

    def save():
        receipt.write_text(json.dumps(report, indent=2) + "\n")

    try:
        for path, snapshot in initial.items():
            if file_pin(Path(path)) != snapshot:
                raise ValueError("Actual JSC caller input changed after command selection: " + path)
        report["immutable_link_inputs"] = [snapshot[0] for snapshot in initial.values()]
        for index, archive in enumerate(archives[:3]):
            snapshot = archive_receipt(work, archive, output / ("pre-members-" + str(index) + ".json"),
                                       extra_objects=[allocator] if index == 1 else [])
            report["thin_member_bindings"].append({"pre": snapshot})
            save()
        dependency_step = {}
        try:
            run(dependency_command, work, "jsc-native-" + output.name + "-dependencies",
                dependency_step, budget, timeout=120, cwd=process_cwd)
        finally:
            matching = [item for item in dependency_step.get("steps", []) if item.get("argv") == dependency_command]
            if matching:
                report.setdefault("steps", []).append({"phase": "dependencies", **matching[-1]})
            save()
        if not matching or matching[-1]["returncode"] != 0:
            raise ValueError("Missing successful genuine caller dependency query receipt")
        dependency_log = Path(matching[-1]["log"])
        dependency_log_pin = file_pin(dependency_log)
        if dependency_log_pin[0]["sha256"] != matching[-1]["log_sha256"]:
            raise ValueError("The genuine caller dependency query log changed")
        dependency_paths = caller_dependency_paths(dependency_log.read_text(), process_cwd)
        if file_pin(dependency_log) != dependency_log_pin or source not in dependency_paths:
            raise ValueError("The complete genuine caller dependency query is unbound")
        caller_inputs = {os.path.abspath(path): file_pin(path) for path in dependency_paths}
        for path in dependency_paths:
            observe(path)
        report["caller_compiler_inputs"] = [snapshot[0] for snapshot in caller_inputs.values()]
        report["immutable_link_inputs"] = [snapshot[0] for snapshot in initial.values()]
        save()
        # The bounded monitor also protects this caller's real compiler/linker.
        for phase, argv in (("compile", command), ("link", traced_link)):
            for path, pin in caller_inputs.items():
                if file_pin(Path(path)) != pin:
                    raise ValueError("An actual caller source/header changed before " + phase)
            if phase == "link" and file_pin(obj) != initial[str(obj.resolve())]:
                raise ValueError("The genuine caller object changed before its actual link")
            step_receipt = {}
            try:
                run(argv, work, "jsc-native-" + output.name + "-" + phase,
                    step_receipt, budget, timeout=180, cwd=process_cwd)
            finally:
                matching = [item for item in step_receipt.get("steps", []) if item.get("argv") == argv]
                if matching:
                    report.setdefault("steps", []).append({"phase": phase, **matching[-1]})
                save()
            if phase == "compile":
                compiled_dependencies = caller_dependency_paths(dependency_file.read_text(), process_cwd)
                if set(compiled_dependencies) != set(dependency_paths):
                    raise ValueError("The actual caller compile used a different source/header dependency set")
                report["caller_compiler_dependency_file"] = observe(dependency_file)
                report["caller_object"] = observe(obj)
                report["immutable_link_inputs"] = [snapshot[0] for snapshot in initial.values()]
                save()
            elif file_pin(obj) != initial[str(obj.resolve())]:
                raise ValueError("The genuine caller object changed during its actual link")
            for path, pin in caller_inputs.items():
                if file_pin(Path(path)) != pin:
                    raise ValueError("An actual caller source/header changed during " + phase)
        linked = [step for step in report["steps"] if step["phase"] == "link"]
        if len(linked) != 1 or linked[0]["returncode"] != 0:
            raise ValueError("Missing successful actual traced JSC link receipt")
        log_path = Path(linked[0]["log"])
        log_before = file_pin(log_path)
        if log_before[0]["sha256"] != linked[0]["log_sha256"]:
            raise ValueError("The actual linker trace changed after its process receipt")
        member_rows = {str(archives[index]): json.loads(Path(binding["pre"]["receipt"]).read_text())["members"]
                       for index, binding in enumerate(report["thin_member_bindings"])}
        report["implicit_link_trace"] = driver_guard.validate_link_trace(
            driver_selection, log_path.read_bytes(), thin_members=member_rows)
        if file_pin(log_path) != log_before:
            raise ValueError("The actual linker trace changed while being checked")
        driver_guard.select_link_inputs(traced_link, cwd=process_cwd, expected=driver_selection)
        for index, archive in enumerate(archives[:3]):
            snapshot = archive_receipt(work, archive, output / ("post-members-" + str(index) + ".json"),
                                       extra_objects=[allocator] if index == 1 else [])
            report["thin_member_bindings"][index]["post"] = snapshot
            save()
        for binding in report["thin_member_bindings"]:
            if immutable_snapshot(Path(binding["pre"]["receipt"])) != immutable_snapshot(Path(binding["post"]["receipt"])):
                raise ValueError("Actual JSC thin member/source/compiler/config inputs changed across link")
        for path, snapshot in initial.items():
            if file_pin(Path(path)) != snapshot:
                raise ValueError("Actual JSC caller input changed across compile/link: " + path)
        final_runtime_obj, final_runtime = runtime_link_input(args.runtime)
        if final_runtime_obj != runtime_obj or final_runtime != runtime:
            raise ValueError("The complete genuine paired runtime changed across JSC caller link")
        validate_build_profile(work, source_root, args.iewebkit_repo, runtime_obj, expected=profile)
        tools.verify()
        report["member_binding_gate"] = "PASS"
        report["link_provenance_passed"] = True
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as error:
        report["failure"] = str(error)
        if binary.is_file():
            report["binary"] = {"path": str(binary), "sha256": digest(binary),
                                "static_gate_passed": False, "provenance_gate_passed": False}
        save()
        raise
    report["binary"] = tools.modules["iewebkit_build_win98"].audit(binary, baseline)
    tools.verify()
    report["binary"]["path"] = str(binary)
    report["binary"]["provenance_gate_passed"] = True
    report["binary"]["requires_gui_subsystem"] = report["binary"]["pe"]["subsystem"] == 2
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"receipt": str(receipt), "sha256": digest(receipt),
                      "binary_sha256": digest(binary), "bytes": binary.stat().st_size,
                      "static_gate_passed": report["binary"]["static_gate_passed"]}))
    if not report["binary"]["static_gate_passed"] or not report["binary"]["requires_gui_subsystem"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
