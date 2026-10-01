#!/usr/bin/env python3
"""Read-only binding of the actual configured Win9x JSC build profile.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
No compiler, generator, repository script, or guest is executed here.
"""
import hashlib
import json
from pathlib import Path
import re
import shlex

from core_archive_receipt import file_pin, private_path


HERE = Path(__file__).resolve().parent
LINK_PROFILE = (
    "-static", "-static-libgcc", "-static-libstdc++", "-Wl,--gc-sections",
    "-Wl,--major-os-version,4,--minor-os-version,0,--major-subsystem-version,4,--minor-subsystem-version,0",
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _cache_values(text):
    values = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([^:#/][^:]*)\:[^=]+=(.*)", line)
        if not match:
            continue
        if match[1] in values:
            raise ValueError("Duplicate actual CMake cache key: " + match[1])
        values[match[1]] = match[2]
    return values


def _stanza(text, prefix):
    lines = text.replace("$\n", "").splitlines()
    matches = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(matches) != 1:
        raise ValueError("Actual Ninja stanza is absent or ambiguous: " + prefix)
    index = matches[0]
    fields = {}
    for line in lines[index + 1:]:
        if not line.startswith("  "):
            break
        match = re.fullmatch(r"  ([A-Za-z_][A-Za-z_0-9]*) = (.*)", line)
        if not match or match[1] in fields:
            raise ValueError("Unsupported or duplicate actual Ninja stanza field")
        fields[match[1]] = match[2]
    return lines[index], fields


def _compile_entry(entries, build, source_file, output):
    matches = []
    for entry in entries:
        directory = Path(entry["directory"]).resolve()
        actual = Path(entry["file"])
        if not actual.is_absolute():
            actual = directory / actual
        if actual.resolve() != source_file:
            continue
        argv = entry.get("arguments") or shlex.split(entry["command"])
        if argv.count("-o") != 1 or argv.count("-c") != 1:
            raise ValueError("Actual JSC command has ambiguous source or output")
        emitted = Path(argv[argv.index("-o") + 1])
        if not emitted.is_absolute():
            emitted = directory / emitted
        selected = Path(argv[argv.index("-c") + 1])
        if not selected.is_absolute():
            selected = directory / selected
        if directory != build or emitted.resolve() != output or selected.resolve() != source_file:
            raise ValueError("Actual JSC command selects another source, directory, or output")
        matches.append(argv)
    if len(matches) != 1:
        raise ValueError("Actual JSC compile command is absent or ambiguous")
    return matches[0]


def validate_build_profile(work, source, repo, runtime_object, *, expected=None):
    """Return a stable profile at configure; reject drift before/after JSC.

    The caller separately validates the genuine paired runtime and all of its
    compiler inputs with core_build.runtime_link_input. This function binds its
    one combined object to the actual configured dependency and link command.
    Store the returned dict as core-build.json's jsc_build_profile and pass that
    same dict as expected before and after the actual Ninja jsc build.
    """
    work = Path(work).resolve(strict=True)
    source = private_path(Path(source), work)
    build = private_path(work / "build-jsc-win9x", work)
    runtime_object = private_path(Path(runtime_object), work)
    repo = Path(repo).resolve(strict=True)
    observed = {}

    def observe(path):
        path = Path(path)
        key = str(path.resolve(strict=True))
        if key not in observed:
            observed[key] = file_pin(path)
        return observed[key][0]

    def read_json(path):
        observe(path)
        return json.loads(Path(path).read_text())

    observe(Path(__file__))
    observe(HERE / "core_archive_receipt.py")
    allocator_helper = HERE / "core_link_wtf.py"
    observe(allocator_helper)
    # This helper only reads the actual source pins and compile database.
    from core_link_wtf import allocator_input

    config_paths = {name: build / name for name in (
        "cmakeconfig.h", "CMakeCache.txt", "compile_commands.json", "build.ninja", "CMakeFiles/rules.ninja",
    )}
    configs = {name: observe(path) for name, path in config_paths.items()}
    cache = _cache_values(config_paths["CMakeCache.txt"].read_text())
    hook_pin_path = HERE / "core_runtime_link_pin.json"
    hook_pin = read_json(hook_pin_path)
    hook = HERE / hook_pin["source"]
    if observe(hook)["sha256"] != hook_pin["sha256"]:
        raise ValueError("Actual deferred target hook differs from its reviewed source pin")
    toolchain = repo / "porting/mingw-me-toolchain.cmake"
    observe(toolchain)
    icu = work / "icu-work/prefix-x86-win9x"
    required_cache = {
        "CMAKE_HOME_DIRECTORY": str(source), "CMAKE_TOOLCHAIN_FILE": str(toolchain),
        "CMAKE_PROJECT_INCLUDE": str(hook), "IEWEBKIT_WIN9X_RUNTIME_OBJECT": str(runtime_object),
        "CMAKE_GENERATOR": "Ninja", "CMAKE_BUILD_TYPE": "MinSizeRel",
        "CMAKE_DISABLE_PRECOMPILE_HEADERS": "ON", "PORT": "JSCOnly", "IEWEBKIT_WIN9X": "ON",
        "EVENT_LOOP_TYPE": "Windows", "ENABLE_C_LOOP": "ON", "ENABLE_JIT": "OFF",
        "ENABLE_WEBASSEMBLY": "OFF", "ENABLE_REMOTE_INSPECTOR": "OFF", "ENABLE_STATIC_JSC": "ON",
        "USE_SYSTEM_MALLOC": "OFF", "USE_MIMALLOC": "ON", "USE_THIN_ARCHIVES": "ON",
        "ICU_INCLUDE_DIR": str(icu / "include"),
        "ICU_UC_LIBRARY_RELEASE": str(icu / "lib/libsicuuc.a"),
        "ICU_I18N_LIBRARY_RELEASE": str(icu / "lib/libsicuin.a"),
        "ICU_DATA_LIBRARY_RELEASE": str(icu / "lib/libsicudt.a"),
    }
    for name, value in required_cache.items():
        if cache.get(name) != value:
            raise ValueError("Actual JSC CMake profile differs: " + name)
    cached_link = shlex.split(cache.get("CMAKE_EXE_LINKER_FLAGS", ""))
    if cached_link != [str(runtime_object), *LINK_PROFILE]:
        raise ValueError("Actual CMake executable flags do not select the genuine upfront static runtime")
    required_macros = {
        "IEWEBKIT_WIN9X": 1, "USE_WINDOWS_EVENT_LOOP": 1, "USE_MIMALLOC": 1,
        "USE_SYSTEM_MALLOC": 0, "ENABLE_C_LOOP": 1, "ENABLE_JIT": 0,
        "ENABLE_DFG_JIT": 0, "ENABLE_FTL_JIT": 0, "ENABLE_WEBASSEMBLY": 0,
        "ENABLE_REMOTE_INSPECTOR": 0, "ENABLE_STATIC_JSC": 1,
    }
    tracked_macros = set(required_macros) | {"USE_GENERIC_EVENT_LOOP"}
    macros = {}
    for line in config_paths["cmakeconfig.h"].read_text().splitlines():
        match = re.fullmatch(r"#define ([A-Za-z_][A-Za-z_0-9]*) (.+)", line)
        if not match or match[1] not in tracked_macros:
            continue
        if match[2] not in ("0", "1"):
            raise ValueError("Unsupported actual generated profile feature value: " + match[1])
        value = int(match[2])
        if match[1] in macros and macros[match[1]] != value:
            raise ValueError("Conflicting actual generated profile feature definition: " + match[1])
        macros[match[1]] = value
    for name, value in required_macros.items():
        if macros.get(name) != value:
            raise ValueError("Actual generated JSC feature differs: " + name)
    if macros.get("USE_GENERIC_EVENT_LOOP", 0) != 0:
        raise ValueError("Actual JSC configuration combines incompatible RunLoop layouts")

    # Later source ports must explicitly continue the earlier before/after
    # chain. In particular, allocator prim.c supersedes the optional-API port.
    effective = {}
    composition = []
    for name in ("core_profile.json", "core_memory_pin.json", "core_statistics_pin.json",
                 "core_optional_api_pin.json", "core_allocator_pin.json"):
        pin = read_json(HERE / name)
        if pin["upstream_commit"] != "5220e80b97a253c60ed899361654142ab5021998":
            raise ValueError("Actual source port belongs to another WebKit upstream commit")
        if observe(HERE / pin["patch"])["sha256"] != pin["patch_sha256"]:
            raise ValueError("Actual source-port patch differs from its reviewed source pin")
        for row in pin["files"]:
            previous = effective.get(row["path"])
            if previous and previous["sha256"] != row["before_sha256"]:
                raise ValueError("Actual source-port override breaks the reviewed before/after chain")
            effective[row["path"]] = {"sha256": row["after_sha256"], "owner": name}
        for row in pin.get("new_files", []):
            if row["path"] in effective:
                raise ValueError("Actual source port repeats a new-file path")
            if observe(HERE / row["source"])["sha256"] != row["sha256"]:
                raise ValueError("Durable new backend header differs from its reviewed source pin")
            effective[row["path"]] = {"sha256": row["sha256"], "owner": name}
        composition.append(name)
    loop_pin = read_json(HERE / "source-pin.json")
    if loop_pin["upstream_commit"] != "5220e80b97a253c60ed899361654142ab5021998":
        raise ValueError("Actual RunLoop port belongs to another WebKit upstream commit")
    if observe(HERE / loop_pin["patch"])["sha256"] != loop_pin["patch_sha256"]:
        raise ValueError("Actual RunLoop patch differs from its reviewed source pin")
    effective[loop_pin["upstream_file"]] = {
        "sha256": loop_pin["modified_sha256"], "owner": "source-pin.json",
    }
    backend = source / loop_pin["upstream_file"]
    header = backend.with_name("RunLoopWin9x.h")
    if observe(header)["sha256"] != observe(HERE / loop_pin["new_header"])["sha256"]:
        raise ValueError("Actual RunLoop backend header differs from the durable native backend")
    for name, row in sorted(effective.items()):
        if observe(private_path(source / name, work))["sha256"] != row["sha256"]:
            raise ValueError("Actual effective source-port after pin differs: " + name)

    entries = read_json(config_paths["compile_commands.json"])
    allocator = build / "Source/bmalloc/mimalloc/mimalloc/CMakeFiles/mimalloc-obj.dir/src/static.c.obj"
    allocator_pin = read_json(HERE / "core_allocator_pin.json")
    allocator_binding = allocator_input(work, build, allocator, entries, allocator_pin)
    jsc_source = private_path(source / "Source/JavaScriptCore/jsc.cpp", work)
    jsc_output = build / "Source/JavaScriptCore/shell/CMakeFiles/jsc.dir/__/jsc.cpp.obj"
    jsc_argv = _compile_entry(entries, build, jsc_source, jsc_output)
    observe(jsc_source)
    observe(Path(jsc_argv[0]))
    observe(runtime_object)

    header_line, fields = _stanza(config_paths["build.ninja"].read_text(), "build bin/jsc.exe: ")
    tokens = shlex.split(header_line.split(": ", 1)[1])
    if any("$" in token for token in tokens) or "|@" in tokens:
        raise ValueError("Unsupported variable or validation syntax in the actual JSC dependency rule")
    rule_name = tokens[0]
    before_order_only = tokens[1:tokens.index("||")] if "||" in tokens else tokens[1:]
    runtime_dependencies = []
    for token in before_order_only:
        if token == "|":
            continue
        path = Path(token)
        if not path.is_absolute():
            path = build / path
        if path.resolve() == runtime_object:
            runtime_dependencies.append(token)
    if len(runtime_dependencies) != 1:
        raise ValueError("Actual JSC runtime object is not one real dependency before order-only inputs")
    linked_flags = shlex.split(fields.get("LINK_FLAGS", ""))
    if (linked_flags[:len(cached_link)] != cached_link
            or any(token != "-Wl,--gc-sections" for token in linked_flags[len(cached_link):])):
        raise ValueError("Actual JSC linker flags omit or override the upfront genuine static runtime")
    if fields.get("TARGET_FILE") != "bin/jsc.exe" or fields.get("PRE_LINK") != ":" or fields.get("POST_BUILD") != ":":
        raise ValueError("Actual JSC target or pre/post-link action differs from the configured profile")
    _, rule = _stanza(config_paths["CMakeFiles/rules.ninja"].read_text(), "rule " + rule_name)
    rule_command = shlex.split(rule.get("command", ""))
    for token in ("$LINK_FLAGS", "$in", "$LINK_LIBRARIES"):
        if rule_command.count(token) != 1:
            raise ValueError("Actual JSC linker rule has unsupported flag/input expansion")
    if (rule_command.index("$LINK_FLAGS") > rule_command.index("$in")
            or rule_command.index("$LINK_FLAGS") > rule_command.index("$LINK_LIBRARIES")
            or jsc_argv[0] not in rule_command):
        raise ValueError("Actual JSC compiler rule does not link the genuine runtime before engine archives")
    libraries = shlex.split(fields.get("LINK_LIBRARIES", ""))
    for archive in ("lib/libJavaScriptCore.a", "lib/libWTF.a", "lib/libbmalloc.a"):
        if libraries.count(archive) != 1:
            raise ValueError("Actual JSC link command omits or duplicates a genuine engine archive")
    allocator_libraries = [token for token in libraries if not token.startswith("-")
                           and (build / token).resolve() == allocator.resolve()]
    if len(allocator_libraries) != 1:
        raise ValueError("Actual JSC link command omits or duplicates the standalone allocator object")
    for archive in ("libsicuuc.a", "libsicuin.a", "libsicudt.a"):
        path = icu / "lib" / archive
        observe(path)
        if libraries.count(str(path)) != 1:
            raise ValueError("Actual JSC link command omitted a genuine pinned ICU dependency")

    for path, before in observed.items():
        if file_pin(Path(path)) != before:
            raise ValueError("Actual JSC profile input changed during validation: " + path)
    result = {
        "schema": "iewebkit-actual-jsc-build-profile-v1", "work": str(work), "source": str(source),
        "configuration_sha256": configs["cmakeconfig.h"]["sha256"],
        "inputs": [observed[path][0] for path in sorted(observed)],
        "effective_source_ports": effective, "composition": composition,
        "allocator_profile": allocator_binding,
        "jsc_compile_argv_sha256": hashlib.sha256(_canonical(jsc_argv)).hexdigest(),
        "jsc_link": {"dependency_rule": header_line, "fields": fields, "command_rule": rule},
        "runtime_object": str(runtime_object), "profile_gate_passed": True,
        "guest_execution": "NOT-VERIFIED", "full_renderer": False,
    }
    if expected is not None and result != expected:
        raise ValueError("Actual configured JSC build profile changed; configure and bind it again")
    return result
