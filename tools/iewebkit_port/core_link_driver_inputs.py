#!/usr/bin/env python3
"""Bind the inputs implicitly selected by an existing static MinGW link driver.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT

Only read-only GCC -###/query and ld --verbose operations run here. There is no
link, temporary file, receipt write, download, or guest operation. This narrow
parser intentionally rejects response files, user specs/plugins/search paths,
dynamic links, and unknown driver/linker options. It does not bind the contents
of explicitly supplied engine objects/thin archives: their separate member and
source receipts remain mandatory.

Use select_link_inputs(original_link_argv, the_actual_process_cwd) before the
link; pin every input_pins row in the enclosing receipt; run traced_link_argv;
validate_link_trace on the successful link's entire merged stdout/stderr log;
then repeat select_link_inputs with expected=the_original_selection. A prediction
or a synthetic trace alone is not evidence that an actual link used these bytes.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
from collections.abc import Mapping, Sequence

from core_archive_receipt import file_pin

LIMIT = 2 * 1024 ** 2
LIBRARY_NAME = re.compile(r"[A-Za-z0-9_+.\-]+\Z")
VERSION_OPTIONS = {"--major-os-version", "--minor-os-version",
                   "--major-subsystem-version", "--minor-subsystem-version"}
SIMPLE_LINK_OPTIONS = {"--gc-sections", "--no-insert-timestamp",
                       "--start-group", "--end-group"}
SIMPLE_DRIVER_OPTIONS = {"-mwindows", "-mconsole", "-static", "-static-libgcc",
                         "-static-libstdc++"}


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(",", ":")).encode("ascii")).hexdigest()


def _environment_digest() -> str:
    # Bind the entire inherited environment without exposing credentials or
    # other unrelated environment values in a receipt or diagnostic.
    return _digest(sorted(os.environ.items()))


def _query(argv: Sequence[str], cwd: Path) -> tuple[str, str]:
    result = subprocess.run(list(argv), cwd=cwd, capture_output=True, timeout=30)
    if result.returncode or len(result.stdout) + len(result.stderr) > LIMIT:
        raise ValueError("bounded read-only link-driver query failed: " + shlex.join(argv))
    return result.stdout.decode("utf-8", errors="strict"), result.stderr.decode("utf-8", errors="strict")


def _single_query(driver: str, option: str, cwd: Path) -> str:
    stdout, stderr = _query([driver, option], cwd)
    if stderr or not stdout.endswith("\n") or len(stdout.splitlines()) != 1:
        raise ValueError("ambiguous link-driver query: " + option)
    return stdout.strip()


def _absolute(value: str, cwd: Path) -> str:
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError("ambiguous link input path")
    path = Path(value)
    return os.path.abspath(path if path.is_absolute() else cwd / path)


def _linker_tokens(tokens: Sequence[str], *, allow_trace=False) -> None:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in SIMPLE_LINK_OPTIONS:
            pass
        elif token in VERSION_OPTIONS:
            index += 1
            if index == len(tokens) or not re.fullmatch(r"[0-9]+", tokens[index]):
                raise ValueError("invalid explicit PE version operand")
        elif token == "-t" and allow_trace:
            pass
        else:
            raise ValueError("unsupported linker option: " + token)
        index += 1
    # Groups can span multiple -Wl arguments, so balance is checked separately
    # over the complete driver option stream in _driver_argv.


def _driver_argv(argv: Sequence[str], cwd: Path) -> tuple[list[str], list[str], str]:
    if not isinstance(argv, (list, tuple)) or not argv or not all(isinstance(x, str) for x in argv):
        raise ValueError("a concrete link argv is required")
    driver = shutil.which(argv[0])
    if not driver:
        raise ValueError("the existing MinGW link driver is missing")
    canonical, explicit, linker_tokens = [os.path.abspath(driver)], [], []
    output, trace_count, index = None, 0, 1
    while index < len(argv):
        token = argv[index]
        if not token or any(ord(c) < 32 for c in token) or "@" in token:
            raise ValueError("response files or ambiguous link operands are unsupported")
        if token in SIMPLE_DRIVER_OPTIONS:
            canonical.append(token)
        elif token == "-o":
            index += 1
            if output is not None or index == len(argv):
                raise ValueError("ambiguous link output")
            output = _absolute(argv[index], cwd)
            canonical += ["-o", output]
        elif token.startswith("-Wl,"):
            parts = token[4:].split(",")
            # A single dedicated trace option is the only ignored option;
            # response files, -L/-T/-plugin and all other syntax fail closed.
            if parts == ["-t"]:
                trace_count += 1
            else:
                _linker_tokens(parts)
                linker_tokens += parts
                canonical.append(token)
        elif token.startswith("-l") and LIBRARY_NAME.fullmatch(token[2:]):
            canonical.append(token)
        elif not token.startswith("-") and Path(token).suffix in (".o", ".obj", ".a"):
            path = _absolute(token, cwd)
            explicit.append(path)
            canonical.append(path)
        else:
            raise ValueError("unsupported link-driver option/input: " + token)
        index += 1
    if trace_count > 1 or output is None or not explicit or "-static" not in canonical:
        raise ValueError("one bounded static object/archive link with one output is required")
    depth = 0
    for token in linker_tokens:
        depth += (token == "--start-group") - (token == "--end-group")
        if depth < 0:
            raise ValueError("unbalanced linker archive group")
    if depth:
        raise ValueError("unbalanced linker archive group")
    return canonical, explicit, output


def traced_link_argv(argv: Sequence[str], cwd: Path | None = None) -> list[str]:
    """Return the validated original command with exactly one GNU input trace."""
    cwd = Path.cwd() if cwd is None else Path(cwd).resolve(strict=True)
    canonical, _, _ = _driver_argv(argv, cwd)
    return [*canonical, "-Wl,-t"]


def select_link_inputs(argv: Sequence[str], cwd: Path | None = None,
                       *, expected: Mapping | None = None) -> dict:
    """Predict and hash the real startup/runtime/import files selected by GCC.

    Existing explicit object/archive paths are recorded, but can be absent while
    preparing a future command. No explicit archive is expanded here. Repeating
    this function with expected detects changed byte/inode pins, environment,
    driver expansion, search resolution, specs, plugin, linker, or search script.
    """
    cwd = Path.cwd() if cwd is None else Path(cwd).resolve(strict=True)
    canonical, explicit, output = _driver_argv(argv, cwd)
    environment = _environment_digest()
    # Loader injection can introduce executable inputs outside this provenance
    # set. Nonempty overrides of GCC's executable/search roots are unsupported.
    for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "GCC_EXEC_PREFIX", "COMPILER_PATH", "LIBRARY_PATH"):
        if os.environ.get(name):
            raise ValueError("unsupported link-tool environment override: " + name)
    snapshots: dict[str, tuple] = {}

    def observe(value: str | Path) -> dict:
        path = Path(value)
        declared = _absolute(str(path), cwd)
        now = file_pin(Path(declared))
        if declared in snapshots and snapshots[declared] != now:
            raise ValueError("link-driver input changed during selection: " + declared)
        snapshots[declared] = now
        return now[0]

    observe(canonical[0])
    observe(Path(__file__))
    observe(Path(__file__).with_name("core_archive_receipt.py"))
    target = _single_query(canonical[0], "-dumpmachine", cwd)
    if target != "i686-w64-mingw32":
        raise ValueError("this guard supports only the actual i686 MinGW driver")
    stdout, stderr = _query([canonical[0], "-###", *canonical[1:]], cwd)
    if stdout:
        raise ValueError("unexpected stdout from the link-driver dry run")
    commands, specs = [], []
    built_in_specs = False
    wrapper = None
    for line in stderr.splitlines():
        if line == "Using built-in specs.":
            built_in_specs = True
        elif line.startswith("Reading specs from "):
            path = line.removeprefix("Reading specs from ")
            if not Path(path).is_absolute():
                raise ValueError("an implicit specs path is not absolute")
            specs.append(observe(path))
        elif line.startswith("COLLECT_LTO_WRAPPER="):
            wrapper = line.split("=", 1)[1]
        elif line.startswith(" "):
            command = shlex.split(line)
            if not command or Path(command[0]).name != "collect2":
                raise ValueError("the dry run selected an unexpected executable")
            commands.append(command)
    if len(commands) != 1 or not (built_in_specs or specs):
        raise ValueError("missing or ambiguous GCC collect2/specs selection")
    collect = commands[0]
    observe(collect[0])
    if not wrapper or not Path(wrapper).is_absolute():
        raise ValueError("the genuine LTO wrapper selection is missing")
    observe(wrapper)
    ld_name = _single_query(canonical[0], "-print-prog-name=ld", cwd)
    linker = shutil.which(ld_name) if not Path(ld_name).is_absolute() else ld_name
    if not linker:
        raise ValueError("the driver-selected real linker is missing")
    linker = _absolute(linker, cwd)
    observe(linker)
    effective_inputs, libraries, searches, normalized = [], [], [], [collect[0]]
    sysroot, emulation, plugin, index = None, None, None, 1
    seen_output, static_mode = False, False
    while index < len(collect):
        token = collect[index]
        if token == "-plugin":
            index += 1
            if plugin is not None or index == len(collect) or not Path(collect[index]).is_absolute():
                raise ValueError("ambiguous implicit linker plugin")
            plugin = collect[index]
            observe(plugin)
            normalized += [token, plugin]
        elif token.startswith("-plugin-opt="):
            value = token.removeprefix("-plugin-opt=")
            if value == wrapper:
                normalized.append(token)
            elif re.fullmatch(r"-fresolution=/[^\n]+/cc[A-Za-z0-9_]+\.res", value):
                # GCC generates this plugin output name, not an existing input.
                normalized.append("-plugin-opt=<driver-generated-resolution-output>")
            elif value.startswith("-pass-through=-l") and LIBRARY_NAME.fullmatch(value.removeprefix("-pass-through=-l")):
                normalized.append(token)
            else:
                raise ValueError("unsupported implicit plugin option: " + token)
        elif token.startswith("--sysroot="):
            if sysroot is not None or not Path(token.split("=", 1)[1]).is_absolute():
                raise ValueError("ambiguous implicit linker sysroot")
            sysroot = token.split("=", 1)[1]
            normalized.append(token)
        elif token in ("-m", "--subsystem", "-o", *VERSION_OPTIONS):
            index += 1
            if index == len(collect):
                raise ValueError("missing implicit linker operand")
            value = collect[index]
            if token == "-m":
                if emulation is not None or value != "i386pe":
                    raise ValueError("unsupported implicit linker emulation")
                emulation = value
            elif token == "--subsystem" and value not in ("windows", "console"):
                raise ValueError("unsupported implicit linker subsystem")
            elif token == "-o":
                if seen_output or _absolute(value, cwd) != output:
                    raise ValueError("the driver changed the planned link output")
                seen_output = True
            elif token in VERSION_OPTIONS and not re.fullmatch(r"[0-9]+", value):
                raise ValueError("invalid implicit PE version operand")
            normalized += [token, value]
        elif token == "-Bstatic":
            static_mode = True
            normalized.append(token)
        elif token.startswith("-L") and len(token) > 2:
            directory = token[2:]
            if not Path(directory).is_absolute():
                raise ValueError("a driver-generated search directory is not absolute")
            searches.append(directory)
            normalized.append(token)
        elif token.startswith("-l") and LIBRARY_NAME.fullmatch(token[2:]):
            if not static_mode:
                raise ValueError("dynamic implicit library selection is unsupported")
            libraries.append(token[2:])
            effective_inputs.append({"kind": "library", "name": token[2:]})
            normalized.append(token)
        elif token in SIMPLE_LINK_OPTIONS:
            normalized.append(token)
        elif not token.startswith("-") and Path(token).suffix in (".o", ".obj", ".a"):
            path = _absolute(token, cwd)
            effective_inputs.append({"kind": "explicit" if path in explicit else "startup", "path": path})
            normalized.append(path)
            if path not in explicit:
                observe(path)
        else:
            raise ValueError("unsupported driver-expanded linker option/input: " + token)
        index += 1
    if not seen_output or not sysroot or emulation != "i386pe" or not plugin or not searches or not libraries:
        raise ValueError("incomplete real static MinGW driver expansion")
    expanded_explicit = [row["path"] for row in effective_inputs if row["kind"] == "explicit"]
    if expanded_explicit != explicit:
        raise ValueError("the driver changed the planned explicit object/archive order")
    script, diagnostic = _query([linker, "-m", emulation, "--sysroot=" + sysroot, "--verbose"], cwd)
    if diagnostic or "using internal linker script:" not in script:
        raise ValueError("unsupported external/default linker-script selection")
    default_searches = re.findall(r'SEARCH_DIR\("([^"\n]+)"\)', script)
    if not default_searches:
        raise ValueError("the actual linker default search paths are missing")
    for directory in default_searches:
        directory = sysroot.rstrip("/") + directory[1:] if directory.startswith("=") else directory
        if not Path(directory).is_absolute():
            raise ValueError("unsupported default linker search path")
        searches.append(directory)
    resolutions = {}
    for name in dict.fromkeys(libraries):
        filename = "lib" + name + ".a"
        candidates = [Path(directory) / filename for directory in searches]
        selected = next((path for path in candidates if path.is_file()), None)
        if selected is None:
            raise ValueError("a real static library cannot be resolved: " + name)
        # Cross-check the linker search against the driver's own file query.
        # Other PE filename conventions are intentionally unsupported here.
        driver_selection = _single_query(canonical[0], "-print-file-name=" + filename, cwd)
        if driver_selection == filename or Path(driver_selection).resolve(strict=True) != selected.resolve(strict=True):
            raise ValueError("GCC/linker static-library resolution is ambiguous: " + name)
        pin = observe(selected)
        with selected.open("rb") as stream:
            if stream.read(8) != b"!<arch>\n":
                raise ValueError("implicit runtime/import input is not a regular GNU archive: " + str(selected))
        observe(selected)
        resolutions[name] = {"name": name, "path": str(selected), "resolved_path": pin["resolved_path"],
                             "driver_print_file_name": driver_selection, "sha256": pin["sha256"]}
    for row in effective_inputs:
        if row["kind"] == "library":
            row.update(resolutions[row["name"]])
    dumpspecs, diagnostic = _query([canonical[0], "-dumpspecs"], cwd)
    if diagnostic or not dumpspecs.startswith("*asm:"):
        raise ValueError("the genuine GCC specs query is incomplete")
    if _environment_digest() != environment:
        raise ValueError("the link-driver environment changed during selection")
    for path, before in snapshots.items():
        if file_pin(Path(path)) != before:
            raise ValueError("link-driver input changed during selection: " + path)
    report = {"schema": "iewebkit-static-mingw-driver-inputs-v1", "selection_gate_passed": True,
              "actual_link_trace_verified": False, "argv": canonical, "cwd": str(cwd),
              "environment_sha256": environment, "target": target, "linker": linker,
              "collect2_argv": normalized, "built_in_specs": built_in_specs, "spec_files": specs,
              "gcc_specs_sha256": hashlib.sha256(dumpspecs.encode()).hexdigest(),
              "linker_default_script_sha256": hashlib.sha256(script.encode()).hexdigest(),
              "search_directories": searches, "selected_inputs": effective_inputs,
              "library_resolutions": list(resolutions.values()),
              "input_pins": [row[0] for row in snapshots.values()],
              "input_states": [{"path": path, "identity": list(row[1])} for path, row in snapshots.items()]}
    if expected is not None and report != dict(expected):
        raise ValueError("the actual implicit linker selection changed across link")
    return report


def validate_link_trace(selection: Mapping, trace: str | bytes, *,
                        thin_members: Mapping[str, Sequence[Mapping]] | None = None) -> dict:
    """Validate a successful real -Wl,-t log against the predicted input set.

    Unknown log lines are rejected, including linker warnings; an enclosing caller
    must already check the actual link return code. GNU thin-member lines, when
    emitted, need the parent's genuine pre-link member inventories. Repetition
    due to group rescans is allowed; every predicted top-level input is required.
    """
    if selection.get("schema") != "iewebkit-static-mingw-driver-inputs-v1" or not selection.get("selection_gate_passed"):
        raise ValueError("a complete actual link-driver selection is required")
    if isinstance(trace, bytes):
        trace = trace.decode("utf-8", errors="strict")
    if not isinstance(trace, str) or not trace.endswith("\n") or len(trace.encode()) > LIMIT:
        raise ValueError("a bounded complete actual linker input trace is required")
    cwd = Path(selection["cwd"])
    expected = {}
    for row in selection["selected_inputs"]:
        path = _absolute(row["path"], cwd)
        expected[path] = str(Path(path).resolve(strict=True))
    resolved_expected = set(expected.values())
    member_paths = {}
    for archive, rows in (thin_members or {}).items():
        archive_path = str(Path(_absolute(archive, cwd)).resolve(strict=True))
        if archive_path not in resolved_expected:
            raise ValueError("thin member inventory belongs to an unselected archive")
        for row in rows:
            pin, _ = file_pin(Path(row["path"]))
            if pin["sha256"] != row["sha256"]:
                raise ValueError("a genuine thin member changed before trace validation")
            member_paths[pin["resolved_path"]] = archive_path
    seen, members, lines = set(), set(), 0
    for line in trace.splitlines():
        if not line:
            continue
        lines += 1
        # GNU archive rescans can surround the archive path with parentheses.
        value = line[1:-1] if line.startswith("(") and line.endswith(")") else line
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("unknown/ambiguous actual linker trace line: " + line[:200])
        resolved = str(path.resolve(strict=True))
        if resolved in resolved_expected:
            seen.add(resolved)
        elif resolved in member_paths:
            members.add(resolved)
        else:
            raise ValueError("actual linker used an unpredicted input: " + line[:200])
    missing = sorted(resolved_expected - seen)
    if missing:
        raise ValueError("actual linker trace omits predicted inputs: " + ", ".join(missing[:5]))
    # Bind all implicit files and identities again after the observed trace.
    states = {row["path"]: row["identity"] for row in selection["input_states"]}
    for row in selection["input_pins"]:
        now, identity = file_pin(Path(row["path"]))
        if now != row or list(identity) != states[row["path"]]:
            raise ValueError("implicit link input changed across the actual trace: " + row["path"])
    return {"actual_link_trace_verified": True, "trace_sha256": hashlib.sha256(trace.encode()).hexdigest(),
            "trace_bytes": len(trace.encode()), "trace_lines": lines,
            "unique_top_level_inputs": len(seen), "unique_thin_members": len(members),
            "selection_sha256": _digest(selection)}
