"""Stage an exact-preimage patch/caller only inside this disjoint source lane.

No canonical source is modified, compiler/engine/guest is started or download
performed. Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = ROOT / "tools/iewebkit_port/core_jsc_native.cpp"
PREIMAGE_SHA256 = "1d38eab54d9bd6f166d6811188087170a27c4c62118a6913fe0cac7657d630e0"
MAX_SOURCE_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 256 * 1024


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("Patch anchor is absent or ambiguous")
    return text.replace(before, after, 1)


def prepare():
    if SOURCE.is_symlink() or not SOURCE.is_file():
        raise ValueError("Require the exact regular canonical caller preimage")
    with SOURCE.open("rb") as stream:
        raw = stream.read(MAX_SOURCE_BYTES + 1)
    if len(raw) > MAX_SOURCE_BYTES or hashlib.sha256(raw).hexdigest() != PREIMAGE_SHA256:
        raise ValueError("Canonical JSC caller preimage changed; review a new patch instead")
    text = raw.decode("utf-8")
    text = once(text, "#include <JavaScriptCore/JavaScript.h>\n",
                '#include <JavaScriptCore/JavaScript.h>\n#include "wasm_cases.h"\n')
    text = once(text, '"C:\\\\GOPLAB\\\\JSCNAT.LOG"', '"C:\\\\GOPLAB\\\\WASM83BD.LOG"')
    text = once(text, '"actual-pinned-JavaScriptCore-C-API"',
                '"actual-pinned-JavaScriptCore-Wasm-subset"')
    text = once(text, '    if (!line("stage", "before-JSContextGroupCreate")) {',
                '    logs = flag("build.c-loop", ENABLE_C_LOOP) && logs;\n'
                '    logs = flag("build.jit", ENABLE_JIT) && logs;\n'
                '    logs = flag("build.webassembly", ENABLE_WEBASSEMBLY) && logs;\n'
                '    logs = flag("full-browser-pass", false) && logs;\n'
                '    if (!logs || !line("stage", "before-JSContextGroupCreate")) {')
    text = once(text, '    // Exercise genuine C API collection and release, without claiming that a',
                '    bool wasmSubset = ENABLE_WEBASSEMBLY;\n'
                '    for (const auto& test : wasm83bdCases) {\n'
                '        exception = nullptr;\n'
                '        if (!line("stage", test.name)) {\n'
                '            logs = false;\n'
                '            wasmSubset = false;\n'
                '            break;\n'
                '        }\n'
                '        value = evaluate(context, test.script, &exception);\n'
                '        bool passed = value && !exception && JSValueIsBoolean(context, value)\n'
                '            && JSValueToBoolean(context, value);\n'
                '        logs = flag(test.name, passed) && logs;\n'
                '        wasmSubset = passed && wasmSubset;\n'
                '    }\n'
                '    logs = flag("wasm.subset", wasmSubset) && logs;\n'
                '    // Exercise genuine C API collection and release, without claiming that a')
    text = once(text, 'bool success = arithmetic && unicode && bigInteger && international && exceptionControl && logs;',
                'bool success = arithmetic && unicode && bigInteger && international && exceptionControl && wasmSubset && logs;')
    patched = text.encode("utf-8")
    patch = "".join(difflib.unified_diff(raw.decode().splitlines(True), text.splitlines(True),
        fromfile="a/tools/iewebkit_port/core_jsc_native.cpp", tofile="b/tools/iewebkit_port/core_jsc_native.cpp")).encode()
    header_path = HERE / "wasm_cases.h"
    header = header_path.read_bytes()
    if len(header) > MAX_SOURCE_BYTES:
        raise ValueError("Probe input header exceeds source bound")
    record = {
        "schema": "zetscape.genuine-jsc-wasm-probe-patch.v1",
        "upstream_commit": "5220e80b97a253c60ed899361654142ab5021998",
        "preimage": {"path": str(SOURCE), "sha256": PREIMAGE_SHA256, "size_bytes": len(raw)},
        "staged_source": {"path": "core_jsc_native_wasm.cpp", "sha256": hashlib.sha256(patched).hexdigest(), "size_bytes": len(patched)},
        "patch": {"path": "native-jsc-modern-wasm.patch", "sha256": hashlib.sha256(patch).hexdigest(), "size_bytes": len(patch)},
        "extra_header": {"path": str(header_path), "sha256": hashlib.sha256(header).hexdigest(), "size_bytes": len(header)},
        "required_log": "C:\\GOPLAB\\WASM83BD.LOG", "required_cases": 8,
        "current_profile_wasm_enabled": False, "expected_current_native_outcome": "Unsupported Wasm is a failure; runtime initialization can fail earlier.",
        "canonical_source_modified": False, "engine_built": False, "guest_executed": False,
        "full_wasm_conformance_pass": False, "browser_pass": False, "gpu_pass": False,
    }
    return patched, patch, record


def stage(output):
    patched, patch, record = prepare()
    # Source staging has no caller-selected destination outside our ownership.
    output = Path(output)
    if not output.is_absolute():
        output = HERE / output
    for parent in [output, *output.parents]:
        if parent == HERE.parent:
            break
        if parent.is_symlink():
            raise ValueError("Do not stage through symlinks")
    output = output.resolve()
    if not output.is_relative_to(HERE) or output == HERE:
        raise ValueError("Output must be a new private directory under this lane")
    if output.exists():
        raise ValueError("Preserve existing evidence; require a new output directory")
    receipt = (json.dumps(record, indent=2) + "\n").encode()
    if sum(map(len, (patched, patch, receipt))) > MAX_OUTPUT_BYTES:
        raise ValueError("Staged output exceeds bounded source budget")
    output.mkdir(parents=True)
    for name, raw in (("core_jsc_native_wasm.cpp", patched), ("native-jsc-modern-wasm.patch", patch), ("probe-source-pin.json", receipt)):
        with (output / name).open("xb") as stream:
            stream.write(raw)
    if hashlib.sha256(SOURCE.read_bytes()).hexdigest() != PREIMAGE_SHA256:
        raise ValueError("Canonical preimage drifted while staging")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="New private subdirectory; absent means read-only preimage check")
    args = parser.parse_args()
    try:
        record = stage(args.output) if args.output else prepare()[2]
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(record, indent=2))


if __name__ == "__main__":
    main()
