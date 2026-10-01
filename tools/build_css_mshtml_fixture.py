#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build genuine MSHTML CSS consumer fixture; no VM/network/global changes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

import pefile
from i486_instruction_gate import scan

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ["src/m98_css_mshtml_values.h", "src/m98_css_mshtml_values.c",
           "tests/m98_css_mshtml_values_host.c", "tests/m98_css_mshtml_guest.cpp",
           "tools/build_css_mshtml_fixture.py", "docs/TRIDENT_CSS_NATIVE_FIXTURE.md",
           "tools/i486_instruction_gate.py", "tests/test_i486_instruction_gate.py",
           "platform/freestanding/memory.c", "platform/freestanding/memory.h",
           "benchmarks/win98se-ko-oem-native-exports-v1.json"]
CORE_EXPORTS = sorted(["m98_css_append", "m98_css_ascii", "m98_css_at", "m98_css_compute",
    "m98_css_count", "m98_css_destroy", "m98_css_empty", "m98_css_errors", "m98_css_literal",
    "m98_css_lookup", "m98_css_number", "m98_css_property_count", "m98_css_replacements",
    "m98_css_serialize", "m98_css_snapshot_destroy", "m98_css_substitute", "m98_css_tokenize",
    "m98_css_value"])


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def read(path, limit=8 * 1024 * 1024):
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.resolve() == path,
            "canonical regular input required: " + str(path))
    require(path.stat().st_size <= limit, "bounded input required")
    before = path.stat()
    data = path.read_bytes()
    after = path.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size,
                          s.st_mtime_ns, s.st_ctime_ns)
    require(identity(after) == identity(before) and len(data) == before.st_size, "input drift")
    return data


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core-receipt", required=True, type=Path)
    parser.add_argument("--core-sha256", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{64}", args.core_sha256), "explicit core hash")
    core_path = args.core_receipt.absolute()
    require(core_path.parent.parent == ROOT / "build", "owned direct core build")
    raw = read(core_path)
    require(digest(raw) == args.core_sha256, "caller-approved core receipt mismatch")
    core = json.loads(raw)
    require(type(core["schema"]) is int and core["schema"] == 1 and
            core["kind"] == "current-css-token-and-variable-core-build" and
            core["profile"] == "current-css-variables-active-fallback-core-v1" and
            core["passed"] is True and
            all(core[k] is False for k in ("foreign_script_execution", "native_execution",
                "mshtml_style_integration", "native_paint", "browser_wpt_pass", "full_modern_css",
                "full_browser", "wasm", "webgpu", "webgl", "modern_apps", "vm_operations")),
            "approved build-only core profile")
    dll = core["artifacts"]["M98CSS.DLL"]
    machine = dll["i486_instructions"]
    require(dll["pe98_gate"] == "pass" and dll["imports"] == {} and
            dll["exports"] == CORE_EXPORTS and
            type(machine["instructions_decoded"]) is int and machine["instructions_decoded"] > 100 and
            machine["post_i486_families"] == "absent" and
            (dll["stack_reserve"], dll["stack_commit"]) == (2097152, 524288),
            "pure i486 DLL core contract")
    inputs = {name: read(ROOT / name) for name in SOURCES}
    closure = {}
    for name, expected in core["source_sha256"].items():
        require(not Path(name).is_absolute() and ".." not in Path(name).parts,
                "canonical source member")
        data = read(ROOT / name)
        require(digest(data) == expected and
                digest(read(core_path.parent / "source" / name)) == expected,
                "core current/frozen source mismatch: " + name)
        closure[name] = expected
    for step in core["steps"]:
        require(step["returncode"] == 0 and
                digest(read(Path(step["log"]))) == step["sha256"], "core build log")
    for name, row in core["artifacts"].items():
        require(Path(name).name == name, "canonical core artifact")
        data = read(core_path.parent / name)
        require(len(data) == row["size"] and digest(data) == row["sha256"], "core artifact")
    for name, expected in core["generated_sha256"].items():
        require(Path(name).name == name and
                digest(read(core_path.parent / name)) == expected, "core generated pin")
    out = args.out.absolute()
    require(out.parent == ROOT / "build" and not out.exists() and
            out.resolve() == out, "fresh canonical owned build output")
    out.mkdir()
    frozen = {name: digest(data) for name, data in inputs.items()}
    for name, data in inputs.items():
        destination = out / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    (out / "core-build.json").write_bytes(raw)
    (out / "M98CSS.DLL").write_bytes(read(core_path.parent / "M98CSS.DLL"))
    steps = []
    receipt = dict(schema=1, kind="genuine-mshtml-css-variable-consumer-build", passed=False,
                   source_sha256=frozen, core_receipt=str(core_path),
                   core_receipt_sha256=args.core_sha256, core_source_sha256=closure,
                   steps=steps, native_execution=False, native_mshtml_styles=False,
                   native_geometry=False, native_paint=False, actual_child_exit=False,
                   full_css=False, browser_wpt=False, full_browser=False,
                   wasm=False, webgpu=False, webgl=False, modern_apps=False,
                   vm_operations=False)

    def run(name, command, env=None):
        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, timeout=60)
        data = result.stdout + result.stderr
        require(len(data) <= 8 * 1024 * 1024, "bounded tool log")
        log = out / (name + ".log")
        log.write_bytes(data)
        steps.append(dict(name=name, command=command, returncode=result.returncode,
                          log=str(log), sha256=digest(data)))
        require(result.returncode == 0, name + ": " + data.decode(errors="replace"))
        return data.decode().strip()

    try:
        run("i486-parser-controls", ["python3", "tests/test_i486_instruction_gate.py", "-v"],
            dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        host_flags = ["-std=c99", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc"]
        host_sources = ["src/m98_css_syntax.c", "src/m98_css_mshtml_values.c",
                        "tests/m98_css_mshtml_values_host.c"]
        run("host-build", ["clang"] + host_flags + host_sources + ["-o", str(out / "values-host")])
        normal = run("host-test", [str(out / "values-host")])
        run("sanitizer-build", ["clang"] + host_flags + ["-fsanitize=address,undefined",
            "-fno-omit-frame-pointer"] + host_sources + ["-o", str(out / "values-sanitize")])
        sanitizer = run("sanitizer-test", [str(out / "values-sanitize")], dict(os.environ,
                        ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
        require(normal == sanitizer, "normal/sanitizer output mismatch")
        native = ["-Os", "-Wall", "-Wextra", "-Werror", "-Isrc", "-march=i486", "-mno-sse",
                  "-mno-sse2", "-mno-mmx", "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe"]
        run("native-values", ["i686-w64-mingw32-gcc", "-std=c99"] + native +
            ["-c", "src/m98_css_mshtml_values.c", "-o", str(out / "values.o")])
        run("native-memory", ["i686-w64-mingw32-gcc", "-std=c99"] + native +
            ["-c", "platform/freestanding/memory.c", "-o", str(out / "memory.o")])
        guest = out / "CSS13PR.EXE"
        run("native-fixture", ["i686-w64-mingw32-g++", "-std=c++11"] + native +
            ["-fno-exceptions", "-fno-rtti", "-nostdlib", "-Wl,--entry,_mainCRTStartup",
             "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
             "-Wl,--no-insert-timestamp", "-Xlinker", "--stack", "-Xlinker", "2097152,524288",
             "tests/m98_css_mshtml_guest.cpp", str(out / "values.o"), str(out / "memory.o"),
             "-lkernel32", "-luser32", "-lole32", "-loleaut32", "-lversion", "-o", str(guest)])
        approved = json.loads(inputs[SOURCES[-1]])["dlls"]
        with pefile.PE(str(guest)) as pe:
            h = pe.OPTIONAL_HEADER
            require(pe.FILE_HEADER.Machine == 0x14c and h.Magic == 0x10b and not pe.is_dll(), "PE32 EXE")
            require(pe.FILE_HEADER.TimeDateStamp == 0 and h.AddressOfEntryPoint, "entry/timestamp")
            require((h.MajorOperatingSystemVersion, h.MinorOperatingSystemVersion) == (4, 10) and
                    h.Subsystem == 2 and (h.MajorSubsystemVersion, h.MinorSubsystemVersion) == (4, 10), "GUI/OS4.10")
            require((h.SizeOfStackReserve, h.SizeOfStackCommit) == (2097152, 524288), "bounded stack")
            require(not h.DllCharacteristics & (0x40 | 0x100 | 0x8000), "loader flags")
            require(h.DATA_DIRECTORY[5].VirtualAddress and not pe.FILE_HEADER.Characteristics & 1, "relocations")
            require(all(not h.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)) and
                    not getattr(pe, "DIRECTORY_ENTRY_EXPORT", []), "clean loader directories/no exports")
            imports = {}
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                name = module.dll.decode().upper()
                require(name in {"KERNEL32.DLL", "USER32.DLL", "OLE32.DLL", "OLEAUT32.DLL", "VERSION.DLL"}, "original DLL")
                symbols = [x.name.decode() if x.name else "#" + str(x.ordinal) for x in module.imports]
                require(set(symbols) <= set(approved[name]), "non-OEM import: " + name)
                imports[name] = sorted(symbols)
        instruction_gates = {}
        for binary in (guest, out / "M98CSS.DLL"):
            gate, data = scan(binary)
            require(gate["instructions_decoded"] > 100, "actual linked instruction stream required")
            log = out / (binary.stem + "-full-disassembly.log")
            log.write_bytes(data)
            steps.append(dict(name=binary.stem + "-full-disassembly", command=gate["command"],
                returncode=0, log=str(log), sha256=digest(data)))
            instruction_gates[binary.name] = gate
        require(guest.stat().st_size <= 1024 * 1024, "bounded guest artifact")
        require(all(digest(read(ROOT / name)) == expected for name, expected in frozen.items()) and
                all(digest(read(ROOT / name)) == expected for name, expected in closure.items()), "source drift")
        receipt.update(passed=True, host=normal, sanitizer=sanitizer,
                       artifacts={p.name: dict(size=p.stat().st_size, sha256=digest(read(p)))
                                  for p in (guest, out / "M98CSS.DLL")})
        receipt["artifacts"][guest.name].update(pe98_gate="pass", imports=imports, exports=[],
            stack_reserve=2097152, stack_commit=524288,
            i486_instructions=instruction_gates[guest.name])
        receipt["artifacts"]["M98CSS.DLL"].update(pe98_gate="pass", imports={}, exports=CORE_EXPORTS,
            stack_reserve=2097152, stack_commit=524288,
            i486_instructions=instruction_gates["M98CSS.DLL"])
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(dict(result=str(out / "result.json"), sha256=digest(read(out / "result.json")),
                          host=normal, native_execution=False)))


if __name__ == "__main__":
    main()
