#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production client boundary tests and Win98 PE32 build, never native guest evidence."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
WIN98_IMPORTS = {"CloseHandle", "CreateEventA", "CreateFileA", "CreateProcessA", "CreateThread", "DeviceIoControl",
                 "ExitProcess", "FlushFileBuffers", "GetCommandLineA", "GetCurrentProcessId", "GetCurrentThreadId",
                 "GetExitCodeProcess", "GetExitCodeThread", "GetLastError", "GetTickCount", "GetVersion", "ResetEvent",
                 "Sleep", "WaitForSingleObject", "WriteFile"}


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*1024), b""):
            result.update(chunk)
    return result.hexdigest()


def inputs(endpoint_root):
    paths = [p for p in HERE.rglob("*") if p.is_file() and "__pycache__" not in p.parts]
    paths += [endpoint_root / p for p in ("ntwrapper/vxd/pma_endpoint.h", "ntwrapper/vxd/bridge.h",
                                         "ntwrapper/include/ntwrapper.h", "shizukudos/abi/shz_vmm_pma.h",
                                         "shizukudos/abi/shz_abi.h")]
    return {str(p.resolve()): digest(p) for p in paths}


def pe_contract(path):
    """Decode the actual PE32 headers/imports independently of compiler output."""
    data = path.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    assert data[pe:pe+4] == b"PE\0\0"
    machine, sections, _, _, _, optsize, _ = struct.unpack_from("<HHIIIHH", data, pe+4)
    opt = pe+24
    assert machine == 0x14c and struct.unpack_from("<H", data, opt)[0] == 0x10b
    assert struct.unpack_from("<HH", data, opt+40) == (4, 0)
    assert struct.unpack_from("<HH", data, opt+48) == (4, 0)
    assert struct.unpack_from("<H", data, opt+68)[0] == 3
    assert struct.unpack_from("<H", data, opt+70)[0] == 0
    table = opt+optsize
    def offset(rva):
        for i in range(sections):
            p = table+40*i
            _, va, rawsize, raw = struct.unpack_from("<IIII", data, p+8)
            if va <= rva < va+rawsize:
                result = raw+rva-va
                assert result < len(data)
                return result
        raise AssertionError(f"unmapped PE RVA {rva:x}")
    def string(rva):
        p = offset(rva)
        return data[p:data.index(0, p)].decode("ascii")
    import_rva = struct.unpack_from("<I", data, opt+104)[0]
    p = offset(import_rva)
    imports = {}
    while data[p:p+20] != b"\0"*20:
        lookup, _, _, name, thunk = struct.unpack_from("<IIIII", data, p)
        dll = string(name)
        q = offset(lookup or thunk)
        names = []
        while struct.unpack_from("<I", data, q)[0]:
            entry = struct.unpack_from("<I", data, q)[0]
            assert not entry & 0x80000000, "ordinal import obscures the old-Windows API contract"
            names.append(string(entry+2))
            q += 4
        imports[dll] = names
        p += 20
    assert len(imports) == 1 and next(iter(imports)).lower() == "kernel32.dll"
    names = set(next(iter(imports.values())))
    assert names == WIN98_IMPORTS, names
    return {"machine": "PE32 i386", "os_version": "4.0", "subsystem_version": "4.0",
            "dll_characteristics": 0, "imports": imports, "crt_imports": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint-root", type=Path, default=REPO)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    endpoint = args.endpoint_root.resolve()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("use a new output directory; previous evidence is retained")
    out.mkdir(parents=True)
    before = inputs(endpoint)
    runs = []
    env = os.environ.copy()
    env.update(ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    def run(command, name):
        result = subprocess.run([str(x) for x in command], cwd=REPO, env=env, capture_output=True, text=True, timeout=120)
        (out / (name+".log")).write_text(result.stdout+result.stderr)
        runs.append({"name": name, "command": [str(x) for x in command], "returncode": result.returncode,
                     "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic"]
    includes = ["-I", endpoint / "ntwrapper/vxd"]
    pe = None
    tool_inputs = {}
    dependency_inputs = {}
    passed = False
    try:
        for name in ("gcc", "clang", "i686-w64-mingw32-gcc", "llvm-readobj"):
            path = Path(shutil.which(name) or name).resolve()
            tool_inputs[str(path)] = digest(path)
            run([path, "--version"], name+"-version")
        for name in ("cc1", "collect2", "as", "ld"):
            result = run(["i686-w64-mingw32-gcc", "-print-prog-name="+name], "native-"+name+"-path")
            printed = result.stdout.strip()
            path = Path(shutil.which(printed) or printed).resolve()
            tool_inputs[str(path)] = digest(path)
        result = run(["i686-w64-mingw32-gcc", "-print-file-name=libkernel32.a"], "kernel32-import-library")
        library = Path(result.stdout.strip()).resolve()
        tool_inputs[str(library)] = digest(library)
        for source in ("client", "probe"):
            dependency = out / (source+".d")
            run(["i686-w64-mingw32-gcc", "-std=c11", "-DWINVER=0x0410", "-D_WIN32_WINNT=0x0400", *includes,
                 "-M", "-MT", source, "-MF", dependency, HERE / (source+".c")], source+"-dependencies")
            words = dependency.read_text().replace("\\\n", " ").split(":", 1)[1].split()
            for word in words:
                path = Path(word).resolve()
                dependency_inputs[str(path)] = digest(path)
        for name, compiler, flags in (("gcc", "gcc", ["-O2"]),
                                      ("asan-ubsan", "clang", ["-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            binary = out / name
            run([compiler, *common, *flags, "-I", HERE / "tests/mock", *includes,
                 HERE / "client.c", HERE / "tests/test_client.c", "-o", binary], name+"-build")
            result = run([binary], name)
            assert "checks (Win32 boundary modeled)" in result.stdout
        binary = out / "PMAQUERY.EXE"
        run(["i686-w64-mingw32-gcc", *common, "-Os", "-march=i486", "-mno-sse", "-mno-mmx", "-msoft-float",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-fno-unwind-tables", "-fno-asynchronous-unwind-tables",
             "-fno-tree-loop-distribute-patterns", "-DWINVER=0x0410", "-D_WIN32_WINNT=0x0400", *includes,
             HERE / "client.c", HERE / "probe.c", "-nostdlib", "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,console:4.0",
             "-Wl,--major-os-version,4,--minor-os-version,0,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp",
             "-lkernel32", "-o", binary], "pe32-build")
        pe = pe_contract(binary)
        pe["sha256"] = digest(binary)
        run(["llvm-readobj", "--file-headers", "--coff-imports", binary], "pe32-inspect")
        passed = True
    except (subprocess.SubprocessError, AssertionError) as error:
        print(str(error), file=sys.stderr)
    after = inputs(endpoint)
    tools_unchanged = all(Path(p).is_file() and digest(Path(p)) == h for p, h in tool_inputs.items())
    dependencies_unchanged = all(Path(p).is_file() and digest(Path(p)) == h for p, h in dependency_inputs.items())
    passed = passed and before == after and tools_unchanged and dependencies_unchanged
    report = {"passed": passed, "scope": "client uses production code; Win32 OS boundary modeled; actual PE32 built only",
              "actual_windows_execution": False, "actual_vxd_event_delivery": False, "actual_backend_rundown": False,
              "inputs_unchanged": before == after and tools_unchanged and dependencies_unchanged,
              "source_sha256": before, "compiler_and_import_library_sha256": tool_inputs,
              "native_header_dependencies_sha256": dependency_inputs, "runs": runs, "pe": pe}
    (out / "result.json").write_text(json.dumps(report, indent=2)+"\n")
    print("PASS" if passed else "FAIL", out / "result.json")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
