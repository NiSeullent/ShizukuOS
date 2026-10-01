#!/usr/bin/env python3
"""Build the pinned genuine GCC TLS-destructor object in a private directory.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
The GCC source retains its own GPL3 / GCC Runtime Library Exception notices.
No installed compiler, library or client configuration is modified.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import shlex

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def actual_compile_inputs(command):
    """Ask the actual compiler for all genuine headers before compilation."""
    dependency_command = command[:-4] + ["-M", "-MT", "runtime-inputs", command[-3]]
    result = subprocess.run(dependency_command, check=True, capture_output=True, text=True, timeout=60)
    paths = shlex.split(result.stdout.replace("\\\n", " ").split(":", 1)[1])
    return [{"path": str(Path(path).resolve()), "sha256": digest(Path(path))} for path in dict.fromkeys(paths)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists() or output == HERE or HERE in output.parents:
        raise ValueError("Use a new private build directory outside the durable source tree")
    pin = json.loads((HERE / "core_runtime_pin.json").read_text())
    companion = pin["companion"]
    source = HERE / pin["source"]
    if digest(source) != pin["after_sha256"] or digest(HERE / pin["patch"]) != pin["patch_sha256"]:
        raise ValueError("Genuine runtime source/patch changed after its exact source pin")
    companion_source = HERE / companion["source"]
    if (digest(companion_source) != companion["after_sha256"]
            or digest(HERE / companion["patch"]) != companion["patch_sha256"]
            or digest(Path(companion["extraction_receipt"]["path"])) != companion["extraction_receipt"]["sha256"]):
        raise ValueError("Exact genuine emutls source/patch/extraction receipt changed")
    dependencies = [pin["installed_runtime"], companion["installed_runtime"], *pin["config_headers"]]
    for item in dependencies:
        if digest(Path(item["path"])) != item["sha256"]:
            raise ValueError("Installed compiler/runtime differs from the source-matched package")
    for item in pin["license_files"]:
        if digest(HERE / item["path"]) != item["sha256"]:
            raise ValueError("Preserve the exact GCC Runtime Library Exception and GPL notices")
    tool_paths = [Path(shutil.which(name)).resolve() for name in
                  ("i686-w64-mingw32-gcc", "i686-w64-mingw32-g++", "i686-w64-mingw32-ar", "i686-w64-mingw32-nm")]
    for driver, program in (("i686-w64-mingw32-gcc", "cc1"), ("i686-w64-mingw32-g++", "cc1plus"),
                            ("i686-w64-mingw32-gcc", "as"), ("i686-w64-mingw32-gcc", "ld")):
        path = subprocess.run([driver, "-print-prog-name=" + program], check=True,
                              capture_output=True, text=True).stdout.strip()
        resolved = Path(path).resolve() if Path(path).is_absolute() else Path(shutil.which(path)).resolve()
        tool_paths.append(resolved)
    tool_pins = [{"path": str(path), "sha256": digest(path)} for path in dict.fromkeys(tool_paths)]
    original = subprocess.run(["i686-w64-mingw32-ar", "p", pin["installed_runtime"]["path"], "atexit_thread.o"],
                              check=True, capture_output=True).stdout
    if hashlib.sha256(original).hexdigest() != pin["installed_runtime"]["original_member_sha256"]:
        raise ValueError("Installed original runtime member does not match the source-matched pin")
    original_emutls = subprocess.run(["i686-w64-mingw32-ar", "p", companion["installed_runtime"]["path"], "emutls.o"],
                                    check=True, capture_output=True).stdout
    if hashlib.sha256(original_emutls).hexdigest() != companion["installed_runtime"]["original_member_sha256"]:
        raise ValueError("Installed genuine emutls member differs from the exact compiler pin")
    if shutil.disk_usage(output.parent).free < 20 * 1024**3 + 1024**2:
        raise ValueError("Preserve the 20 GiB host reserve and a bounded one MiB compile margin")
    output.mkdir(parents=True)
    (output / "atexit_thread.original.o").write_bytes(original)
    (output / "emutls.original.o").write_bytes(original_emutls)
    durable = source
    source = output / "gcc-15.1.1-atexit_thread.cc"
    source.write_bytes(durable.read_bytes())
    copied_emutls = output / "gcc-15.1.1-emutls.c"
    copied_emutls.write_bytes(companion_source.read_bytes())
    (output / "source-pin.json").write_bytes((HERE / "core_runtime_pin.json").read_bytes())
    receipt = {"schema": "iewebkit-genuine-gcc-tls-runtime-compile-v1",
               "pin_sha256": digest(HERE / "core_runtime_pin.json"),
               "source": str(source), "durable_source": str(durable), "source_sha256": digest(source),
               "companion_source": str(copied_emutls), "companion_source_sha256": digest(copied_emutls),
               "companion_original_member_sha256": hashlib.sha256(original_emutls).hexdigest(),
               "original_member_sha256": hashlib.sha256(original).hexdigest(),
               "profiles": {}, "compiler_tools": tool_pins, "native_dll_lifetime": "NOT-VERIFIED"}
    for name, win9x, ntver in (("win9x", "1", "0x0400"), ("modern-control", "0", "0x0601")):
        obj = output / ("atexit_thread." + name + ".o")
        command = ["i686-w64-mingw32-g++", "-std=gnu++23", "-Os", "-g0",
                   "-ffunction-sections", "-fdata-sections", "-DWINVER=0x0410",
                   "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=" + ntver,
                   "-DIEWEBKIT_WIN9X=" + win9x, "-c", str(source), "-o", str(obj)]
        actual_inputs = actual_compile_inputs(command)
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        log = output / (name + ".log")
        log.write_text(result.stdout + result.stderr)
        item = {"argv": command, "returncode": result.returncode, "log": str(log), "log_sha256": digest(log),
                "compiler_inputs": actual_inputs}
        receipt["profiles"][name] = item
        (output / "runtime-compile.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError("Actual GCC runtime source failed compilation: " + str(log))
        undefined = subprocess.run(["i686-w64-mingw32-nm", "-u", str(obj)],
                                   check=True, capture_output=True, text=True).stdout
        defined = subprocess.run(["i686-w64-mingw32-nm", "-g", "--defined-only", str(obj)],
                                 check=True, capture_output=True, text=True).stdout
        if "___cxa_thread_atexit" not in defined:
            raise ValueError("Actual source compilation omitted the required GNU ABI function")
        if ("GetModuleHandleExW" in undefined) == (win9x == "1"):
            raise ValueError("Legacy/modern module-lifetime API selection failed")
        item.update({"object": str(obj), "object_sha256": digest(obj),
                     "undefined_symbols": undefined.splitlines(), "defined_symbols": defined.splitlines(),
                     "api_selection_gate": "PASS"})
        emutls_obj = output / ("emutls." + name + ".o")
        platform_headers = Path(pin["config_headers"][0]["path"]).parent.parent
        emutls_command = ["i686-w64-mingw32-gcc", "-std=gnu11", "-Os", "-g0", "-ffunction-sections", "-fdata-sections",
                          "-DIEWEBKIT_STANDALONE_EMUTLS=1", "-DIEWEBKIT_WIN9X=" + win9x,
                          "-I" + str(platform_headers), "-c", str(copied_emutls), "-o", str(emutls_obj)]
        companion_inputs = actual_compile_inputs(emutls_command)
        emutls_result = subprocess.run(emutls_command, capture_output=True, text=True, timeout=60)
        emutls_log = output / ("emutls-" + name + ".log")
        emutls_log.write_text(emutls_result.stdout + emutls_result.stderr)
        item["companion_compile"] = {"argv": emutls_command, "returncode": emutls_result.returncode,
                                     "log": str(emutls_log), "log_sha256": digest(emutls_log),
                                     "compiler_inputs": companion_inputs}
        (output / "runtime-compile.json").write_text(json.dumps(receipt, indent=2) + "\n")
        if emutls_result.returncode:
            raise RuntimeError("Genuine paired emutls source failed compilation: " + str(emutls_log))
        emutls_undefined = subprocess.run(["i686-w64-mingw32-nm", "-u", str(emutls_obj)], check=True,
                                         capture_output=True, text=True).stdout
        drain = "___cxa_thread_atexit_emutls_drain"
        if (drain in emutls_undefined) != (win9x == "1"):
            raise ValueError("Real emutls legacy/modern destructor ordering selection failed")
        combined = output / ("runtime." + name + ".o")
        combine = ["i686-w64-mingw32-gcc", "-r", "-nostdlib", str(obj), str(emutls_obj), "-o", str(combined)]
        subprocess.run(combine, check=True, capture_output=True, text=True, timeout=30)
        combined_undefined = subprocess.run(["i686-w64-mingw32-nm", "-u", str(combined)], check=True,
                                           capture_output=True, text=True).stdout
        combined_defined = subprocess.run(["i686-w64-mingw32-nm", "-g", "--defined-only", str(combined)], check=True,
                                         capture_output=True, text=True).stdout
        if (drain in combined_undefined or "___emutls_get_address" not in combined_defined
                or "___emutls_register_common" not in combined_defined or "___cxa_thread_atexit" not in combined_defined):
            raise ValueError("The genuine paired runtime relocatable link is incomplete")
        for row in actual_inputs + companion_inputs:
            if digest(Path(row["path"])) != row["sha256"]:
                raise ValueError("A real runtime compiler header/source changed across compilation")
        item["components"] = [{"object": str(obj), "sha256": digest(obj)},
                               {"object": str(emutls_obj), "sha256": digest(emutls_obj)}]
        item.update({"object": str(combined), "object_sha256": digest(combined), "combine_argv": combine,
                     "undefined_symbols": combined_undefined.splitlines(), "defined_symbols": combined_defined.splitlines(),
                     "companion_selection_gate": "PASS"})
    receipt["installed_runtime_unchanged"] = digest(Path(pin["installed_runtime"]["path"])) == pin["installed_runtime"]["sha256"]
    receipt["installed_emutls_runtime_unchanged"] = digest(Path(companion["installed_runtime"]["path"])) == companion["installed_runtime"]["sha256"]
    for row in tool_pins:
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("The actual compiler/assembler/linker changed across runtime compilation")
    path = output / "runtime-compile.json"
    path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"receipt": str(path), "sha256": digest(path),
                      "win9x_object_sha256": receipt["profiles"]["win9x"]["object_sha256"],
                      "api_selection_gates": "PASS", "installed_runtime_unchanged": receipt["installed_runtime_unchanged"]}))


if __name__ == "__main__":
    main()
