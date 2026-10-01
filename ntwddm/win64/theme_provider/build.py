#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a private AMD64 theme candidate and inspect a supplied runtime; no install/VM."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCES = [
    "LICENSE",
    "src/uxtheme_engine_core.c", "src/uxtheme_engine_core.h",
    "src/uxtheme_engine_win32.c", "src/uxtheme_engine.def", "src/uxtheme_sysfont.c",
    "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c", "ntwddm/include/nttheme.h",
    "ntwddm/include/ntwddm.h", "platform/freestanding/memory.c",
    "platform/freestanding/memory.h", "tests/uxtheme_engine_host.c",
    "ntwddm/win64/theme_provider/build.py", "ntwddm/win64/theme_provider/provider.def",
    "ntwddm/win64/theme_provider/extensions.c", "ntwddm/win64/theme_provider/extensions_host.c",
    "ntwddm/win64/theme_provider/host_types.h",
    "ntwddm/win64/theme_provider/cookie.h",
    "ntwddm/win64/theme_provider/transport.c", "ntwddm/win64/theme_provider/transport.h",
    "ntwddm/win64/theme_provider/transport_host.c", "ntwddm/win64/theme_provider/transport_host_types.h",
    "ntwddm/win64/theme_provider/default_style.h", "ntwddm/win64/theme_provider/default_style_host.c",
]
COOKIE = "static m98_theme_handle cookie(HTHEME theme) { return (m98_theme_handle)(ULONG_PTR)theme; }"
COOKIE64 = """static m98_theme_handle cookie(HTHEME theme)
{
    /* AMD64 handle upper bits must not alias a valid opaque 32-bit cookie. */
    return m98w_cookie_value((uintptr_t)theme);
}"""


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def definition(text):
    entries = {}
    for line in text.splitlines()[2:]:
        if line.strip():
            tokens = line.strip().split()
            name, target = tokens[0].split("=", 1)
            require(name not in entries, "duplicate definition name")
            entries[name] = {"target": target, "ordinal": int(tokens[1][1:]) if len(tokens) > 1 else None}
    return entries


def runtime_snapshot(directory):
    paths = sorted(directory.glob("*"))
    modules = {}
    for path in paths:
        if path.suffix.lower() != ".dll":
            continue
        require(path.is_file() and not path.is_symlink(), f"runtime module must be a regular file: {path}")
        key = path.name.upper()
        require(key not in modules, f"case-aliased runtime module: {key}")
        before = digest(path)
        with pefile.PE(str(path)) as pe:
            require(pe.FILE_HEADER.Machine == 0x8664 and pe.OPTIONAL_HEADER.Magic == 0x20b,
                    f"runtime module must be AMD64 PE32+: {path}")
            exports = {}
            for entry in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []):
                if entry.name:
                    name = entry.name.decode("ascii")
                    require(name not in exports, f"duplicate runtime export {key}!{name}")
                    exports[name] = {"ordinal": entry.ordinal,
                                     "forwarder": entry.forwarder.decode("ascii") if entry.forwarder else None}
        require(before == digest(path), f"runtime module changed while reading: {path}")
        modules[key] = {"path": str(path.resolve()), "sha256": before, "exports": exports}
    require(modules, "no runtime DLLs provided")
    return modules


def pe_gate(path, expected):
    with pefile.PE(str(path)) as pe:
        h = pe.OPTIONAL_HEADER
        require(pe.is_dll() and pe.FILE_HEADER.Machine == 0x8664 and h.Magic == 0x20b, "expected AMD64 PE32+ DLL")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and h.AddressOfEntryPoint != 0, "wrong timestamp/entry point")
        require(h.Subsystem == 2 and h.DATA_DIRECTORY[5].VirtualAddress != 0, "GUI DLL with relocations required")
        for index in (9, 10, 13, 14):
            require(not h.DATA_DIRECTORY[index].VirtualAddress, f"unexpected runtime directory {index}")
        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = entry.dll.decode("ascii").upper()
            require(dll in {"KERNEL32.DLL", "USER32.DLL", "GDI32.DLL"}, f"unexpected import {dll}")
            require(all(item.name for item in entry.imports), f"unnamed import in {dll}")
            imports[dll] = sorted(item.name.decode("ascii") for item in entry.imports)
        require(imports, "provider imports missing")
        exports = {}
        for entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            require(entry.name is not None and not entry.forwarder, "unnamed/forwarded provider export")
            name = entry.name.decode("ascii")
            require(name not in exports and entry.address != 0, "duplicate/null provider export")
            exports[name] = entry.ordinal
        require(set(exports) == set(expected), "provider exports do not match definition")
        for name, spec in expected.items():
            if spec["ordinal"] is not None:
                require(exports[name] == spec["ordinal"], f"wrong ordinal for {name}")
        return {"status": "PASS", "machine": "AMD64", "format": "PE32+", "imports": imports, "exports": exports,
                "dll_name": pe.DIRECTORY_ENTRY_EXPORT.name.decode("ascii"),
                "native_win98_loadable": False, "windows_dll_executed": False}


def import_coverage(imports, modules):
    resolved, unresolved = [], []
    for dll, names in imports.items():
        for name in names:
            module = modules.get(dll)
            export = module["exports"].get(name) if module else None
            item = {"dll": dll, "name": name}
            if export and not export["forwarder"]:
                resolved.append(item)
            else:
                item["reason"] = "missing_module" if module is None else "unresolved_forwarder" if export else "missing_export"
                if export:
                    item["forwarder"] = export["forwarder"]
                unresolved.append(item)
    return {"status": "BLOCKED" if unresolved else "STATIC_NAMES_PRESENT",
            "resolved": resolved, "unresolved": unresolved,
            "abi_semantics_verified": False, "runtime_execution_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-dir", required=True, type=Path,
                        help="Read-only directory of the actual consumer's AMD64 DLLs")
    parser.add_argument("--default-style", choices=("off", "classic", "modern"), default="off",
                        help="Explicit app-local initial style; applied lazily outside DllMain (default off)")
    args = parser.parse_args()
    runtime_dir = args.runtime_dir.resolve(strict=True)
    require(runtime_dir.is_dir(), "runtime directory missing")
    run_dir = HERE / "build" / (datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])
    run_dir.mkdir(parents=True)
    hashes = {name: digest(ROOT / name) for name in SOURCES}
    result = {"schema": 1, "status": "FAIL", "source_root": str(ROOT), "source_hashes": hashes,
              "run_dir": str(run_dir), "installation": "not_performed", "vm_started": False,
              "native_win98_execution_verified": False, "kernel64_execution_verified": False,
              "signal_functionality_verified": False, "os_wide_theme_verified": False,
              "default_style": {"selection": args.default_style, "value": {"off": 0, "classic": 1, "modern": 2}[args.default_style],
                                "application_local_only": True, "lazy_initialization": True,
                                "dllmain_initialization": False, "public_api_called_during_initialization": False},
              "lineage": {"shared_engine": "src/uxtheme_engine_{core,win32}.c + ntwddm nttheme/ntstyle",
                          "license": "GPL-2.0-only; repository LICENSE",
                          "abi_reference": "https://raw.githubusercontent.com/wine-mirror/wine/df15af3652511150490934682202d45af892f887/dlls/uxtheme/uxtheme.spec",
                          "ordinal_47": "DrawThemeBackgroundEx; pinned primary-source specification",
                          "semantics_reference": "https://raw.githubusercontent.com/wine-mirror/wine/df15af3652511150490934682202d45af892f887/dlls/uxtheme/draw.c",
                          "implementation_copied": False}}
    commands = []

    def run(argv, env=None):
        completed = subprocess.run(argv, cwd=ROOT, env=env, text=True, capture_output=True, timeout=120)
        commands.append({"argv": argv, "returncode": completed.returncode,
                         "stdout": completed.stdout, "stderr": completed.stderr})
        (run_dir / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        require(completed.returncode == 0, f"command failed: {argv}\n{completed.stdout}{completed.stderr}")
        return completed.stdout.strip()

    try:
        modules = runtime_snapshot(runtime_dir)
        definitions = definition((HERE / "provider.def").read_text())
        base = definition((ROOT / "src/uxtheme_engine.def").read_text())
        require(len(base) == 22 and all(definitions.get(k) == v for k, v in base.items()), "shared 22-export mapping drift")
        require(set(definitions) - set(base) == {"GetThemePartSize", "DrawThemeBackgroundEx"}, "unexpected extension exports")
        versions = {name: run([name, "--version"]).splitlines()[0] for name in ("clang", "x86_64-w64-mingw32-gcc")}
        includes = ["-Isrc", "-Intwddm/include"]
        core = ["src/uxtheme_engine_core.c", "ntwddm/src/nttheme.c", "ntwddm/src/ntstyle.c"]
        host_results = {}
        for kind, flags in (("host", []), ("sanitizer", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
            for name, test, pattern in (
                ("shared_engine", "tests/uxtheme_engine_host.c", r"PASS: (\d+) theme lifecycle, pixel, state, query and allocation checks"),
                ("extensions", "ntwddm/win64/theme_provider/extensions_host.c", r"PASS: (\d+) shared-engine part-size and extension dispatch assertions"),
                ("transport", "ntwddm/win64/theme_provider/transport_host.c", r"PASS: (\d+) private Unicode transport, buffer, failure and cleanup assertions"),
                ("default_style", "ntwddm/win64/theme_provider/default_style_host.c", r"PASS: (\d+) default-style initialization, pixel, transition and allocation assertions"),
            ):
                executable = run_dir / (name + "-" + kind)
                run(["clang", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"] + flags + includes +
                    ([] if name == "transport" else core) + [test, "-o", str(executable)])
                output = run([str(executable)], dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
                match = re.fullmatch(pattern, output)
                require(match is not None and int(match[1]) > 0, f"unrecognized host result: {output}")
                host_results[name + "_" + kind] = {"checks": int(match[1]), "output": output,
                                                 "windows_abi_execution_verified": False}
        adapter = (ROOT / "src/uxtheme_engine_win32.c").read_text()
        require(adapter.count(COOKIE) == 1, "AMD64 cookie-port anchor changed; review required")
        adapter_path = run_dir / "shared-adapter-amd64.c"
        include_anchor = '#include "uxtheme_engine_core.h"'
        require(adapter.count(include_anchor) == 1, "AMD64 adapter include anchor changed; review required")
        create_anchor = "status = m98_theme_engine_create(&desc, &engine);"
        require(adapter.count(create_anchor) == 1, "lazy default-style creation anchor changed; review required")
        default_value = result["default_style"]["value"]
        create_replacement = f"status = m98w_create_default(&desc, {default_value}u, &engine);"
        adapter_path.write_text(adapter.replace(COOKIE, COOKIE64).replace(create_anchor, create_replacement).replace(
            include_anchor, include_anchor + '\n#include "cookie.h"\n#include "transport.h"\n#include "default_style.h"'))
        result["adapter_port"] = {"source": "src/uxtheme_engine_win32.c", "source_sha256": hashes["src/uxtheme_engine_win32.c"],
                                  "generated_path": str(adapter_path), "generated_sha256": digest(adapter_path),
                                  "cookie_replacements": 1, "header_insertions": 3,
                                  "lazy_creation_replacements": 1, "creation_anchor": create_anchor,
                                  "creation_replacement": create_replacement,
                                  "reason": "Reject non-zero AMD64 handle upper bits instead of aliasing a 32-bit cookie",
                                  "original_anchor": COOKIE, "replacement": COOKIE64}
        font_source = (ROOT / "src/uxtheme_sysfont.c").read_text()
        font_include_anchor = '#include <vssym32.h>'
        require(font_source.count(font_include_anchor) == 1, "system-font transport include anchor changed; review required")
        font_path = run_dir / "shared-sysfont-amd64.c"
        font_path.write_text(font_source.replace(font_include_anchor, font_include_anchor + '\n#include "transport.h"'))
        result["private_unicode_transport"] = {
            "public_user32_exports_added": False, "peer_sources_modified": False,
            "shared_font_source": "src/uxtheme_sysfont.c", "shared_font_sha256": hashes["src/uxtheme_sysfont.c"],
            "generated_font_path": str(font_path), "generated_font_sha256": digest(font_path),
            "generated_font_header_insertions": 1,
            "message_support": "WM_THEMECHANGED with zero wParam/lParam only",
            "spi_support": "GETNONCLIENTMETRICS (340/344-byte A to 504-byte W); GETICONTITLELOGFONT (60-byte A to 92-byte W)",
            "spi_endpoint_unsupported_cases_propagated": True,
            "text_support": "Strict ACP roundtrip; bounded 1 MiB; supported DrawTextW alignment/wrapping/clipping/calcrect/prefix/end-ellipsis flags",
            "unsupported_text_flags_rejected": True,
            "property_support": "Private bounded ASCII property names transported as UTF-16; full-width HWND/HANDLE preserved",
            "windows_abi_execution_verified": False,
        }
        dll = run_dir / "UXTHEME.DLL"
        run(["x86_64-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
             "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-mno-red-zone", "-nostdlib", "-shared",
             "-Wl,--entry,DllMain", "-Wl,--subsystem,windows:6.0", "-Wl,--major-os-version,6", "-Wl,--minor-os-version,0",
             "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"] +
            includes + ["-Intwddm/win64/theme_provider"] + core + [str(adapter_path), str(font_path), "platform/freestanding/memory.c",
                               "ntwddm/win64/theme_provider/extensions.c", "ntwddm/win64/theme_provider/transport.c", str(HERE / "provider.def"),
                               "-lkernel32", "-luser32", "-lgdi32", "-o", str(dll)])
        gate = pe_gate(dll, definitions)
        coverage = import_coverage(gate["imports"], modules)
        require(all(digest(ROOT / name) == value for name, value in hashes.items()), "source changed during build")
        require(runtime_snapshot(runtime_dir) == modules, "consumer runtime changed during build")
        result.update(status="STATIC_CANDIDATE_BLOCKED" if coverage["unresolved"] else "STATIC_CANDIDATE_READY_FOR_GUEST_TEST",
                      structural_build_status="PASS", host_results=host_results, compiler_versions=versions,
                      artifact={"path": str(dll), "sha256": digest(dll), "bytes": dll.stat().st_size, "pe_gate": gate},
                      runtime_import_coverage=coverage, runtime_snapshot={"directory": str(runtime_dir), "dll_count": len(modules),
                      "modules": modules})
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        receipt = run_dir / "result.json"
        receipt.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['status']}: {receipt}")
    print(f"Receipt SHA256: {digest(receipt)}")
    print(f"Unresolved consumer imports: {len(result['runtime_import_coverage']['unresolved'])}")


if __name__ == "__main__":
    main()
