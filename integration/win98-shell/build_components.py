#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Selective compile/link of the Win98 theme selector and appearance app.

Compile flags are copied verbatim from ntwddm/win98/theme_selector/build.py
(selector) and tools/build_theme_engine.py (appearance); PE/import gates are the
existing native_gate()/pe_gate() functions and the existing i486 scanner. This
tool never installs, executes, boots or publishes anything and makes no
runtime claim. Host tests, sanitizers and the M98THEME.DLL build are NOT run.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARENT = ROOT / "build" / "shell08-components"
RESERVE = 20 * 1024**3
LIMIT = 16 * 1024**2
SEL = "ntwddm/win98/theme_selector"
# Exact flag list from tools/build_theme_engine.py main() `native` (minus includes).
NATIVE = ["i686-w64-mingw32-gcc", "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
          "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
          "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
          "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
          "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
          "-Wl,--no-insert-timestamp", "-Isrc", "-Intwddm/include"]
# Exact selector link line from ntwddm/win98/theme_selector/build.py (output appended).
SELECTOR_FLAGS = ["-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
    "-march=i486", "-mno-sse", "-mno-sse2", "-mno-mmx", "-msoft-float",
    "-fno-builtin", "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib",
    "-Wl,--entry,_mainCRTStartup", "-Wl,--subsystem,windows:4.10",
    "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10",
    "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
    "-Wl,--no-insert-timestamp"]
COMPONENTS = {
    "selector": {
        "artifact": "SHZTHEME.EXE",
        "sources": [SEL + "/selector_core.h", SEL + "/selector_core.c", SEL + "/selector_win98.c",
                    "platform/freestanding/memory.c", "platform/freestanding/memory.h",
                    SEL + "/build.py", "benchmarks/win98se-ko-oem-native-exports-v1.json"],
        "command": ["i686-w64-mingw32-gcc"] + SELECTOR_FLAGS +
                   [SEL + "/selector_core.c", SEL + "/selector_win98.c",
                    "platform/freestanding/memory.c",
                    "-lkernel32", "-luser32", "-lgdi32", "-ladvapi32", "-o", "{out}"],
    },
    "appearance": {
        "artifact": "SHZAPPEAR.EXE",
        "sources": ["apps/shizukuos-appearance/main.c", "platform/freestanding/memory.c",
                    "platform/freestanding/memory.h", "src/uxtheme_engine_core.h",
                    "src/uxtheme_shizukuos_style.h", "ntwddm/include/ntwddm.h",
                    "ntwddm/include/nttheme.h", "tools/build_theme_engine.py",
                    "tools/i486_instruction_gate.py",
                    "benchmarks/win98se-ko-oem-native-exports-v1.json"],
        "command": NATIVE + ["-Wl,--entry,_mainCRTStartup", "apps/shizukuos-appearance/main.c",
                   "platform/freestanding/memory.c", "-lkernel32", "-luser32", "-lgdi32",
                   "-o", "{out}"],
    },
}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def tool_info(binary):
    found = shutil.which(binary)
    require(found, f"tool not found on PATH: {binary}")
    real = Path(found).resolve()
    version = subprocess.run([found, "--version"], capture_output=True, text=True, timeout=30)
    return {"name": binary, "path": found, "resolved": str(real), "sha256": sha(real),
            "version": (version.stdout.splitlines() or [""])[0]}


def check_space():
    free = shutil.disk_usage(ROOT).free
    require(free >= RESERVE + LIMIT, f"20 GiB reserve plus output budget required; free {free}")
    return free



def write_receipt(run_dir, receipt):
    """Persist a final status consistent with the complete output budget."""
    path = run_dir / "receipt.json"
    used = sum(p.stat().st_size for p in run_dir.rglob("*") if p.is_file() and p != path)
    receipt["output_bytes_before_receipt"] = used
    encoded = (json.dumps(receipt, indent=2) + "\n").encode()
    total = used + len(encoded)
    if total > LIMIT:
        receipt["status"] = "FAIL"
        receipt["error"] = f"output {total} exceeds {LIMIT} including receipt"
        path.write_text(json.dumps(receipt, indent=2) + "\n")
        raise RuntimeError(receipt["error"])
    path.write_bytes(encoded)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=("selector", "appearance", "all"), required=True)
    parser.add_argument("--dry-run", action="store_true",
                        help="print commands and source hashes; compile nothing, write nothing")
    parser.add_argument("--appearance-source-frozen", action="store_true",
                        help="parent confirmation required to actually build the appearance app")
    parser.add_argument("--output-dir", type=Path,
                        help="fresh directory under build/shell08-components")
    args = parser.parse_args()
    names = ["selector", "appearance"] if args.only == "all" else [args.only]
    if "appearance" in names and not args.dry_run:
        require(args.appearance_source_frozen,
                "appearance build refused: pass --appearance-source-frozen only after the parent confirms the source is frozen")
    free = check_space()
    run_dir = (args.output_dir or PARENT / (datetime.datetime.now(datetime.timezone.utc)
               .strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8])).resolve()
    require(run_dir.is_relative_to(PARENT.resolve()), "output must be under build/shell08-components")
    plans = {}
    for name in names:
        spec = COMPONENTS[name]
        plans[name] = [a.replace("{out}", str(run_dir / spec["artifact"])) for a in spec["command"]]
    src_hash = {n: {s: sha(ROOT / s) for s in COMPONENTS[n]["sources"]} for n in names}
    if args.dry_run:
        for name in names:
            missing = [s for s in COMPONENTS[name]["sources"] if not (ROOT / s).is_file()]
            print(json.dumps({"component": name, "cwd": str(ROOT), "command": plans[name],
                              "missing_sources": missing, "source_sha256": src_hash[name],
                              "tool": tool_info(plans[name][0])}, indent=2))
        print("DRY-RUN only: nothing compiled, no output written.")
        return
    require(not run_dir.exists() or not any(run_dir.iterdir()), "output dir must be fresh")
    PARENT.mkdir(parents=True, exist_ok=True)
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    sel_build = load("shz_selector_build", ROOT / SEL / "build.py")
    sys.path.insert(0, str(ROOT / "tools"))
    theme_build = load("shz_theme_engine_build", ROOT / "tools/build_theme_engine.py")
    theme_build.BUILD = run_dir   # pe_gate only reads M98THEME.DLL here, which appearance must not import
    receipt = {"schema": 1, "status": "FAIL", "components": {}, "source_root": str(ROOT),
               "run_directory": str(run_dir), "free_bytes_at_start": free,
               "host_tests_run": False, "sanitizers_run": False, "m98theme_dll_built": False,
               "installation_performed": False, "native_win98_execution": "not_tested",
               "runtime_claims": "none"}
    try:
        for name in names:
            spec, cmd = COMPONENTS[name], plans[name]
            entry = receipt["components"][name] = {"status": "FAIL", "command": cmd,
                    "source_sha256": src_hash[name], "tool": tool_info(cmd[0])}
            done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
            entry["returncode"] = done.returncode
            entry["stdout"], entry["stderr"] = done.stdout[:8192], done.stderr[:8192]
            require(done.returncode == 0, f"{name}: compile/link failed")
            out = run_dir / spec["artifact"]
            gates = entry["gates"] = {}
            if name == "selector":
                gates["native_gate"] = sel_build.native_gate(out)
            else:
                gates["pe_gate"] = theme_build.pe_gate(out, False)
                require("M98THEME.DLL" not in gates["pe_gate"]["imports"],
                        "appearance must not statically import the provider")
            cpu, disasm = theme_build.scan(out)
            (run_dir / (spec["artifact"] + ".i486.log")).write_bytes(disasm)
            gates["i486_scan"] = {"status": "PASS", "cpu": cpu}
            entry["artifact"] = {"path": str(out), "sha256": sha(out), "bytes": out.stat().st_size}
            require({s: sha(ROOT / s) for s in spec["sources"]} == src_hash[name],
                    f"{name}: source changed during build")
            entry["status"] = "PASS_STATIC_GATES_ONLY"
        receipt["status"] = "PASS_STATIC_GATES_ONLY"
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        write_receipt(run_dir, receipt)
    print(f"{receipt['status']}: {names}; compile+PE/import/i486 static gates only; receipt {run_dir/'receipt.json'}")


if __name__ == "__main__":
    main()
