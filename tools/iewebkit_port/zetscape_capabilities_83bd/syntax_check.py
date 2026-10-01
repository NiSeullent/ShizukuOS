"""Bounded syntax/reference controls; never link/run JSC or a browser.

Use actual configured x86 compiler/header arguments. New output stays in this
lane. Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BUILD = ROOT / "build/iewebkit-core-83bd/build-jsc-win9x"
CONFIG_SHA256 = "65becf92311c7c05a574ab7ad2093d233eb2119579ae549140006a3d1aed3670"
OUTPUT_LIMIT = 256 * 1024


def pin(path):
    path = Path(path)
    raw = path.read_bytes()
    return {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}


def bounded_output(path, *, new=False):
    path = Path(path)
    if not path.is_absolute():
        path = HERE / path
    for parent in [path, *path.parents]:
        if parent == HERE.parent:
            break
        if parent.is_symlink():
            raise ValueError("Do not access private output through symlinks")
    path = path.resolve()
    if not path.is_relative_to(HERE) or path == HERE:
        raise ValueError("Only disjoint private output under this lane is allowed")
    if new and path.exists():
        raise ValueError("Preserve old check evidence; choose a new private output")
    return path


def child_bounds():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))


def compiler_bounds():
    child_bounds()
    resource.setrlimit(resource.RLIMIT_AS, (1024 * 1024 * 1024, 1024 * 1024 * 1024))


def run_check(staged, output):
    staged = bounded_output(staged)
    output = bounded_output(output, new=True)
    source = staged / "core_jsc_native_wasm.cpp"
    source_pin_path = staged / "probe-source-pin.json"
    source_pin = json.loads(source_pin_path.read_bytes())
    if pin(source)["sha256"] != source_pin["staged_source"]["sha256"]:
        raise ValueError("Staged caller differs from its exact-source patch receipt")
    if pin(HERE / "wasm_cases.h")["sha256"] != source_pin["extra_header"]["sha256"]:
        raise ValueError("Wasm fixture header differs from its patch receipt")
    preimage = Path(source_pin["preimage"]["path"])
    if preimage != ROOT / "tools/iewebkit_port/core_jsc_native.cpp" or pin(preimage)["sha256"] != source_pin["preimage"]["sha256"]:
        raise ValueError("Require unchanged canonical caller; never patch it here")
    config = BUILD / "cmakeconfig.h"
    db = BUILD / "compile_commands.json"
    inputs = [pin(config), pin(db), pin(source), pin(HERE / "wasm_cases.h"), pin(preimage)]
    if inputs[0]["sha256"] != CONFIG_SHA256:
        raise ValueError("Actual generated profile changed; review a new capability snapshot")
    entries = json.loads(db.read_bytes())
    matches = [entry for entry in entries if entry["file"] == str(ROOT / "build/iewebkit-core-83bd/webkitgtk-2.54.0/Source/JavaScriptCore/jsc.cpp")]
    if len(matches) != 1:
        raise ValueError("Actual JSC compile entry is absent or ambiguous")
    entry = matches[0]
    args = entry.get("arguments") or shlex.split(entry["command"])
    if args[0] != "/usr/bin/i686-w64-mingw32-g++" or args.count("-c") != 1 or args.count("-o") != 1 or Path(entry["directory"]) != BUILD:
        raise ValueError("Require the actual pinned x86 JSC compiler graph")
    remove = {args.index("-c"), args.index("-c") + 1, args.index("-o"), args.index("-o") + 1}
    base = [arg for index, arg in enumerate(args) if index not in remove]
    base += ["-I" + str(HERE), "-fsyntax-only", "-Werror", "-fdiagnostics-color=never"]
    output.mkdir(parents=True)
    environment = os.environ.copy()
    environment["TMPDIR"] = str(output)
    results = []
    for name, unit in (("wasm-caller", source), ("effective-features", HERE / "effective_features.cpp")):
        dependency = output / (name + ".d")
        argv = base + ["-MMD", "-MF", str(dependency), str(unit)]
        run = subprocess.run(argv, cwd=BUILD, stdin=subprocess.DEVNULL, capture_output=True,
                             timeout=45, env=environment, preexec_fn=compiler_bounds)
        if len(run.stdout) + len(run.stderr) > 65536:
            raise ValueError("Compiler diagnostics exceed bounded source receipt")
        results.append({"scope": name, "compiler_argv": argv, "exit_code": run.returncode,
                        "stdout": run.stdout.decode(errors="replace"), "stderr": run.stderr.decode(errors="replace"),
                        "dependency_file": str(dependency), "guest_executed": False})
    # Persist compiler results before the separate host reference control.
    (output / "compiler-results.json").write_text(json.dumps(results, indent=2) + "\n")
    cases = re.findall(r'\{ "([a-z0-9.-]+)", R"JS\((.*?)\)JS" \}', (HERE / "wasm_cases.h").read_text(), re.S)
    if len(cases) != 8 or len({name for name, script in cases}) != 8:
        raise ValueError("Require all eight unique frozen representative cases")
    program = """const vm=require('node:vm'); let input='';
process.stdin.on('data',p=>input+=p); process.stdin.on('end',()=>{
 const cases=JSON.parse(input); const run=(disabled)=>{
  const ctx=vm.createContext(disabled?{WebAssembly:undefined}:{});
  return cases.map(([name,script])=>{try{return {name,passed:vm.runInContext(script,ctx,{timeout:1000})===true}}
   catch(error){return {name,passed:false,error:error.name}}}); };
 const actual=run(false),unsupported=run(true);
 process.stdout.write(JSON.stringify({engine:'host Node/V8 reference control only',
  node:process.versions.node,v8:process.versions.v8,actual,unsupported,
  host_reference_pass:actual.every(r=>r.passed)&&unsupported.every(r=>!r.passed),
  native_jsc_executed:false,native_wasm_pass:false,full_browser_pass:false})); });"""
    # Node reserves a large virtual code range; cap its heap and fixture memory
    # instead of the compiler's virtual-address cap. The module has max 2 pages.
    reference_run = subprocess.run(["node", "--max-old-space-size=64", "-e", program],
        input=json.dumps(cases).encode(), capture_output=True, timeout=15, preexec_fn=child_bounds)
    if len(reference_run.stdout) + len(reference_run.stderr) > 16384:
        raise ValueError("Reference diagnostics exceed bounded source receipt")
    reference = json.loads(reference_run.stdout) if reference_run.returncode == 0 else {
        "exit_code": reference_run.returncode, "stderr": reference_run.stderr.decode(errors="replace"),
        "host_reference_pass": False}
    for observed in inputs:
        if pin(observed["path"]) != observed:
            raise ValueError("Actual source/configuration drifted during focused check")
    record = {"schema": "zetscape.genuine-jsc-wasm-header-check.v1", "inputs": inputs,
        "compiled_units": results, "host_reference": reference,
        "status": "SYNTAX_AND_HOST_REFERENCE_PASS" if all(r["exit_code"] == 0 for r in results) and reference["host_reference_pass"] else "FAILED",
        "engine_linked": False, "guest_executed": False, "native_wasm_pass": False,
        "gpu_pass": False, "full_browser_pass": False,
        "resource_bound": {"maximum_private_output_bytes": OUTPUT_LIMIT,
            "child_file_bytes": 1024 * 1024, "compiler_address_space_bytes": 1024 * 1024 * 1024,
            "compiler_cpu_seconds_per_unit": 30, "reference_heap_mib": 64, "reference_wasm_memory_bytes": 131072,
            "full_build_started": False}}
    receipt = (json.dumps(record, indent=2) + "\n").encode()
    if len(receipt) > 32768 or sum(p.stat().st_size for p in output.rglob("*") if p.is_file()) + len(receipt) > OUTPUT_LIMIT:
        raise ValueError("Check outputs exceed bounded private source budget")
    path = output / "syntax-reference-receipt.json"
    path.write_bytes(receipt)
    return {"status": record["status"], "checks": [{"scope": r["scope"], "exit": r["exit_code"], "stderr": r["stderr"]} for r in results],
            "host_reference": reference, "receipt": pin(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = run_check(args.staged, args.output)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
