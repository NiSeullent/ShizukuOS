#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the actual kernel build inventory against GCC's local dependencies.

The real profile selection and source_hashes run with build boundaries
intercepted. Only GCC preprocessing runs; no kernel, stub, link or guest build.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.dont_write_bytecode = True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_kbuild(root, name):
    # Each module gets its own actual shzlib path bindings. Imports perform no
    # build/download; main is called separately with its build boundaries held.
    saved_path, saved_helper = list(sys.path), sys.modules.pop("shzlib", None)
    spec = importlib.util.spec_from_file_location(name, root / "shizukudos/kbuild.py")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = saved_path
        sys.modules.pop("shzlib", None)
        if saved_helper is not None:
            sys.modules["shzlib"] = saved_helper
    return module


class ProfilesCollected(Exception):
    pass


class StubCollected(Exception):
    pass


def collect_profiles(module, private_build=None):
    profiles = []
    original_kernel, original_stub, original_run = module.build_kernel, module.build_standalone_stub, module.run
    saved_argv = list(sys.argv)
    original_build = module.BUILD
    if private_build is not None:
        module.BUILD = private_build

    def kernel(name, directory, flags, nasm, ld, image, extra_c=()):
        del nasm, ld, image
        inputs = module.sources(directory, ".c") + list(extra_c)
        profiles.append({"name": name, "units": [{"source": p,
            "flags": list(flags) + ["-I", module.SHZ, "-I", module.SHZ / directory]} for p in inputs]})
        return {}  # main stops before inspecting, linking or publishing images

    def stub(k32=False):
        def capture(command, **kwargs):
            del kwargs
            if command[0] == "gcc":
                index = command.index("-c")
                profiles.append({"name": "stub-k32" if k32 else "stub-k64", "units": [{
                    "source": command[index+1], "flags": command[1:index]}]})
                raise StubCollected
            # The only preceding operation is the NASM call, also intercepted.
            if command[0] != "nasm":
                raise AssertionError("unexpected stub operation before C input capture")
            return subprocess.CompletedProcess(command, 0, "", "")
        module.run = capture
        try:
            original_stub(k32=k32)
        except StubCollected:
            pass
        finally:
            module.run = original_run
        if k32:
            raise ProfilesCollected
        return {}

    module.build_kernel, module.build_standalone_stub = kernel, stub
    sys.argv = [str(module.__file__)]
    try:
        module.main()
    except ProfilesCollected:
        pass
    finally:
        module.build_kernel, module.build_standalone_stub, module.run = original_kernel, original_stub, original_run
        module.BUILD = original_build
        sys.argv[:] = saved_argv
    expected = {"kernel32", "kernel64", "kernel64s", "kernel32s", "stub-k64", "stub-k32"}
    if {p["name"] for p in profiles} != expected or len(profiles) != 6:
        raise AssertionError("actual main did not select the four kernels and both stubs")
    return profiles


def normalized_profiles(profiles, root):
    return {p["name"]: [{"source": str(u["source"].relative_to(root)),
            "flags": [str(f).replace(str(root), "<ROOT>") for f in u["flags"]]} for u in p["units"]] for p in profiles}


def dependencies(output):
    body = output.replace("\\\n", " ").partition(":")[2]
    if not body:
        raise ValueError("GCC produced no dependency rule")
    return [Path(p).resolve() for p in shlex.split(body)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error("choose a fresh output directory")
    out.mkdir(parents=True)
    live = load_kbuild(ROOT, "kbuild_closure_live")
    inventory = live.source_hashes()
    # Select from the live production tree independently of the inventory.
    # Otherwise an omitted glob-selected C file could vanish from the frozen
    # tree, silently reducing both the build and the dependency check.
    live_profiles = collect_profiles(live, private_build=out / "live-selection-build")
    selected_c = {u["source"] for p in live_profiles for u in p["units"]}
    paths = {ROOT / p for p in inventory}
    paths.update(selected_c)
    # Extra headers deliberately precede dependency generation, so an omitted
    # header cannot make preprocessing fail before the coverage test sees it.
    for directory in (ROOT / "shizukudos", ROOT / "shizukufs/v1/libsfs", ROOT / "drivers/ahci_native"):
        paths.update(directory.rglob("*.h"))
    paths.add(Path(__file__).resolve())
    snapshots = {p: p.read_bytes() for p in sorted(paths)}
    frozen = out / "frozen"
    artifacts = {}
    for p, data in snapshots.items():
        copy = frozen / p.relative_to(ROOT); copy.parent.mkdir(parents=True, exist_ok=True); copy.write_bytes(data)
        artifacts[copy] = data
    gcc = Path(shutil.which("gcc")).resolve()
    gcc_bytes = gcc.read_bytes()
    module = load_kbuild(frozen, "kbuild_closure_frozen")
    frozen_inventory = module.source_hashes()
    profiles = collect_profiles(module)
    live_selection = normalized_profiles(live_profiles, ROOT)
    frozen_selection = normalized_profiles(profiles, frozen)
    result = {"status": "FAIL", "scope": "Actual kbuild source inventory and six profile C dependency closures only",
              "source_inventory_count": len(inventory), "source_inventory_sha256": inventory,
              "sources_sha256": {str(p.relative_to(ROOT)): digest(b) for p,b in snapshots.items()},
              "gcc": {"path": str(gcc), "sha256": digest(gcc_bytes)}, "profiles": [], "records": [],
              "frozen_inventory_equal": frozen_inventory == inventory, "missing_dependencies": [],
              "live_selections": live_selection, "frozen_selections": frozen_selection,
              "selections_equal": live_selection == frozen_selection,
              "missing_selected_c": sorted(str(p.relative_to(ROOT)) for p in selected_c if str(p.relative_to(ROOT)) not in inventory),
              "header_mutation_control": {}, "omitted_c_control": {}, "kernel_built": False, "guest_executed": False}

    def stable():
        return all(p.read_bytes() == b for p,b in snapshots.items()) and all(
            p.read_bytes() == b for p,b in artifacts.items()) and gcc.read_bytes() == gcc_bytes

    all_missing = set()
    all_dependencies = set()
    compiled = 0
    passed = frozen_inventory == inventory and result["selections_equal"] and not result["missing_selected_c"]
    for profile in profiles:
        record = {"name": profile["name"], "units": [], "missing_dependencies": []}
        for index, unit in enumerate(profile["units"]):
            source = unit["source"]
            command = list(map(str, [gcc, *unit["flags"], "-MM", "-MT", "closure", source]))
            if not stable():
                process = subprocess.CompletedProcess(command, 125, "", "source/tool/artifact changed; refused")
            else:
                try:
                    process = subprocess.run(command, capture_output=True, text=True, timeout=15)
                except subprocess.TimeoutExpired:
                    process = subprocess.CompletedProcess(command, 124, "", "bounded 15-second preprocessing timeout")
            log = out / (profile["name"] + "-" + str(index) + ".d")
            log.write_text(process.stdout + process.stderr)
            artifacts[log] = log.read_bytes()
            info = {"source": str(source.relative_to(frozen)), "command": command, "returncode": process.returncode,
                    "stdout": process.stdout, "stderr": process.stderr}
            missing = []
            if process.returncode == 0:
                dep = dependencies(process.stdout)
                local = [str(p.relative_to(frozen)) for p in dep]
                if str(source.relative_to(frozen)) not in local:
                    raise AssertionError("GCC dependency rule omitted the selected C source")
                all_dependencies.update(local)
                missing = sorted(set(local) - set(frozen_inventory))
                info["local_dependencies"] = local
                compiled += 1
            else:
                passed = False
            info["missing_dependencies"] = missing
            all_missing.update(missing)
            record["units"].append(info)
            record["missing_dependencies"] = sorted(set(record["missing_dependencies"]) | set(missing))
        result["profiles"].append(record)
        print(profile["name"], len(record["units"]), "missing", record["missing_dependencies"], flush=True)
    result["missing_dependencies"] = sorted(all_missing)
    passed = passed and not all_missing
    header = frozen / "shizukudos/win64/pe_parse.h"
    before = header.read_bytes()
    try:
        header.write_bytes(before + b"\n/* bounded source-inventory mutation control */\n")
        mutated = module.source_hashes()
        changes = sorted(k for k in set(mutated) | set(frozen_inventory) if mutated.get(k) != frozen_inventory.get(k))
        result["header_mutation_control"] = {"path": str(header.relative_to(frozen)), "before_sha256": digest(before),
            "mutated_sha256": digest(header.read_bytes()), "changed_inventory_paths": changes,
            "passed": changes == ["shizukudos/win64/pe_parse.h"]}
    finally:
        header.write_bytes(before)
    passed = passed and result["header_mutation_control"]["passed"]
    # Exercise an actual, temporary inventory-function omission, rather than
    # replacing the production inventory with a test-only list. Independently
    # frozen/live-selected C files remain visible to the real profile selector.
    kbuild_copy = frozen / "shizukudos/kbuild.py"
    code = kbuild_copy.read_bytes()
    anchor = b"    return {str(p.relative_to(REPO)): sha256_file(p) for p in sorted(paths)}"
    if code.count(anchor) != 1:
        raise AssertionError("cannot bind the bounded omitted-C control to actual source_hashes")
    try:
        kbuild_copy.write_bytes(code.replace(anchor, b"    paths.discard(SHZ / 'kernel64/proc.c')\n" + anchor))
        omitted = load_kbuild(frozen, "kbuild_closure_omitted_c")
        omitted_inventory = omitted.source_hashes()
        omitted_profiles = collect_profiles(omitted)
        missing_units = sorted(str(p.relative_to(ROOT)) for p in selected_c
                               if str(p.relative_to(ROOT)) not in omitted_inventory)
        missing_dep = sorted(all_dependencies - set(omitted_inventory))
        equal_selection = normalized_profiles(omitted_profiles, frozen) == frozen_selection
        result["omitted_c_control"] = {"path": "shizukudos/kernel64/proc.c", "inventory_count": len(omitted_inventory),
            "mutated_kbuild_sha256": digest(kbuild_copy.read_bytes()), "selections_equal": equal_selection,
            "missing_selected_c": missing_units, "missing_dependencies": missing_dep,
            "passed": equal_selection and missing_units == ["shizukudos/kernel64/proc.c"] and
                      missing_dep == ["shizukudos/kernel64/proc.c"]}
    finally:
        kbuild_copy.write_bytes(code)
    passed = passed and result["omitted_c_control"]["passed"]
    result["inputs_stable"] = stable() and live.source_hashes() == inventory and module.source_hashes() == frozen_inventory
    result["dependency_units"] = compiled
    result["artifacts_sha256"] = {str(p.relative_to(out)): digest(b) for p,b in artifacts.items()}
    result["status"] = "PASS" if passed and result["inputs_stable"] else "FAIL"
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("KBUILD_CLOSURE_HOST:", result["status"], "inventory", len(inventory), "units", compiled,
          "mutation", result["header_mutation_control"]["passed"], flush=True)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
