#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile ordinary source-bound Supervisor components; no media or VM needed."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("native_input_guards", here / "build.py")
    guards = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guards)
    output = guards.fresh_output(args.out)
    for tool in ("gcc", "nasm", "ld", "nm", "readelf", "objcopy", "x86_64-w64-mingw32-gcc"):
        if not shutil.which(tool):
            parser.error("required local tool missing: " + tool)
    pins = {str(p.relative_to(guards.ROOT)): guards.file_sha(p) for p in guards.source_files()}
    output.mkdir()
    source = here.parent / "build.py"
    spec = importlib.util.spec_from_file_location("ordinary_supervisor", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.OUT = output
    result = {"status": "FAIL_COMPILE_PRESERVED", "sources_sha256": pins,
              "VM_executed": False, "Windows98_executed": False}
    try:
        module.build_vbios()
        payload, payload_commands = module.build_payload()
        loader, loader_command = module.build_loader(payload)
        artifacts = {}
        for name in ("BOOTX64.EFI", "payload.bin", "payload.elf", "vbios.bin"):
            path = output / name
            artifacts[name] = {"bytes": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        after = {str(p.relative_to(guards.ROOT)): guards.file_sha(p) for p in guards.source_files()}
        if pins != after:
            raise ValueError("ordinary Supervisor source changed during compilation")
        result.update(status="PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN", artifacts=artifacts,
                      commands=[[str(x) for x in c] for c in [*payload_commands, loader_command]],
                      source_before_after_match=True)
    except BaseException as error:
        result["error"] = str(error)
        raise
    finally:
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "payload_bytes": len(payload), "loader": str(loader)}))


if __name__ == "__main__":
    main()
