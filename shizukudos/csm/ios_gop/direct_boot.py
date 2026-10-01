#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze the cooperating IO.SYS runner and capture its entry with local GDB.

GDB's dump command treats the double quotes around these local filenames as
literal filename characters. This adapter removes only those four dump-filename
quotes in the frozen copy. The peer's source and all guest originals are kept.
"""
import hashlib
import json
import re
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PEER = REPO / "shizukudos" / "iosys_uefi" / "boot.py"
OUT = REPO / "build" / "shizukudos" / "csm-ios-gop-7acd-direct" / "inputs"


def adapt_dump_filenames(source):
    expression = re.compile(r'''(?m)^(\s*)f'dump binary memory "(\{probe / "[a-z0-9-]+\.bin"\})" (0x[0-9a-f]+ 0x[0-9a-f]+)',?''')
    adapted, count = expression.subn(lambda m: m[1] + "f'dump binary memory " + m[2] + " " + m[3] + "',", source)
    if count not in (0, 4):
        raise RuntimeError("The cooperating capture script no longer has the reviewed four dump commands")
    if count == 0:
        absolute_commands = len(re.findall(r"f'dump binary memory \{probe /", source))
        relative_commands = len(re.findall(r'"dump binary memory (?:entry|handover|stack-bpb|int1e)\.bin 0x[0-9a-f]+ 0x[0-9a-f]+"', source))
        if absolute_commands != 4 and not (relative_commands == 4 and "cwd=probe" in source):
            raise RuntimeError("The cooperating capture command format needs review")
    return adapted, count


def main():
    argv = sys.argv[1:]
    if "--run-name" not in argv:
        raise RuntimeError("A uniquely owned --run-name is required")
    name = argv[argv.index("--run-name") + 1]
    if not re.fullmatch(r"run-ios-gop-7acd-direct-[a-zA-Z0-9_-]+", name):
        raise RuntimeError("The direct trial must use this collaboration's run-name prefix")
    if " " in str(REPO) or "\n" in str(REPO):
        raise RuntimeError("This local capture adapter requires paths without whitespace")
    original = PEER.read_bytes()
    adapted, count = adapt_dump_filenames(original.decode("utf-8"))
    inputs = OUT / name
    inputs.mkdir()
    snapshot = inputs / "direct-runner.py"
    snapshot.write_text(adapted)
    (inputs / "peer-runner.py").write_bytes(original)
    (inputs / "adapter.py").write_bytes(Path(__file__).read_bytes())
    metadata = {"profile": "frozen-cooperating-io-sys-entry-capture",
                "peer_source": str(PEER), "peer_sha256": hashlib.sha256(original).hexdigest(),
                "adapted_sha256": hashlib.sha256(adapted.encode()).hexdigest(),
                "dump_filename_quote_changes": count, "guest_kernel_changes": "none by this capture adapter"}
    (inputs / "adapter-result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    module = types.ModuleType("frozen_direct_io_sys_runner")
    module.__file__ = str(PEER)
    exec(compile(adapted, str(snapshot), "exec"), module.__dict__)
    # HERE/imports retain their original location; the executed source receipt
    # uses the immutable adapted snapshot rather than another chat's live file.
    module.__file__ = str(snapshot)
    old_argv = sys.argv
    try:
        sys.argv = [str(PEER), *argv]
        return module.main()
    finally:
        sys.argv = old_argv


if __name__ == "__main__":
    raise SystemExit(main())
