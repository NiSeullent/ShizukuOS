#!/usr/bin/env python3
"""Execute fixture COM bytes on the pinned synthetic DOS/VXDLDR CPU model.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import types
import zipfile

from build_loader import build, VARIANTS

HERE = Path(__file__).resolve().parent
MODEL = HERE.parent / "v86diag/test.py"
WHEEL_SHA = "9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def test(variant, provenance_path):
    own_source = Path(__file__).read_bytes()
    provenance_bytes = provenance_path.read_bytes()
    provenance = json.loads(provenance_bytes)
    wheel = provenance_path.parent / "unicorn.whl"
    if provenance["version"] != "2.1.4" or provenance["sha256"] != WHEEL_SHA:
        raise ValueError("expected the pinned private Unicorn tool")
    wheel_bytes = wheel.read_bytes()
    if len(wheel_bytes) != 16436886 or digest(wheel_bytes) != WHEEL_SHA:
        raise ValueError("CPU tool wheel identity changed")
    target = Path(provenance["private_target"]).resolve()
    with zipfile.ZipFile(wheel) as archive:
        for member in archive.infolist():
            if not member.is_dir() and (target / member.filename).read_bytes() != archive.read(member):
                raise ValueError("extracted CPU tool file changed")
    sys.path.insert(0, str(target))
    os.environ["LIBUNICORN_PATH"] = str(target / "unicorn/lib")
    import unicorn
    if unicorn.__version__ != "2.1.4" or not Path(unicorn.__file__).resolve().is_relative_to(target):
        raise ValueError("CPU tool import escaped the verified private directory")
    from unicorn.unicorn_py3 import unicorn as native
    library = Path(native.uclib._name).resolve()
    expected_library = (target / "unicorn/lib/libunicorn.so.2").resolve()
    if library != expected_library:
        raise ValueError("CPU tool loaded a native library outside the pinned wheel")
    library_bytes = library.read_bytes()
    receipt = build(variant)
    out = HERE / "build" / variant / "guest"
    receipt_bytes = (out / "build-result.json").read_bytes()
    code = (out / "MINLDR.COM").read_bytes()
    candidate = (out / "NTWMIN9X.VXD").read_bytes()
    model_bytes = MODEL.read_bytes()
    tree = ast.parse(model_bytes, filename=str(MODEL))
    changes = []

    class Adapt(ast.NodeTransformer):
        def visit_Constant(self, node):
            value = node.value
            replacement = value
            if type(value) is int and value in (9390, 9389):
                replacement = len(candidate) if value == 9390 else len(candidate) - 1
            elif isinstance(value, (str, bytes)):
                try:
                    text = value.decode("ascii") if isinstance(value, bytes) else value
                except UnicodeDecodeError:
                    return node
                text = text.replace("C:\\NTWLAB\\NTWLDR.LOG", "C:\\VXDLAB\\MINLDR.LOG")
                text = text.replace("C:\\NTWLAB\\NTWRAP9X.VXD", "C:\\VXDLAB\\NTWMIN9X.VXD")
                text = text.replace("NTWLDR FORMAT=1", "MINLDR FORMAT=1")
                text = text.replace("PREFLIGHT=EXACT_9390_BYTES_AND_EOF",
                                    f"PREFLIGHT=EXACT_{len(candidate)}_BYTES_AND_EOF")
                if text == "NTWRAP9X":
                    text = "NTWMIN9X"
                replacement = text.encode("ascii") if isinstance(value, bytes) else text
            if replacement != value:
                changes.append({"line": node.lineno, "before": repr(value), "after": repr(replacement)})
                return ast.copy_location(ast.Constant(replacement), node)
            return node

    tree = ast.fix_missing_locations(Adapt().visit(tree))
    # The original scenario matrix, ownership and raw-result assertions stay
    # intact. Only its historical input identity/size are adapted in memory.
    adapted = ast.unparse(tree) + "\n"
    (out / "adapted-host-model.py").write_text(adapted)
    shim = types.ModuleType("build")
    shim.CANDIDATE_SHA = digest(candidate)
    previous = sys.modules.get("build")
    module = types.ModuleType("fixture_v86_model")
    sys.modules[module.__name__] = module
    sys.modules["build"] = shim
    try:
        exec(compile(tree, str(MODEL), "exec"), module.__dict__)
    finally:
        if previous is None:
            del sys.modules["build"]
        else:
            sys.modules["build"] = previous
    started = time.monotonic()
    stats = module.suite(code, candidate)
    log = stats.pop("synthetic_success_log").encode("ascii")
    (out / "synthetic-success.log").write_bytes(log)
    for path, expected in ((Path(__file__), own_source), (MODEL, model_bytes), (out / "MINLDR.COM", code),
                           (out / "NTWMIN9X.VXD", candidate),
                           (out / "build-result.json", receipt_bytes),
                           (provenance_path, provenance_bytes), (library, library_bytes)):
        if path.read_bytes() != expected:
            raise ValueError("CPU test input changed during execution")
    result = {
        "schema": 1, "kind": "isolated-fixture-v86-host-cpu-test", "variant": variant,
        "passed": True, "native_execution_verified": False,
        "fixture": "synthetic DOS/VXDLDR callbacks; actual generated COM instructions",
        "sources": receipt["sources"], "test_source_sha256": digest(own_source),
        "historical_model_sha256": digest(model_bytes), "model_identity_adaptations": changes,
        "adapted_model_sha256": digest(adapted.encode()), "build_receipt_sha256": digest(receipt_bytes),
        "artifact_sha256": digest(code), "candidate_sha256": digest(candidate),
        "tool_provenance_sha256": digest(provenance_bytes), "synthetic_log_sha256": digest(log),
        "unicorn": unicorn.__version__, "elapsed_seconds": time.monotonic() - started,
        "native_library": {"path": str(library), "sha256": digest(library_bytes)},
        "stats": stats,
    }
    (out / "test-result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=VARIANTS, required=True)
    parser.add_argument("--tool-provenance", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(test(args.variant, args.tool_provenance), indent=2, sort_keys=True))
