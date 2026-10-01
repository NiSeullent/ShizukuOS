#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build pinned Wine11 OLEACC in isolated outputs without changing module caches.

Reads the prepared Wine repository and already-built import libraries. Materializes
only OLEACC source blobs and copies the small required linker inputs into --out.
No Wine configure, sparse checkout, normal build receipt or guest is modified.
The complete upstream proxy layer is intentionally not replaced by success stubs;
unresolved dependencies are a feasibility result, not application compatibility.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys

PIN = "db11d0fe6a169c457e23d007e20404643d067aa8"
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def git(source, *args):
    return subprocess.run(["git", "-C", str(source), *args], check=True, capture_output=True).stdout


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def local_default_objects(module_dir):
    """Keep real standard COM objects; explicitly exclude the absent RPC layer."""
    path = module_dir / "main.c"
    before = path.read_text()
    changes = {
        "return OLEACC_DllMain(hinstDLL, fdwReason, lpvReserved);":
            "/* Local standard objects have no RPC proxy runtime to initialize. */\n    return TRUE;",
        "return OLEACC_DllRegisterServer();": "return E_NOTIMPL; /* RPC proxy registration is unavailable. */",
        "return OLEACC_DllUnregisterServer();": "return E_NOTIMPL; /* RPC proxy registration is unavailable. */",
        "return OLEACC_DllGetClassObject(rclsid, iid, ppv);":
            "if (ppv) *ppv = NULL;\n        return CLASS_E_CLASSNOTAVAILABLE; /* RPC proxy factory is unavailable. */",
        "0, FALSE, DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS))\n        return E_FAIL;":
            "0, FALSE, DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS)) {\n        CloseHandle(server_proc);\n        return E_FAIL;\n    }",
        "GlobalDeleteAtom(result);": "if (GlobalDeleteAtom(result)) {\n        CloseHandle(mapping);\n        return E_FAIL;\n    }",
        "if(!mapping) {\n        CoReleaseMarshalData(stream);\n        IStream_Release(stream);\n        return hr;":
            "if(!mapping) {\n        CoReleaseMarshalData(stream);\n        IStream_Release(stream);\n        return E_FAIL;",
        "hres = IAccessible_QueryInterface(acc, &IID_IOleWindow, (void**)&ow);":
            "if (!acc || !phwnd) return E_INVALIDARG;\n    *phwnd = NULL;\n    hres = IAccessible_QueryInterface(acc, &IID_IOleWindow, (void**)&ow);",
        "if(!container || !children || !children_cnt)":
            "if(!container || !children || !children_cnt || start < 0 || count < 0)",
        "switch(idObject) {":
            "if (!ppvObject || !riidInterface) return E_INVALIDARG;\n    *ppvObject = NULL;\n    switch(idObject) {",
    }
    text = before
    for original, replacement in changes.items():
        if text.count(original) != 1:
            raise RuntimeError("pinned OLEACC adaptation anchor changed")
        text = text.replace(original, replacement)
    path.write_text(text)
    diff = "".join(difflib.unified_diff(before.splitlines(True), text.splitlines(True),
                                      fromfile="a/dlls/oleacc/main.c", tofile="b/dlls/oleacc/main.c"))
    (module_dir.parent.parent / "oleacc-local-adaptation.patch").write_text(diff)
    return {"main.c_sha256": sha256(path), "patch": diff,
            "excluded": ["RPC proxy factory", "RPC proxy registration"],
            "optional_missing_user32_and_atom_apis_return_failure": True}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-wine", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--local-default-objects", action="store_true",
                        help="exclude RPC proxies and preserve failing optional-provider paths")
    args = parser.parse_args(argv)
    source, runtime, out = args.prepared_wine.resolve(), args.runtime.resolve(), args.out.resolve()
    if not out.is_relative_to(REPO / "build"):
        parser.error("isolated output must be under this checkout's ignored build directory")
    if git(source, "rev-parse", "HEAD").decode().strip() != PIN:
        parser.error("prepared Wine source is not the pinned Wine11 commit")
    if out == runtime or out.is_relative_to(runtime) or out == source or out.is_relative_to(source):
        parser.error("output must be separate from prepared source and runtime caches")
    out.mkdir(parents=True, exist_ok=True)
    shadow = out / "source"
    module_dir = shadow / "dlls" / "oleacc"
    module_dir.mkdir(parents=True, exist_ok=True)
    source_files = []
    for name in git(source, "ls-tree", "--name-only", f"{PIN}:dlls/oleacc").decode().splitlines():
        if "/" in name or name == "tests":
            continue
        data = git(source, "show", f"{PIN}:dlls/oleacc/{name}")
        target = module_dir / name
        target.write_bytes(data)
        source_files.append({"path": f"dlls/oleacc/{name}", "sha256": sha256(target)})
    include = shadow / "include"
    if not include.exists(): include.symlink_to(source / "include", target_is_directory=True)
    wrc = shadow / "tools" / "wrc"
    wrc.parent.mkdir(parents=True, exist_ok=True)
    if not wrc.exists(): wrc.symlink_to(source / "tools" / "wrc", target_is_directory=True)
    output = out / "runtime"
    lib = output / "wineport" / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    linker_inputs = []
    for path in sorted(runtime.glob("*.a")):
        target = output / path.name
        digest = sha256(path)
        shutil.copy2(path, target)
        if digest != sha256(target) or digest != sha256(path):
            raise RuntimeError("runtime linker input changed while copying")
        linker_inputs.append({"path": str(path), "copy": str(target), "sha256": digest})
    for name in ("libshzwine0.a", "libshzwcrt.a", "libuuid.a"):
        path = runtime / "wineport" / "lib" / name
        target = lib / name
        digest = sha256(path)
        shutil.copy2(path, target)
        if digest != sha256(target) or digest != sha256(path):
            raise RuntimeError("runtime linker input changed while copying")
        linker_inputs.append({"path": str(path), "copy": str(target), "sha256": digest})
    widl = source / "tools" / "widl" / "widl"
    for switches in (("-h", "-H", "oleacc_classes.h", "oleacc_classes.idl"),
                     ("-p", "-o", "oleacc_classes_p.c", "oleacc_classes.idl"),
                     ("--dlldata-only", "oleacc_classes")):
        subprocess.run([str(widl), "-m64", "-I", str(source / "include"), *switches],
                       cwd=module_dir, check=True, capture_output=True)
    generated = [{"path": name, "sha256": sha256(module_dir / name)}
                 for name in ("oleacc_classes.h", "oleacc_classes_p.c", "dlldata.c")]
    adaptation = local_default_objects(module_dir) if args.local_default_objects else None
    spec = importlib.util.spec_from_file_location("shz_oleacc_wine_builder", HERE / "build.py")
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    builder.OUT, builder.WOUT = output, output / "wineport"
    provided = {p.stem.lower(): builder.def_exports(p) for p in runtime.glob("*.def")}
    flags = [*builder.WINE_CFLAGS, "-I", shadow / "include", "-I", shadow / "include/msvcrt"]
    rt = {"shzwine0": lib / "libshzwine0.a", "shzwcrt": lib / "libshzwcrt.a", "glue_flags": flags}
    module = json.loads((HERE / ("oleacc-local-module.json" if args.local_default_objects else "oleacc-module.json")).read_text())
    receipt = {"upstream_commit": PIN, "sources": source_files, "generated_sources": generated,
               "widl_sha256": sha256(widl), "linker_inputs": linker_inputs,
               "module": module, "prepared_source_read_only": True, "normal_cache_unchanged": True,
               "guest_started": False, "app_functionality_verified": False}
    if adaptation: receipt["adaptation"] = adaptation
    try:
        result = builder.build_module(shadow, rt, module, 0x7ff860000000, provided, {"wine": shadow})
        receipt["build"] = {k: str(v) if isinstance(v, Path) else v for k, v in result.items()}
        receipt["sha256"] = sha256(result["dll"])
    except SystemExit as error:
        receipt["build_failure"] = str(error)
    (out / "oleacc-probe-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"receipt": str(out / "oleacc-probe-result.json"),
                      "failure": receipt.get("build_failure"), "build": receipt.get("build")}))
    return 1 if "build_failure" in receipt else 0


if __name__ == "__main__":
    raise SystemExit(main())
