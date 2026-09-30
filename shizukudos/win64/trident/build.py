#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ShizukuTrident components (docs/shizukudos10/TRIDENT.md) and return the files to pack into WIN64.IMG.

Components, each with its own builder next to its sources:
  engine/build_engine.py   shzlite.dll        the minimal engine behind engine.h     -> \\SHZ\\SYS64\\shzlite.dll
  xul/build_xul.py         xul.dll + VERSION  the Gecko binding re-implemented over engine.h
                                              -> \\SHZ\\SYS64\\gecko\\xul.dll, \\SHZ\\SYS64\\gecko\\VERSION
The Wine browser modules themselves (urlmon, mshtml, ieframe, iexplore, ...) and tridentrt.dll are wineport modules
(wineport/modules.json) and are packed by wineport.

win64/build.py calls build(OUT) once, after the Wine port and before packing (its single "W2" hook line).
`python3 shizukudos/win64/trident/build.py` rebuilds the components against an existing Shizuku build.
"""
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import shzlib  # noqa: E402

COMPONENTS = [
    # (builder, {output key: archive path})
    (HERE / "engine" / "build_engine.py", {"dll": "\\SHZ\\SYS64\\shzlite.dll"}),
    (HERE / "xul" / "build_xul.py", {"dll": "\\SHZ\\SYS64\\gecko\\xul.dll", "version": "\\SHZ\\SYS64\\gecko\\VERSION"}),
]


def _load(path):
    spec = importlib.util.spec_from_file_location("trident_" + path.parent.name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def build(out):
    """Build every component whose builder exists into <out>/trident/<component>; returns [(archive path, bytes)]."""
    out = Path(out)
    files, result = [], {}
    for builder, packed in COMPONENTS:
        name = builder.parent.name
        if not builder.exists():                      # component not written yet: nothing to pack, said so in the result
            result[name] = {"status": "absent", "builder": str(builder.relative_to(shzlib.REPO))}
            continue
        info = _load(builder).build(out / "trident" / name)
        for key, archive_path in packed.items():
            files.append((archive_path, Path(info[key]).read_bytes()))
        result[name] = {"status": "built", **{k: str(v) for k, v in info.items()}}
    shzlib.write_json(out / "trident" / "trident-result.json", {"built_utc": shzlib.utc_now(), "components": result})
    return files


if __name__ == "__main__":
    for path, data in build(shzlib.BUILD / "win64"):
        print(f"{path:40} {len(data):9} bytes")
