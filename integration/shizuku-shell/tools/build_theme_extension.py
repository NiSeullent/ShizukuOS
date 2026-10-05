#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Theme extension helpers for the shell build (used by ../build.py; also runnable on its own).

  python3 tools/build_theme_extension.py --control OUTDIR   # cheap host parser control (gcc), writes OUTDIR/control.txt

* theme_map(): the exact staged theme-file map (repo source -> beside-EXE copy -> intended media target) so the root
  media stager/mkpayload can be extended later. Nothing here modifies the media stager.
* stage_themes(stage_dir): copies the three external theme.ini files beside the new EXE (stage/THEMES/<Name>/theme.ini),
  plus the exact theme attribution and GPL3 data license; verifies each byte-exact copy.
  No audio/image asset is copied (sound refs are names only).
* run_control(): compiles tests/test_theme.c with theme.c on the host and runs it. Host portable parser/state control
  only; NOT a guest run and NOT a Win32 execution.
Only writes where told; no Git, no network.
"""
import hashlib, subprocess, sys
from pathlib import Path
sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent.parent
THEMES = ("Slade", "Flute", "Jade")
MAX_THEME_BYTES = 16384
THEME_LICENSE_FILES = ("THEME-NOTICE.TXT", "THEME-GPL3.TXT")
TARGET_ROOT = "C:\\SHZ\\SYSTEM\\THEMES\\"          # intended media location (root extends its stager later)
CUSTOM_TARGET = "E:\\SHZ\\THEME\\CUSTOM.INI"       # user-provided, writable data volume; not shipped
SELECT_TARGET = "E:\\SHZ\\THEME\\SELECT.CFG"       # persisted selection record, written by the shell


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def theme_map():
    rows = []
    for n in THEMES:
        src = HERE / "themes" / n / "theme.ini"
        d = src.read_bytes()
        if not 0 < len(d) <= MAX_THEME_BYTES:
            raise RuntimeError(f"{src}: size {len(d)} outside 1..{MAX_THEME_BYTES}")
        rows.append({"name": n,
                     "source": f"integration/shizuku-shell/themes/{n}/theme.ini",
                     "beside_exe": f"THEMES/{n}/theme.ini",
                     "media_target": f"{TARGET_ROOT}{n}\\theme.ini",
                     "sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d)})
    return rows


def stage_themes(stage):
    stage = Path(stage)
    rows = theme_map()
    for r in rows:
        dst = stage / r["beside_exe"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes((HERE.parents[1] / r["source"]).read_bytes())
        if sha(dst) != r["sha256"]:
            raise RuntimeError(f"staged {dst} differs from source")
    licenses = []
    for name in THEME_LICENSE_FILES:
        src = HERE / "themes" / name
        data = src.read_bytes()
        limit = MAX_THEME_BYTES if name == "THEME-NOTICE.TXT" else 65536
        if not 0 < len(data) <= limit:
            raise RuntimeError(f"{src}: invalid theme notice/license size")
        if name == "THEME-GPL3.TXT" and not (b"GNU GENERAL PUBLIC LICENSE" in data and b"Version 3, 29 June 2007" in data):
            raise RuntimeError("theme data requires the full GPL version 3 license")
        dst = stage / "THEMES" / name
        dst.write_bytes(data)
        if sha(dst) != sha(src):
            raise RuntimeError(f"staged {dst} differs from source")
        licenses.append({"name": name, "source": "integration/shizuku-shell/themes/" + name,
                         "beside_exe": "THEMES/" + name, "media_target": TARGET_ROOT + name,
                         "sha256": sha(src), "bytes": len(data)})
    return {"files": rows, "data_license": "GPL-3.0", "license_files": licenses,
            "custom_target_not_shipped": CUSTOM_TARGET, "selection_record_written_by_shell": SELECT_TARGET,
            "load_order": [TARGET_ROOT + "<Name>\\theme.ini", "<exe dir>\\THEMES\\<Name>\\theme.ini (only if the C: file is absent)"]}


def run_control(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    exe = out / "test_theme"
    cc = subprocess.run(["gcc", "-Wall", "-Wextra", "-Werror", "-I", str(HERE / "src"), str(HERE / "tests" / "test_theme.c"),
                         str(HERE / "src" / "theme.c"), "-o", str(exe)], capture_output=True, text=True, timeout=60)
    log = "compile rc=%d\n%s%s" % (cc.returncode, cc.stdout, cc.stderr)
    rc = cc.returncode
    if rc == 0:
        r = subprocess.run([str(exe), str(HERE / "themes")], capture_output=True, text=True, timeout=60)
        log += "run rc=%d\n%s%s" % (r.returncode, r.stdout, r.stderr)
        rc = r.returncode
    (out / "control.txt").write_text(log)
    print(log)
    return rc


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--control":
        sys.exit(run_control(sys.argv[2]))
    print("usage: build_theme_extension.py --control OUTDIR")
    sys.exit(2)
