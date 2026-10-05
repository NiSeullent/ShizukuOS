#!/usr/bin/env python3
"""Isolated build of the ShizukuOS native shell candidate (default-off, never part of the global runtime build).

  python3 build.py --out /fresh/empty/dir [--runtime-dir DIR]

* --out must not exist or be empty (a fresh dir outside any dispatch stage / projector input); the runtime
  dir is only READ (directly, or via `sudo -n cat` when permission is denied) and never modified.
* one strict compile per object (-Wall -Wextra -Werror), one resource compile, one link; every command has a
  60 s timeout and every artifact is checked against the 8 MiB bound.
* the PE64 import table of the result is compared with the real export tables of the runtime's
  USER32/GDI32/KERNEL32 DLLs. Anything missing, an unreadable runtime or a failed step gives stageable=false.
  Nothing is declared compatible with Windows 10 from this: it is a link/import-resolution receipt only.
"""
import argparse, hashlib, json, os, struct, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode = True      # never write bytecode caches into the (hash-pinned) source tree

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
W64 = REPO / "shizukudos" / "win64"
DEFAULT_RUNTIME = REPO / "build" / "installer-link-boot05" / "installer-runtime"
CC, DLLTOOL, WINDRES = "x86_64-w64-mingw32-gcc", "x86_64-w64-mingw32-dlltool", "x86_64-w64-mingw32-windres"
# same warning/ABI flags as shizukudos/win64/build.py COMMON
COMMON = ["-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
          "-mno-red-zone", "-fno-ident", "-fno-tree-loop-distribute-patterns",
          "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-cast-function-type", "-DSHZ_THEME_NATIVE"]
SOURCES = ["main.c", "ui.c", "tasks.c", "taskbar.c", "startmenu.c", "desktop.c", "files.c", "launcher.c", "theme.c", "wallpaper.c", "sound.c", "fileops.c", "editor.c", "catalog.c", "search.c", "firstboot.c"]
THEME_FILES = ["tools/build_theme_extension.py", "tests/test_theme.c", "THEME-INTEGRATION.md",
               "themes/Slade/theme.ini", "themes/Flute/theme.ini", "themes/Jade/theme.ini",
               "themes/THEME-NOTICE.TXT", "themes/THEME-GPL3.TXT"]   # pinned inputs of the theme extension
DLLS = ["kernel32", "user32", "gdi32", "ntdll", "winmm"]   # ntdll: required by the project CRT (shzcrt.c NtShzEvidence)
FONT_ROOT = REPO / "integration" / "shizuku-font"      # root-owned, READ-ONLY; read via sudo -n cat when denied
FONT_PINS = HERE / "font-input-pins.json"
F23 = FONT_ROOT                       # COMMON core integration/shizuku-font (the historical shell font23/ draft is no longer compiled)
BCRYPT = W64 / "dlls" / "bcrypt"      # portable SHA-256 (hashes.c/h, hash_consts.h) required by noto_provider
FN = HERE / "font23-native"           # successor wrapper shz_text_noto.c + shz_text_diag.h
NATIVE = REPO / "build" / "font23-inputs-74b0"          # staged real libfreetype.a / libshzwcrt.a / headers (hash-pinned)
FONT_SOURCES = [F23 / "noto_provider.c", F23 / "noto_provider.h", F23 / "noto_win32.c", F23 / "noto_win32.h",
                F23 / "noto_asset_pins.h", F23 / "shz_text.h", BCRYPT / "hashes.c", BCRYPT / "hashes.h", BCRYPT / "hash_consts.h",
                FN / "shz_text_noto.c", FN / "shz_text_diag.h"]
# project CRT (shzcrt.c) defines these; libshzwcrt.a (real Wine-port CRT pulled by FreeType) defines them too: the project
# copies are renamed at compile time so the link has exactly one definition each (verified: see receipt/report).
CRT_RENAMED = ["memcmp", "memcpy", "memmove", "memset", "strcmp", "strcpy", "strlen"]
GPL2_TEXT = REPO / "LICENSE"
COPYING_LIB = HERE / "upstream" / "reactos" / "COPYING.LIB"
MAX_ARTIFACT = 8 * 1024 * 1024
TIMEOUT = 60

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def font_bytes_for_pins():
    """Read the pinned font inputs (root-owned, read-only). Returns {relpath: bytes}."""
    pins = json.loads(FONT_PINS.read_text())["files"]
    return {rel: read_runtime(FONT_ROOT / rel) for rel in pins}, pins

def source_hashes():
    """Hash every input that influences the result: this script, sources, resource generator, project CRT sources and
    headers (shzcrt.c/.h and all W64 include/crt headers), license text, the pin file and the root font inputs.
    NOT hashed: the MinGW toolchain/system headers (not controlled here) -- no bit-reproducibility claim is made."""
    files = [HERE / "build.py", FONT_PINS, COPYING_LIB, GPL2_TEXT]
    files += [REPO / "shizukudos" / "abi" / name for name in ("shz_auth.h", "shz_firstboot.h", "shz_audio.h")]
    files += [REPO / "shizukudos/accounts/account.h", W64 / "apps/elevate/secret.c", W64 / "apps/elevate/secret.h", HERE / "src/firstboot.h"]
    files += FONT_SOURCES + [HERE / "tools" / "font_native_link.py", FN / "font_link_probe.c"]
    files += [HERE / t for t in THEME_FILES] + [HERE / "src" / "theme.h", HERE / "src" / "wallpaper.h", HERE / "src" / "sound.h"]
    files += [HERE / "src" / s for s in SOURCES] + [HERE / "src" / "shell.h", HERE / "src" / "strings_ko.h",
              HERE / "src" / "layout.h", HERE / "src" / "icons.h",
              HERE / "src" / "editor.h", HERE / "src" / "fileops.h", HERE / "src" / "catalog.h", HERE / "src" / "search.h",
              HERE / "res" / "shell_ko.rc.in", HERE / "tools" / "gen_rc.py", W64 / "crt" / "shzcrt.c"]
    files += sorted((W64 / "include").rglob("*.h")) + sorted((W64 / "crt").glob("*.h"))
    h = {str(f.relative_to(REPO)): sha(f) for f in files}
    fonts, _ = font_bytes_for_pins()
    for rel, data in fonts.items():
        h["integration/shizuku-font/" + rel] = hashlib.sha256(data).hexdigest()
    for rel in json.loads(FONT_PINS.read_text())["native_inputs"]:
        h["build/font23-inputs-74b0/" + rel] = sha(NATIVE / rel)
    return h

receipt = {"steps": []}

COMMANDS = []   # full argv of every executed step (receipt, not just output tails)
def run(name, cmd):
    t = time.time()
    COMMANDS.append([str(c) for c in cmd])
    try:
        p = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, timeout=TIMEOUT)
        rc, out = p.returncode, (p.stdout + p.stderr)[-4000:]
    except subprocess.TimeoutExpired:
        rc, out = 124, f"timeout after {TIMEOUT}s"
    receipt["steps"].append({"name": name, "rc": rc, "seconds": round(time.time() - t, 2), "output_tail": out})
    if rc != 0:
        raise RuntimeError(f"step {name} failed rc={rc}\n{out}")

def read_runtime(path):
    """READ-ONLY access to the runtime dir; falls back to `sudo -n cat` when permission is denied."""
    try:
        return Path(path).read_bytes()
    except PermissionError:
        p = subprocess.run(["sudo", "-n", "cat", str(path)], capture_output=True, timeout=TIMEOUT)
        if p.returncode != 0:
            raise
        return p.stdout

# ---- minimal PE64 reader (exports / imports) ----
def pe_sections(d):
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    assert d[pe:pe + 4] == b"PE\0\0", "not PE"
    machine, nsec, _, _, _, optsz, _ = struct.unpack_from("<HHIIIHH", d, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    subsystem = struct.unpack_from("<H", d, opt + 68)[0]
    ddir = opt + (112 if magic == 0x20B else 96)
    secs = []
    so = opt + optsz
    for i in range(nsec):
        n, vs, va, rs, ro = struct.unpack_from("<8sIIII", d, so + 40 * i)
        secs.append((va, max(vs, rs), ro))
    return machine, magic, subsystem, ddir, secs

def rva2off(secs, rva):
    for va, sz, ro in secs:
        if va <= rva < va + sz:
            return rva - va + ro
    raise ValueError(f"rva {rva:#x} unmapped")

def cstr(d, o):
    e = d.index(b"\0", o)
    return d[o:e].decode("ascii", "replace")

def pe_exports(d):
    machine, magic, _, ddir, secs = pe_sections(d)
    rva, size = struct.unpack_from("<II", d, ddir)
    if not rva:
        return machine, []
    o = rva2off(secs, rva)
    _, _, _, _, _, _, nfunc, nnames, _, nameptr, _ = struct.unpack_from("<IIHHIIIIIII", d, o)
    no = rva2off(secs, nameptr)
    names = [cstr(d, rva2off(secs, struct.unpack_from("<I", d, no + 4 * i)[0])) for i in range(nnames)]
    return machine, names

def pe_imports(d):
    machine, magic, sub, ddir, secs = pe_sections(d)
    rva, _ = struct.unpack_from("<II", d, ddir + 8)
    out = []
    o = rva2off(secs, rva)
    while True:
        oft, _, _, name, ft = struct.unpack_from("<IIIII", d, o)
        if not name:
            break
        dll = cstr(d, rva2off(secs, name)).lower()
        t = rva2off(secs, oft or ft)
        while True:
            v = struct.unpack_from("<Q", d, t)[0]
            if not v:
                break
            if v >> 63:
                out.append((dll, f"#{v & 0xFFFF}"))
            else:
                out.append((dll, cstr(d, rva2off(secs, v & 0x7FFFFFFF) + 2)))
            t += 8
        o += 20
    return machine, magic, sub, out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--runtime-dir", default=str(DEFAULT_RUNTIME))
    a = ap.parse_args()
    out = Path(a.out).resolve()
    rt = Path(a.runtime_dir)
    if out == rt.resolve() or rt.resolve() in out.parents:
        sys.exit("refusing to build inside the runtime dir")
    if out.exists() and any(out.iterdir()):
        sys.exit(f"--out {out} is not empty; use a fresh directory")
    out.mkdir(parents=True, exist_ok=True)
    (out / "obj").mkdir(); (out / "implib").mkdir()

    receipt["source_sha256_before"] = source_hashes()
    receipt["target"] = "PE32+ x64 (Microsoft x64 ABI), Win32 API; development candidate, NOT a Windows 10 claim"
    receipt["stageable"] = False
    receipt["reasons"] = []
    stage = out / "stage"
    stage.mkdir()
    exe = stage / "shizuku-shell.exe"
    runtime_before = {}
    exports = {}
    try:
        # ---- font inputs: verify against the pins BEFORE anything is compiled (fail closed), then stage a copy ----
        fonts, pins = font_bytes_for_pins()
        for rel, meta in pins.items():
            d = fonts[rel]
            if hashlib.sha256(d).hexdigest() != meta["sha256"] or len(d) != meta["bytes"]:
                raise RuntimeError(f"font input {rel} does not match font-input-pins.json (refusing to compile)")
        fsrc = out / "fontsrc"
        for rel, d in fonts.items():
            dst = fsrc / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_bytes(d)
            if sha(dst) != pins[rel]["sha256"]:
                raise RuntimeError(f"staged copy of {rel} differs from pin")
        for rel, meta in json.loads(FONT_PINS.read_text())["f23_common_sources"].items():   # common core + bcrypt, fail closed
            if sha(REPO / rel) != meta["sha256"] or (REPO / rel).stat().st_size != meta["bytes"]:
                raise RuntimeError(f"common font source {rel} does not match font-input-pins.json (refusing to compile)")
        for rel, meta in json.loads(FONT_PINS.read_text())["native_inputs"].items():     # native FreeType/CRT inputs, fail closed
            f = NATIVE / rel
            if sha(f) != meta["sha256"] or f.stat().st_size != meta["bytes"]:
                raise RuntimeError(f"native font input {rel} does not match font-input-pins.json (refusing to compile)")
        receipt["native_inputs_verified"] = len(json.loads(FONT_PINS.read_text())["native_inputs"])
        receipt["font_pins_verified"] = {rel: {"sha256": m["sha256"], "bytes": m["bytes"]} for rel, m in pins.items()}
        receipt["font_note"] = ("pins are shell20-recorded values of the root font inputs (supplied-text-not-claims); "
                                "glyph rendering on a guest is unverified")
        # licenses staged beside the final EXE (small files only; no font file is copied here: the Noto files are loaded at
        # run time from C:\\SHZ\\FONTS and their licence text belongs with the (not yet existing) NAS font package)
        (stage / "FTL.TXT").write_bytes((NATIVE / "licenses" / "FTL.TXT").read_bytes())
        (stage / "COPYING.LIB").write_bytes(COPYING_LIB.read_bytes())
        # GPL-2.0-only text for shz_text.c: the repository's own LICENSE (GNU GPL v2 text, no appendix); not invented
        (stage / "GPL-2.0.txt").write_bytes(GPL2_TEXT.read_bytes())
        receipt["staged_licenses"] = {n: sha(stage / n) for n in ("FTL.TXT", "COPYING.LIB", "GPL-2.0.txt")}
        receipt["gpl2_text_source"] = {"path": "LICENSE", "sha256": sha(GPL2_TEXT)}
        # external theme definitions beside the EXE (stage/THEMES/<Name>/theme.ini) + exact source->target map for the
        # root media stager. Sound/image refs inside are names only: no audio/image asset is copied.
        sys.path.insert(0, str(HERE / "tools"))
        import build_theme_extension as bte
        receipt["theme_stage_map"] = bte.stage_themes(stage)
        # runtime exports (actual DLLs; read-only)
        for dll in DLLS:
            try:
                data = read_runtime(rt / f"{dll}.dll")
                m, names = pe_exports(data)
                if m != 0x8664:
                    receipt["reasons"].append(f"{dll}.dll machine {m:#x} is not x64")
                exports[dll + ".dll"] = set(names)
                runtime_before[dll + ".dll"] = hashlib.sha256(data).hexdigest()
                receipt.setdefault("runtime_dlls", {})[dll + ".dll"] = {
                    "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "named_exports": len(names)}
            except Exception as e:                      # permission / missing: recorded, not hidden
                receipt["reasons"].append(f"runtime {dll}.dll unreadable: {type(e).__name__}: {e}")
        # import libraries generated from the actual export tables (names only; no function bodies)
        for dll, names in exports.items():
            base = dll[:-4]
            deff = out / "implib" / f"{base}.def"
            deff.write_text(f"LIBRARY {dll}\nEXPORTS\n" + "".join(f"  {n}\n" for n in sorted(names)))
            run(f"dlltool {base}", [DLLTOOL, "-m", "i386:x86-64", "-d", deff, "-l", out / "implib" / f"lib{base}.a"])

        objs = []
        for s in SOURCES:
            o = out / "obj" / (s[:-2] + ".o")
            run(f"cc {s}", [CC, *COMMON, "-c", "-I", HERE / "src", "-I", fsrc, "-I", FN, "-I", W64 / "crt", "-I", W64 / "include", "-I", W64 / "apps/elevate", "-I", REPO / "shizukudos" / "abi", HERE / "src" / s, "-o", o])
            objs.append(o)
        for s in (F23 / "noto_provider.c", F23 / "noto_win32.c", BCRYPT / "hashes.c", FN / "shz_text_noto.c"):     # real Noto/FreeType provider + wrapper
            o = out / "obj" / (s.stem + ".o")
            run(f"cc {s.name}", [CC, *COMMON, "-c", "-I", NATIVE / "include", "-I", F23, "-I", BCRYPT, "-I", FN, "-I", fsrc, s, "-o", o])
            objs.append(o)
        secret = out / "obj" / "secret.o"
        run("cc existing secret.c", [CC, *COMMON, "-c", "-I", W64 / "apps/elevate", W64 / "apps/elevate/secret.c", "-o", secret])
        objs.append(secret)
        crt = out / "obj" / "shzcrt.o"
        run("cc shzcrt.c", [CC, *COMMON, "-c", *[f"-D{n}=shzcrt_{n}" for n in CRT_RENAMED],
                            "-I", W64 / "include", "-I", W64 / "crt", W64 / "crt" / "shzcrt.c", "-o", crt])
        objs.append(crt)
        rc = out / "obj" / "shell_ko.rc"
        run("gen_rc", [sys.executable, HERE / "tools" / "gen_rc.py", rc])
        res = out / "obj" / "shell_ko.res.o"
        run("windres", [WINDRES, "-c", "65001", "-O", "coff", rc, res])
        objs.append(res)
        missing_libs = [d for d in DLLS if d + ".dll" not in exports]
        if missing_libs:
            raise RuntimeError("no import library for " + ",".join(missing_libs))
        run("link", [CC, *COMMON, "-nostdlib", "-Wl,--entry,ShzStart", "-Wl,--subsystem,windows", "-Wl,--kill-at",
                     "-Wl,--dynamicbase", "-Wl,--nxcompat", *objs, NATIVE / "lib" / "libfreetype.a", NATIVE / "lib" / "libshzwcrt.a", "-L", out / "implib",
                     *["-l" + dll for dll in DLLS], "-lgcc", "-o", exe])
    except Exception as e:
        receipt["reasons"].append(str(e).splitlines()[0])
        receipt["failure_detail"] = str(e)[-3000:]

    if exe.exists():
        d = exe.read_bytes()
        machine, magic, sub, imps = pe_imports(d)
        by = {}
        for dll, fn in imps:
            by.setdefault(dll, []).append(fn)
        missing = {dll: sorted(f for f in fns if f not in exports.get(dll, set()))
                   for dll, fns in by.items()}
        unresolved_dlls = [dll for dll in by if dll not in exports]
        receipt["exe"] = {"path": str(exe), "sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d),
                          "machine": hex(machine), "optional_magic": hex(magic), "subsystem": sub}
        receipt["imports"] = {dll: sorted(fns) for dll, fns in by.items()}
        receipt["missing_exports"] = {k: v for k, v in missing.items() if v}
        receipt["dlls_without_runtime_export_table"] = unresolved_dlls
        for dll, fn in (("user32.dll", "SetShellWindow"), ("gdi32.dll", "GetTextColor"), ("gdi32.dll", "IntersectClipRect"),
                        ("kernel32.dll", "CreateFileW"), ("kernel32.dll", "ReadFile"), ("kernel32.dll", "WriteFile"),
                        ("kernel32.dll", "GetFileSizeEx"), ("kernel32.dll", "FlushFileBuffers"), ("kernel32.dll", "MoveFileExW"),
                        ("kernel32.dll", "CreateDirectoryW"), ("kernel32.dll", "DeleteFileW"), ("kernel32.dll", "GetModuleFileNameW"),
                        ("user32.dll", "GetClassNameW")):      # theme.c native load/persist + Files relayout enumeration
            if fn not in by.get(dll, []):
                receipt["reasons"].append(f"expected import {dll}!{fn} absent from the image")
        receipt["setshellwindow_import_checked_against_runtime_user32"] = (
            "SetShellWindow" in by.get("user32.dll", []) and "SetShellWindow" in exports.get("user32.dll", set()))
        if machine != 0x8664 or magic != 0x20B:
            receipt["reasons"].append("image is not PE32+ x64")
        if len(d) > MAX_ARTIFACT:
            receipt["reasons"].append("exe exceeds 8 MiB")
        if receipt["missing_exports"]:
            receipt["reasons"].append("imports missing from runtime DLL exports")
        if unresolved_dlls:
            receipt["reasons"].append("imported DLL(s) not checked against runtime: " + ",".join(unresolved_dlls))
    else:
        receipt["reasons"].append("no executable produced")

    total = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    receipt["artifact_total_bytes"] = total
    if total > MAX_ARTIFACT:
        receipt["reasons"].append("artifact dir exceeds 8 MiB")
    # runtime DLLs and root font inputs are read-only inputs: re-read and fail if they changed during the build
    for dll, h0 in runtime_before.items():
        try:
            h1 = hashlib.sha256(read_runtime(rt / dll)).hexdigest()
        except Exception as e:
            h1 = f"unreadable: {e}"
        if h1 != h0:
            receipt["reasons"].append(f"runtime {dll} changed or unreadable after build")
    receipt["runtime_dll_sha256_before"] = runtime_before
    receipt["source_sha256_after"] = source_hashes()
    receipt["source_unchanged_during_build"] = receipt["source_sha256_before"] == receipt["source_sha256_after"]
    if not receipt["source_unchanged_during_build"]:
        receipt["reasons"].append("sources changed during build")
    receipt["stageable"] = not receipt["reasons"]
    receipt["commands"] = COMMANDS
    receipt["reproducibility"] = "not claimed: toolchain/system headers are not hashed; compare the exe sha256 only as a record"
    receipt["note"] = ("stageable=true would only mean: links, x64, and every import resolves to a runtime export name. "
                       "It is not an execution result and not Windows 10 compatibility evidence.")
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2))
    print(json.dumps({k: receipt.get(k) for k in ("stageable", "reasons", "missing_exports", "artifact_total_bytes")}, indent=2))
    return 0 if receipt["stageable"] else 1

if __name__ == "__main__":
    sys.exit(main())
