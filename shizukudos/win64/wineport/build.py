#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build Win64 system DLLs from the pinned Wine tree (external-reuse profile, docs/shizukudos10/BASELINE.md sec. 5).

Inputs
  build/upstream/<name>        pinned upstream trees (shizukudos/upstream/manifest.json), fetched shallowly if absent;
                               Wine is configured once on the host only for widl/wrc and its generated headers
  wineport/patches/<up>/*.patch local changes, applied in order to a pristine copy of the files they touch
  wineport/modules.json        what to build: static libraries, DLLs (sources, link order) and Wine conformance tests
  wineport/crt, wineport/glue  Shizuku-original runtime support linked statically into every Wine module

Outputs (build/shizukudos/win64/, next to the Shizuku DLLs so the loader tools and WIN64.IMG packing see them)
  <name>.dll, lib<name>.a, <name>.def  one per module; exports = .spec entries that are implemented (see winespec.py:
                                       spec stubs and C bodies that are FIXME/E_NOTIMPL shells are NOT exported)
  <name>.exe                          "kind": "exe" modules (Wine programs/), packed as \\SHZ\\SYS64\\<name>.exe
  wineport/typelib/<name>.tlb         "kind": "typelib" modules (data-only type libraries such as dlls/stdole2.tlb),
                                      raw MSFT files made by widl -t; enabled ones are packed where the entry's
                                      image_path says (a disabled one is built only for widl importlib or a probe)
  wineport/gen/<wine path>/           sources generated for "makedep" modules (widl, bison, flex), laid out like
                                      Wine's object directory so that e.g. mshtml's "../jscript/jsdisp.h" resolves
  wineport/T_WINE_<NAME>.EXE          Wine's own tests for a module (subtests selected in modules.json)
  wineport/wineport-result.json       per module: export counts by kind, every excluded stub, link command

Modules with "makedep": true are built with Wine's makedep rules (tools/makedep.c) for everything in their
Makefile.in: *.idl -> widl (header; typelib/regtypelib/register resources; ident/client/server sources; "proxy" ->
a dlldata.c without NDR code, see DLLDATA_SHIM), *.y -> bison, *.l -> flex, EXTRAINCL, PARENTSRC and per-file
<obj>_EXTRADEFS / <obj>_EXTRAIDLFLAGS, with $(VAR) references expanded from Wine's configured top-level Makefile.
Modules without the key keep the original rules (the .c and .rc files of SOURCES, module EXTRADEFS).
An entry with "placeholder": true only reserves its place in the module order and keeps its "dir" in the sparse
checkout; it is never built (another part of the tree defines the module).

SHZ_WINEPORT_PROBE=1 also builds disabled modules and never stops: missing import libraries are left out of the
link, a failed link still writes the module's import library (so dependants link against it), and the compile
errors / unresolved symbols of every module are recorded under "probe" in wineport-result.json.

The Shizuku build (win64/build.py) calls build() after its own modules; `python3 build.py` alone rebuilds only the
Wine port against an existing Shizuku build.
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
sys.path.insert(0, str(HERE))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run  # noqa: E402
import winespec  # noqa: E402

W64 = SHZ / "win64"
OUT = BUILD / "win64"
WOUT = OUT / "wineport"
UPSTREAM = REPO / "build" / "upstream"
MANIFEST = SHZ / "upstream" / "manifest.json"
CONFIG = HERE / "modules.json"
CC = "x86_64-w64-mingw32-gcc"
AR = "x86_64-w64-mingw32-ar"
NM = "x86_64-w64-mingw32-nm"
DLLTOOL = "x86_64-w64-mingw32-dlltool"
WINDRES = "x86_64-w64-mingw32-windres"
BISON = "bison"
FLEX = "flex"
HOSTCC = "gcc"               # host compiler: tools/wmc (the host Wine build makes only widl and wrc)
JOBS = max(1, int(os.environ.get("SHZ_WINEPORT_JOBS", "2")))
GEN = WOUT / "gen"            # generated sources of "makedep" modules, mirroring the Wine tree
TLBDIR = WOUT / "typelib"     # raw type libraries; also widl's importlib search path (-L)


class CompileError(SystemExit):
    """Compilation failed; .errors holds one message per failed source."""
    def __init__(self, errors):
        super().__init__("compilation failed:\n" + "\n".join(errors[:6]))
        self.errors = errors


class LinkError(SystemExit):
    """Link failed; .undefined holds the unresolved symbols ld reported."""
    def __init__(self, msg, undefined=()):
        super().__init__(msg)
        self.undefined = sorted(set(undefined))

WINE_CONFIGURE = ["--enable-win64", "--disable-tests", "--without-mingw", "--without-x", "--without-freetype",
                  "--without-gnutls", "--without-alsa", "--without-pulse", "--without-dbus", "--without-fontconfig",
                  "--without-gstreamer", "--without-opengl", "--without-vulkan", "--without-sdl", "--without-udev",
                  "--without-usb", "--without-v4l2", "--without-wayland", "--without-xcomposite", "--without-xcursor",
                  "--without-xfixes", "--without-xinerama", "--without-xinput", "--without-xinput2", "--without-xrandr",
                  "--without-xrender", "--without-xshape", "--without-xshm", "--without-xxf86vm", "--without-capi",
                  "--without-coreaudio", "--without-cups", "--without-gphoto", "--without-inotify", "--without-krb5",
                  "--without-netapi", "--without-opencl", "--without-oss", "--without-pcap", "--without-pcsclite",
                  "--without-sane", "--without-unwind", "--without-ffmpeg", "--without-gettext", "--without-gettextpo"]

# Wine's PE flags (configure.ac / makedep.c for an x86_64 mingw build), plus what the Shizuku runtime needs.
WINE_CFLAGS = ["-O2", "-g0", "-D__WINESRC__", "-D__WINE_PE_BUILD", "-D_UCRT", "-D_WIN32", "-D_ACRTIMP=", "-fshort-wchar", "-mabi=ms",
               "-fno-strict-aliasing", "-mcx16", "-ffunction-sections", "-fdata-sections", "-fno-stack-protector", "-fno-ident",
               "-Wno-format", "-Wno-attributes", "-Wno-unused", "-Wno-int-to-pointer-cast", "-Wno-pointer-to-int-cast",
               "-Wno-incompatible-pointer-types", "-Wno-array-bounds", "-Wno-stringop-overflow",
               "-Wno-dangling-pointer", "-Wno-misleading-indentation"]


# ---------------------------------------------------------------- upstream trees
def manifest():
    return json.loads(MANIFEST.read_text())["upstreams"]


def git(tree, *args, check=True):
    r = subprocess.run(["git", "-C", str(tree), *args], capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(args)} in {tree}: {r.stderr.strip()}")
    return r.stdout.strip()


def ensure_tree(name):
    """Shallow fetch of the pinned commit (never a moving ref) into build/upstream/<name>; verifies HEAD."""
    spec = manifest()[name]
    dest = UPSTREAM / name
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        git(dest, "init", "-q")
        git(dest, "remote", "add", "origin", spec.get("fetch_mirror", spec["repository"]))
        sparse = spec.get("sparse_paths")
        run(["git", "-C", dest, "fetch", "-q", "--depth", "1", *(["--filter=blob:none"] if sparse else []), "origin",
             spec["commit"]], timeout=3600)
        if sparse:                                     # only these directories of a large repository
            git(dest, "sparse-checkout", "set", "--no-cone", *sparse)
        git(dest, "checkout", "-q", "FETCH_HEAD")
    head = git(dest, "rev-parse", "HEAD")
    if head != spec["commit"]:
        raise SystemExit(f"{name}: pinned {spec['commit']} but {dest} is at {head}")
    return dest


def wine_keep_paths(cfg):
    """The part of the Wine working tree the PE build reads (git sparse-checkout --no-cone patterns): the root files
    (licences, VERSION), include/, tools/, nls/ (the code page tables wrc loads), winecrt0, the .spec of each
    delay-imported DLL, and the directories and files of the modules, static libraries and image files that come
    from Wine. Disabled modules are kept too: a probe build (SHZ_WINEPORT_PROBE=1) compiles them. A module's
    "keep" list adds further paths (e.g. a PARENTSRC directory)."""
    keep = ["/*", "!/*/", "/include/", "/tools/", "/nls/", "/dlls/winecrt0/"]     # nls/: wrc's code page tables
    for lib in cfg.get("static_libs", {}).values():
        if lib.get("upstream", "wine") == "wine":
            keep.append(f"/{lib['dir']}/")
    for m in cfg["modules"]:
        if m.get("upstream", "wine") == "wine":
            keep.append(f"/{m.get('dir', 'dlls/' + m['name'])}/")
            keep += [f"/dlls/{d}/{d}.spec" for d in m.get("delay_imports", [])]
            for f in m.get("extra_sources", []):             # the file and the headers next to it
                keep += [f"/{f}", f"/{f.rsplit('/', 1)[0]}/*.h"]
            keep += [f"/{p}" for p in m.get("keep", [])]
            keep += [f"/{f}" for f in m.get("tests", {}).get("shizuku", {}).get("typelibs", {}).values()]
    keep += [f"/{f['path']}" for f in cfg.get("image_files", []) if f.get("upstream", "wine") == "wine"]
    return list(dict.fromkeys(keep))


def ensure_wine_host(wine, keep):
    """Host configure + the tools and generated headers the PE build needs (widl, wrc, include/*.h from *.idl), then
    the working tree is reduced to `keep` (about 60 MB instead of 415 MB). Wine's configure runs makedep over every
    directory's sources, so configure and the tool build see the full checkout (restored from the local objects of the
    shallow clone if it was reduced before); nothing later needs the rest of the tree."""
    need = [wine / "tools/widl/widl", wine / "tools/wrc/wrc", wine / "include/dwrite_3.h", wine / "include/wincrypt.h"]
    sparse = git(wine, "config", "--bool", "core.sparseCheckout", check=False) == "true"
    if sparse and (not (wine / "Makefile").exists() or not all(p.exists() for p in need)):
        git(wine, "sparse-checkout", "disable")
        sparse = False
    if not (wine / "Makefile").exists():
        log = UPSTREAM / "wine-configure.log"
        with open(log, "w") as f:
            subprocess.run(["./configure", *WINE_CONFIGURE], cwd=wine, stdout=f, stderr=subprocess.STDOUT, check=True)
    if not all(p.exists() for p in need):
        log = UPSTREAM / "wine-headers.log"
        with open(log, "w") as f:
            subprocess.run(["make", f"-j{JOBS}", "tools/widl/widl", "tools/wrc/wrc"], cwd=wine, stdout=f,
                           stderr=subprocess.STDOUT, check=True)
            idls = sorted(p.relative_to(wine).with_suffix(".h") for p in (wine / "include").glob("*.idl"))
            subprocess.run(["make", f"-j{JOBS}", "-k", *map(str, idls)], cwd=wine, stdout=f, stderr=subprocess.STDOUT)
    if not sparse or git(wine, "sparse-checkout", "list", check=False).splitlines() != keep:
        git(wine, "sparse-checkout", "set", "--no-cone", *keep)


def patch_files(patch):
    """(touched, created) paths of a unified diff."""
    touched, created = [], []
    lines = patch.read_text(errors="replace").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("+++ "):
            new = line[4:].split("\t")[0]
            old = lines[i - 1][4:].split("\t")[0] if i and lines[i - 1].startswith("--- ") else ""
            path = new[2:] if new.startswith("b/") else new
            if old == "/dev/null":
                created.append(path)
            elif path != "/dev/null":
                touched.append(path)
    return touched, created


def apply_patches(name, tree):
    """Restore every file the patch set touches to the pinned revision, then apply the set in order. A stamp keeps the
    tree untouched (and the objects fresh) when neither the patches nor the tree changed."""
    pdir = HERE / "patches" / name
    patches = sorted(pdir.glob("*.patch")) if pdir.is_dir() else []
    listed = sorted(REPO / p for p in manifest()[name].get("patches", []))
    if listed != patches:
        raise SystemExit(f"shizukudos/upstream/manifest.json upstreams.{name}.patches does not list exactly "
                         f"{pdir.relative_to(REPO)}/*.patch")
    digest =hashlib.sha256(b"".join(p.name.encode() + p.read_bytes() for p in patches)).hexdigest()
    stamp = tree / ".shizuku-patches"
    if stamp.exists() and stamp.read_text().strip() == digest:
        return patches
    touched, created = set(), set()
    for p in patches:
        t, c = patch_files(p)
        touched.update(t)
        created.update(c)
    old = stamp.read_text().split("\n", 1)[1].split() if stamp.exists() and "\n" in stamp.read_text() else []
    restore = sorted(set(touched) | {f for f in old if not f.startswith("+")})
    if restore:
        git(tree, "checkout", "-q", "--", *[f for f in restore if git(tree, "ls-files", f, check=False)])
    for f in set(created) | {f[1:] for f in old if f.startswith("+")}:
        (tree / f).unlink(missing_ok=True)
    for p in patches:
        r = subprocess.run(["git", "-C", str(tree), "apply", "--whitespace=nowarn", str(p)], capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"patch {p.relative_to(REPO)} does not apply to {tree}:\n{r.stderr}")
    stamp.write_text(digest + "\n" + " ".join(sorted(touched) + ["+" + c for c in sorted(created)]) + "\n")
    return patches


# ---------------------------------------------------------------- compilation with dependency tracking
def up_to_date(obj, cmd_sig):
    dep, sig = obj.with_suffix(".d"), obj.with_suffix(".sig")
    if not obj.exists() or not dep.exists() or not sig.exists() or sig.read_text() != cmd_sig:
        return False
    t = obj.stat().st_mtime
    text = dep.read_text().replace("\\\n", " ")
    files = text.split(":", 1)[1].split() if ":" in text else []
    for f in files:
        try:
            if Path(f).stat().st_mtime > t:
                return False
        except FileNotFoundError:
            return False
    return True


def compile_one(src, obj, flags):
    obj.parent.mkdir(parents=True, exist_ok=True)
    cmd = [str(x) for x in (CC, *flags, "-MMD", "-MF", obj.with_suffix(".d"), "-c", "-o", obj, src)]
    sig = hashlib.sha256("\0".join(cmd).encode()).hexdigest()
    if up_to_date(obj, sig):
        return None
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        return f"{src}:\n{r.stderr[-6000:]}"
    obj.with_suffix(".sig").write_text(sig)
    return None


def compile_all(jobs):
    errors = []
    with ThreadPoolExecutor(max_workers=JOBS) as pool:
        for e in pool.map(lambda j: compile_one(*j), jobs):
            if e:
                errors.append(e)
    if errors:
        raise CompileError(errors)


def merge_string_tables(res_path):
    """wrc emits one RT_STRING resource per STRINGTABLE statement, so a 16-string block split over two statements
    appears twice (windres would keep only one). Merge such duplicates slot by slot."""
    import struct
    data = res_path.read_bytes()
    entries, off = [], 0
    while off + 8 <= len(data):
        dsize, hsize = struct.unpack_from("<II", data, off)
        header, body = data[off:off + hsize], data[off + hsize:off + hsize + dsize]
        p = off + 8
        ids = []
        for _ in range(2):
            if struct.unpack_from("<H", data, p)[0] == 0xFFFF:
                ids.append(struct.unpack_from("<H", data, p + 2)[0]); p += 4
            else:
                q = p
                while struct.unpack_from("<H", data, q)[0]: q += 2
                ids.append(data[p:q].decode("utf-16-le")); p = q + 2
        p = (p + 3) & ~3
        lang = struct.unpack_from("<IHH", data, p)[2]
        entries.append([ids[0], ids[1], lang, header, body])
        off = (off + hsize + dsize + 3) & ~3
    merged, out = {}, []
    for e in entries:
        key = (e[0], e[1], e[2])
        if e[0] == 6 and key in merged:
            first = merged[key]
            def slots(b):
                res, q = [], 0
                for _ in range(16):
                    n = struct.unpack_from("<H", b, q)[0] if q + 2 <= len(b) else 0
                    res.append(b[q + 2:q + 2 + 2 * n]); q += 2 + 2 * n
                return res
            a, b = slots(first[4]), slots(e[4])
            first[4] = b"".join(struct.pack("<H", len(x or y) // 2) + (x or y) for x, y in zip(a, b))
            continue
        merged[key] = e
        out.append(e)
    blob = bytearray()
    for e in out:
        header = bytearray(e[3])
        struct.pack_into("<I", header, 0, len(e[4]))
        blob += header + e[4]
        while len(blob) % 4:
            blob.append(0)
    res_path.write_bytes(bytes(blob))


def compile_rc(wine, rc, obj, includes, defines):
    """Wine resource script -> .res with Wine's wrc (it understands Wine's .rc extensions) -> COFF with windres."""
    res = obj.with_suffix(".res")
    obj.parent.mkdir(parents=True, exist_ok=True)
    deps = [rc, *rc.parent.glob("*.rgs"), *rc.parent.glob("*.h"), *rc.parent.glob("*.ico"), *rc.parent.glob("*.bmp"),
            *rc.parent.glob("*.cur"), *rc.parent.glob("*.manifest"), *rc.parent.glob("*.idl")]
    if obj.exists() and all(d.stat().st_mtime <= obj.stat().st_mtime for d in deps):
        return obj
    run([wine / "tools/wrc/wrc", "--nostdinc", "-I", rc.parent, *[f"-I{i}" for i in includes], "-I", wine / "include",
         "-D__WINESRC__", "-D_WIN64", "-D__x86_64__", *defines, "-o", res, rc], cwd=rc.parent)
    merge_string_tables(res)
    run([WINDRES, "-J", "res", "-O", "coff", "-i", res, "-o", obj])
    return obj


def makefile_vars(path):
    text = path.read_text().replace("\\\n", " ")
    out = {}
    for m in re.finditer(r"^([A-Z_]+)\s*=\s*(.*)$", text, re.M):
        out[m.group(1)] = m.group(2).split()
    return out


_TOP_VARS = {}


def wine_top_vars(wine):
    """The variables of Wine's configured top-level Makefile (XML2_PE_CFLAGS, datadir, ...): the assignments before
    its first rule, unexpanded."""
    if wine not in _TOP_VARS:
        out = {}
        text = (wine / "Makefile").read_text(errors="replace")
        text = text[:text.find("\nall:")].replace("\\\n", " ")
        for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", text, re.M):
            out[m.group(1)] = m.group(2).strip()
        _TOP_VARS[wine] = out
    return _TOP_VARS[wine]


def expand_make(value, lookup, depth=0):
    """make's recursive $(VAR) / ${VAR} expansion (no functions; an unknown variable expands to nothing)."""
    if depth > 20:
        raise SystemExit(f"recursive make variable in {value!r}")
    return re.sub(r"\$[({]([A-Za-z_][A-Za-z0-9_]*)[)}]",
                  lambda m: expand_make(lookup(m.group(1)), lookup, depth + 1), value).replace("$$", "$")


def makefile_vars_full(path, wine):
    """Every variable of a Wine Makefile.in, including per-file ones (nsembed_EXTRADEFS), expanded the way make does
    (srcdir/top_srcdir as absolute paths, the rest from the configured top-level Makefile), then split into words the
    way the shell running the recipe splits them (so -DINSTALL_DATADIR="\\"${datadir}\\"" gives the argument
    -DINSTALL_DATADIR="/usr/local/share")."""
    text = path.read_text().replace("\\\n", " ")
    local = {m.group(1): m.group(2).strip()
             for m in re.finditer(r"^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", text, re.M)}
    top = wine_top_vars(wine)
    fixed = {"srcdir": str(path.parent), "top_srcdir": str(wine)}

    def lookup(name):
        for table in (fixed, local, top):
            if name in table:
                return table[name]
        return ""
    return {name: shlex.split(expand_make(value, lookup)) for name, value in local.items()}


def file_var(mk, source, name):
    """makedep get_expanded_file_local_var: <obj>_<NAME>, obj = the source name without extension, non-alphanumeric
    characters as '_' (parser.tab.c -> parser_tab_EXTRADEFS)."""
    obj = re.sub(r"\.[^./]*$", "", Path(source).name)
    return mk.get(re.sub(r"[^A-Za-z0-9]", "_", obj) + "_" + name, [])


def source_pragmas(path):
    """The flags of every `#pragma makedep ...` line of a source (makedep parse_pragma_directive)."""
    flags = set()
    for line in path.read_text(errors="replace").splitlines():
        m = re.match(r"\s*#\s*pragma\s+makedep\s+(.*)$", line)
        if m:
            words = m.group(1).split()
            if words and words[0] == "depend":
                continue
            flags.update(words)
    return flags


def is_unix_source(path):
    head = path.read_text(errors="replace")[:4000]
    return "#pragma makedep unix" in head


# ---------------------------------------------------------------- static libraries
def build_static(name, srcs, flags, outdir):
    objs = [outdir / name / (s.stem + "_" + hashlib.sha1(str(s).encode()).hexdigest()[:6] + ".o") for s in srcs]
    compile_all([(s, o, flags) for s, o in zip(srcs, objs)])
    lib = outdir / f"lib{name}.a"
    if not lib.exists() or any(o.stat().st_mtime > lib.stat().st_mtime for o in objs):
        lib.unlink(missing_ok=True)
        run([AR, "rcs", lib, *objs])
    return lib


def crt_flags(wine):
    return [*WINE_CFLAGS, "-U__WINESRC__", "-fno-builtin", "-Wall", "-Werror", "-Wno-unused-function", "-Wno-unused-parameter",
            "-Wno-format", "-Wno-builtin-declaration-mismatch", "-Wno-mismatched-dealloc", "-I", HERE / "crt", "-I", wine / "include",
            "-I", wine / "include/msvcrt"]


def build_runtime(wine):
    """libshzwcrt.a (C runtime), libshzwine0.a (Wine glue: parts of Wine's winecrt0 + Shizuku glue), crt0 object."""
    lib = WOUT / "lib"
    crt_src = sorted((HERE / "crt").glob("wcrt_*.[cS]"))
    crt_src = [s for s in crt_src if s.name not in ("wcrt_startup.c", "wcrt_wstartup.c")]
    shzwcrt = build_static("shzwcrt", crt_src, crt_flags(wine), lib)
    crt0 = lib / "crt0" / "wcrt_startup.o"
    crt0w = lib / "crt0" / "wcrt_wstartup.o"
    compile_all([(HERE / "crt/wcrt_startup.c", crt0, crt_flags(wine)),
                 (HERE / "crt/wcrt_wstartup.c", crt0w, crt_flags(wine))])
    glue_flags = [*WINE_CFLAGS, "-I", wine / "include", "-I", wine / "include/msvcrt"]
    winecrt0 = [wine / "dlls/winecrt0" / f for f in ("debug.c", "delay_load.c", "crt_dllmain.c", "crt_fltused.c",
                                                      "dll_main.c", "dll_canunload.c", "dll_register.c")]
    glue = [*sorted(p for p in (HERE / "glue").glob("*.c") if p.name != "unixcall.c"), *winecrt0]
    shzwine0 = build_static("shzwine0", glue, glue_flags, lib)
    # programs ("kind": "exe"): winecrt0's default main -> WinMain and wmain -> wWinMain, used when the program
    # defines only WinMain/wWinMain (an archive, so a program's own main/wmain wins)
    shzwinexe = build_static("shzwinexe", [wine / "dlls/winecrt0" / f for f in ("exe_main.c", "exe_wmain.c")],
                             glue_flags, lib)
    return {"shzwcrt": shzwcrt, "shzwine0": shzwine0, "crt0": crt0, "crt0w": crt0w, "shzwinexe": shzwinexe,
            "glue_flags": glue_flags}


def build_extlib(tree, wine, name, cfg):
    """A static library from an upstream tree: the SOURCES of its Wine Makefile.in, or an explicit source list. It is
    compiled against Wine's C runtime headers so that it uses the same runtime (wineport/crt) as the DLLs."""
    d = tree / cfg.get("dir", "")
    makedep = cfg.get("makedep") and (d / "Makefile.in").exists()
    if makedep:
        mk = makefile_vars_full(d / "Makefile.in", wine)
    else:
        mk = makefile_vars(d / "Makefile.in") if (d / "Makefile.in").exists() else {}
    srcs = [d / s for s in (cfg.get("sources") or [s for s in mk.get("SOURCES", []) if s.endswith(".c")])]
    flags = [*WINE_CFLAGS, *cfg.get("defines", []), *mk.get("EXTRADEFS", []), "-I", d,
             *[x for i in cfg.get("includes", []) for x in ("-I", tree / i)],
             *[x for i in cfg.get("shizuku_includes", []) for x in ("-I", HERE / i)], "-I", wine / "include",
             "-I", wine / "include/msvcrt", "-w"]
    if makedep:
        # makedep: EXTRAINCL include directories and -D/-U flags; an EXTLIB (third-party library) is built without
        # __WINESRC__
        inc, defs = extraincl(mk, wine)
        flags += [*[x for i in inc for x in ("-I", i)], *defs, *(["-U__WINESRC__"] if mk.get("EXTLIB") else [])]
    return build_static(name, srcs, flags, WOUT / "lib")


# ---------------------------------------------------------------- dynamic-import thunks
def dynamic_thunks(mod, spec, path):
    """Functions of a DLL the Shizuku runtime may not export: resolved on first call with LoadLibrary/GetProcAddress;
    when absent the call returns the configured failure value (e.g. STATUS_NOT_SUPPORTED) instead of pretending."""
    lines = ["# generated by wineport/build.py: first-call resolution of optional imports", "    .text"]
    data = ["    .data", "    .p2align 3"]
    strs = ["    .section .rdata,\"dr\""]
    dlls = sorted({g["dll"] for g in spec})
    for dll in dlls:
        tag = re.sub(r"\W", "_", dll)
        strs += [f"dll_{tag}: .asciz \"{dll}\""]
    for group in spec:
        tag = re.sub(r"\W", "_", group["dll"])
        for fn in group["functions"]:
            fail = group["fail"]
            lines += [f"    .globl {fn}", f"    .def {fn}; .scl 2; .type 32; .endef", f"{fn}:",
                      f"    jmp *ptr_{fn}(%rip)",
                      f"resolve_{fn}:",
                      "    pushq %rcx", "    pushq %rdx", "    pushq %r8", "    pushq %r9",
                      "    subq $104, %rsp",
                      "    movdqu %xmm0, 32(%rsp)", "    movdqu %xmm1, 48(%rsp)", "    movdqu %xmm2, 64(%rsp)",
                      "    movdqu %xmm3, 80(%rsp)",
                      f"    leaq name_{fn}(%rip), %rcx", f"    leaq dll_{tag}(%rip), %rdx", f"    leaq ptr_{fn}(%rip), %r8",
                      f"    leaq fail_{fn}(%rip), %r9", "    call shzw_dyn_resolve",
                      "    movdqu 32(%rsp), %xmm0", "    movdqu 48(%rsp), %xmm1", "    movdqu 64(%rsp), %xmm2",
                      "    movdqu 80(%rsp), %xmm3",
                      "    addq $104, %rsp", "    popq %r9", "    popq %r8", "    popq %rdx", "    popq %rcx",
                      f"    jmp *ptr_{fn}(%rip)", f"fail_{fn}:"]
            value = int(str(fail), 0)
            if 0 <= value <= 0xffffffff:
                lines += [f"    movl ${fail}, %ecx", "    jmp shzw_dyn_fail"]
            else:            # a 64-bit or negative failure value (e.g. -1 = INVALID_HANDLE_VALUE): returned directly
                lines += ["    subq $40, %rsp", "    movl $127, %ecx", "    call *__imp_SetLastError(%rip)",
                          "    addq $40, %rsp", f"    movabsq ${value & 0xffffffffffffffff:#x}, %rax", "    ret"]
            data += [f"ptr_{fn}: .quad resolve_{fn}", f"    .globl __imp_{fn}", f"__imp_{fn}: .quad {fn}"]
            strs += [f"name_{fn}: .asciz \"{fn}\""]
    path.write_text("\n".join(lines + data + strs) + "\n")
    return path


# ---------------------------------------------------------------- makedep modules: generated sources
IDL_OUTPUTS = (("typelib", "_l.res"), ("regtypelib", "_t.res"), ("register", "_r.res"), ("ident", "_i.c"),
               ("client", "_c.c"), ("server", "_s.c"))
IDL_FLAGS = {"header", "proxy", "client", "server", "ident", "typelib", "register", "regtypelib", "winmd", "install",
             "testdll"}

# `#pragma makedep proxy`: Wine compiles widl's <idl>_p.c (NDR proxies/stubs) and a dlldata.c whose entry points
# (ENTRY_PREFIX DllMain/DllGetClassObject/DllCanUnloadNow/DllRegisterServer/DllUnregisterServer, hProxyDll) the
# module calls. The Shizuku rpcrt4 has no NDR engine, so the proxy code is not generated; this dlldata.c keeps the
# entry points (compiled with the module's dlldata_EXTRADEFS, like Wine's) and serves no proxy/stub class.
DLLDATA_SHIM = r"""/* generated by wineport/build.py: dlldata.c of %(module)s for the widl proxy of %(idls)s, without the NDR
 * proxy/stub code (<idl>_p.c is not built: the Shizuku rpcrt4 has no NDR engine, so these interfaces cannot be
 * marshaled and the proxy/stub factory class is not served). The entry points match rpcproxy.h DLLDATA_ROUTINES:
 * DllMain records hProxyDll; with WINE_REGISTER_DLL, DllRegisterServer/DllUnregisterServer process the module's
 * WINE_REGISTRY resources. */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "objbase.h"
#include "rpcproxy.h"

HRESULT WINAPI DLLGETCLASSOBJECT_ENTRY(REFCLSID rclsid, REFIID riid, void **ppv);
HRESULT WINAPI DLLGETCLASSOBJECT_ENTRY(REFCLSID rclsid, REFIID riid, void **ppv)
{
    *ppv = NULL;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT WINAPI DLLCANUNLOADNOW_ENTRY(void);
HRESULT WINAPI DLLCANUNLOADNOW_ENTRY(void)
{
    return S_OK;
}

#if defined(REGISTER_PROXY_DLL) || defined(WINE_REGISTER_DLL)
HINSTANCE hProxyDll = NULL;

BOOL WINAPI DLLMAIN_ENTRY(HINSTANCE inst, DWORD reason, LPVOID reserved);
BOOL WINAPI DLLMAIN_ENTRY(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(inst);
        hProxyDll = inst;
    }
    return TRUE;
}

HRESULT WINAPI DLLREGISTERSERVER_ENTRY(void);
HRESULT WINAPI DLLREGISTERSERVER_ENTRY(void)
{
#ifdef WINE_REGISTER_DLL
    return __wine_register_resources();
#else
    return S_OK;  /* no proxies to register */
#endif
}

HRESULT WINAPI DLLUNREGISTERSERVER_ENTRY(void);
HRESULT WINAPI DLLUNREGISTERSERVER_ENTRY(void)
{
#ifdef WINE_REGISTER_DLL
    return __wine_unregister_resources();
#else
    return S_OK;
#endif
}
#endif
"""


def extraincl(mk, wine):
    """makedep load_sources: the include directories (relative ones are relative to the top of the tree, "./"
    stripped) and the -D/-U flags of EXTRAINCL."""
    inc, defs = [], []
    for arg in mk.get("EXTRAINCL", []):
        if arg.startswith("-I"):
            p = arg[2:]
            while p.startswith("./"):
                p = p[2:].lstrip("/")
            path = Path(p) if os.path.isabs(p) else wine / p
            if path not in inc:
                inc.append(path)
        elif arg.startswith(("-D", "-U")) and arg not in defs:
            defs.append(arg)
    return inc, defs


def generate(cmd, outputs, deps, cwd=None):
    """Run a source generator (widl, bison, flex, wrc) unless its outputs exist, were made by the same command and
    are newer than every input. A failure is reported like a compilation error."""
    cmd = [str(x) for x in cmd]
    if not shutil.which(cmd[0]):
        raise SystemExit(f"required tool missing: {cmd[0]}")
    sig = hashlib.sha256("\0".join(cmd).encode()).hexdigest()
    stamp = Path(str(outputs[0]) + ".sig")
    if stamp.exists() and stamp.read_text() == sig and all(o.exists() for o in outputs):
        t = min(o.stat().st_mtime for o in outputs)
        if all(Path(x).stat().st_mtime <= t for x in deps if Path(x).exists()):
            return False
    for o in outputs:
        o.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        for o in outputs:
            o.unlink(missing_ok=True)
        raise CompileError([f"{' '.join(cmd)}:\n{(r.stdout + r.stderr)[-6000:]}"])
    stamp.write_text(sig)
    return True


_INCLUDE_RE = re.compile(r'^\s*(?:import\s+"([^"]+)"|#\s*include\s*[<"]([^>"]+)[>"]|importlib\s*\(\s*"([^"]+)")',
                         re.M)
_SCANNED = {}


def scanned_includes(path):
    """The names a source imports/includes (idl import and importlib, cpp #include), cached."""
    if path not in _SCANNED:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            text = ""
        _SCANNED[path] = [a or b or c for a, b, c in _INCLUDE_RE.findall(text)]
    return _SCANNED[path]


def include_closure(path, dirs):
    """Every file a widl input reads (imports, includes, importlibs, recursively), resolved like widl's preprocessor:
    the including file's directory, then the search path."""
    seen, stack, out = {path}, [path], []
    while stack:
        p = stack.pop()
        for name in scanned_includes(p):
            for base in (p.parent, *dirs):
                q = base / name
                if q.is_file():
                    if q not in seen:
                        seen.add(q)
                        out.append(q)
                        if q.suffix in (".idl", ".h", ".inl", ".acf", ".rh"):
                            stack.append(q)
                    break
    return out


def concat_res(parts, out):
    """Several .res files as one (one leading empty entry, then every resource of every file), so that the module
    gets a single resource object, as winebuild links all of a module's .res files into one resource directory."""
    import struct
    blob = bytearray(struct.pack("<IIHHHHIHHII", 0, 32, 0xFFFF, 0, 0xFFFF, 0, 0, 0, 0, 0, 0))
    for part in parts:
        data = part.read_bytes()
        off = 0
        while off + 8 <= len(data):
            dsize, hsize = struct.unpack_from("<II", data, off)
            end = off + hsize + dsize
            if not (dsize == 0 and data[off + 8:off + 12] == b"\xff\xff\x00\x00"):
                blob += data[off:end]
                while len(blob) % 4:
                    blob.append(0)
            off = (end + 3) & ~3
    out.write_bytes(bytes(blob))


def ensure_wmc(wine):
    """Wine's message compiler, built with the host compiler into wineport/tools/wmc (the host configuration builds
    only widl and wrc): tools/wmc sources, mcy.y through bison, wmc_EXTRADEFS. Like makedep's rule for this
    configuration, wmc runs without --po-dir: po/ is in DISABLED_SUBDIRS (MSGFMT = false), so LINGUAS is empty."""
    out = WOUT / "tools" / "wmc"
    exe = out / "wmc"
    d = wine / "tools/wmc"
    y = d / "mcy.y"
    generate([BISON, "-o", out / "mcy.tab.c", y], [out / "mcy.tab.c"], [y])
    generate([BISON, "-o", out / "mcy.tab.hdr.c", f"--defines={out / 'mcy.tab.h'}", y], [out / "mcy.tab.h"], [y])
    (out / "mcy.tab.hdr.c").unlink(missing_ok=True)
    mk = makefile_vars_full(d / "Makefile.in", wine)
    srcs = [d / s for s in mk.get("SOURCES", []) if s.endswith(".c")]
    generate([HOSTCC, "-O2", "-o", exe, "-I", out, "-I", d, "-I", wine / "include", "-D__WINESRC__", "-DWINE_UNIX_LIB",
              *file_var(mk, "wmc.c", "EXTRADEFS"), *srcs, out / "mcy.tab.c"],
             [exe], [*srcs, out / "mcy.tab.c", out / "mcy.tab.h", *d.glob("*.h"), wine / "tools/tools.h"])
    return exe


class Makedep:
    """Wine makedep's rules (tools/makedep.c) for one directory of the Wine tree: include path and defines
    (load_sources, get_source_defines), and the sources it generates (add_generated_sources, output_source_idl,
    output_source_y, output_source_l, output_source_rc). Generated files go to GEN/<directory>."""

    def __init__(self, wine, d, m=None):
        self.wine, self.d, self.m = wine, d, m or {}
        self.mk = makefile_vars_full(d / "Makefile.in", wine) if (d / "Makefile.in").exists() else {}
        self.gen = GEN / d.relative_to(wine)
        parent = self.mk.get("PARENTSRC")
        self.parent = Path(os.path.normpath(d / parent[0])) if parent else None
        self.inc_extra, self.def_extra = extraincl(self.mk, wine)
        self._included = None

    def find(self, name):
        """A SOURCES entry: in the directory, else in PARENTSRC."""
        p = self.d / name
        if not p.exists() and self.parent and (self.parent / name).exists():
            return self.parent / name
        return p

    def search_path(self, extra=True):
        """-I order of makedep: object (generated) directory, source directory, PARENTSRC, include/,
        include/msvcrt, EXTRAINCL directories; for C files (extra) the module's modules.json includes come before
        include/."""
        mine = [*[self.wine / i for i in self.m.get("includes", [])],
                *[HERE / i for i in self.m.get("shizuku_includes", [])]] if extra else []
        return [self.gen, self.d, *([self.parent] if self.parent else []), *mine,
                self.wine / "include", self.wine / "include/msvcrt", *self.inc_extra]

    def tool_defines(self, source):
        """get_source_defines for widl/wrc: include path, -D_UCRT, -D__WINESRC__, EXTRAINCL -D/-U, EXTRADEFS,
        <obj>_EXTRADEFS (Makefile.in only, so a directory's outputs do not depend on which module asks for them)."""
        return [*[f"-I{i}" for i in self.search_path(False)], "-D_UCRT", "-D__WINESRC__", *self.def_extra,
                *self.mk.get("EXTRADEFS", []), *file_var(self.mk, source, "EXTRADEFS")]

    def cflags(self, source):
        return [*WINE_CFLAGS, *[x for i in self.search_path() for x in ("-I", i)], *self.def_extra,
                *self.mk.get("EXTRADEFS", []), *self.m.get("defines", []), *file_var(self.mk, source, "EXTRADEFS")]

    def included(self, name):
        """makedep find_include_file: does any source or header of the directory include this file name?"""
        if self._included is None:
            names = set()
            for base in (self.d, self.parent):
                if base and base.is_dir():
                    for f in base.iterdir():
                        if f.suffix in (".c", ".h", ".rc", ".idl", ".y", ".l", ".inl"):
                            names.update(Path(n).name for n in scanned_includes(f))
            self._included = names
        return name in self._included

    def widl(self, idl, out_name):
        """widl -o <out> with makedep's arguments; run in GEN with a relative output path, as makedep runs it from
        the top of the tree (the path is the name of a typelib's registration resource)."""
        out = self.gen / out_name
        widl = self.wine / "tools/widl/widl"
        cmd = [widl, "-o", out.relative_to(GEN), "-m64", "--nostdinc", f"-L{TLBDIR}", *self.tool_defines(idl.name),
               *self.mk.get("EXTRAIDLFLAGS", []), *file_var(self.mk, idl.name, "EXTRAIDLFLAGS"), idl]
        generate(cmd, [out], [widl, idl, *include_closure(idl, [*self.search_path(False), TLBDIR])], cwd=GEN)
        return out

    def bison(self, y):
        """<name>.tab.c (bison -o), and <name>.tab.h if something includes it (a second run with --defines)."""
        stem = y.name[:-2]
        c = self.gen / f"{stem}.tab.c"
        generate([BISON, "-o", c, y], [c], [y])
        if self.included(f"{stem}.tab.h"):
            h, tmp = self.gen / f"{stem}.tab.h", self.gen / f"{stem}.tab.hdr.c"
            generate([BISON, "-o", tmp, f"--defines={h}", y], [h], [y])
            tmp.unlink(missing_ok=True)
        return c

    def flex(self, lex):
        c = self.gen / f"{lex.name[:-2]}.yy.c"
        generate([FLEX, f"-o{c}", lex], [c], [lex])
        return c

    def foreign_headers(self):
        """Headers generated in another directory that this one includes as "../<dir>/<name>.h" (mshtml includes
        ../jscript/jsdisp.h): made there with that directory's rules, so -I<gen dir> resolves them."""
        for base in (self.d, self.parent):
            if not (base and base.is_dir()):
                continue
            for f in base.iterdir():
                if f.suffix not in (".c", ".h", ".rc", ".idl"):
                    continue
                for name in scanned_includes(f):
                    if not name.startswith("../") or not name.endswith(".h"):
                        continue
                    target = Path(os.path.normpath(f.parent / name))
                    idl = target.with_suffix(".idl")
                    if not target.exists() and idl.is_file() and self.wine in idl.parents:
                        Makedep(self.wine, idl.parent).widl(idl, target.name)

    def generate_sources(self, sources, obj_dir, notes):
        """Every generated file of the module: returns (C sources to compile, .res files to link)."""
        csrcs, res = [], []
        self.foreign_headers()
        idls = [self.find(s) for s in sources if s.endswith(".idl")]
        for idl in idls:                                     # headers first: the other outputs may include them
            flags = source_pragmas(idl)
            if "header" in flags or not (flags & IDL_FLAGS) or self.included(idl.stem + ".h"):
                self.widl(idl, idl.stem + ".h")
        proxies = []
        for idl in idls:
            flags = source_pragmas(idl)
            for flag, ext in IDL_OUTPUTS:
                if flag in flags:
                    out = self.widl(idl, idl.stem + ext)
                    (res if ext.endswith(".res") else csrcs).append(out)
            if "proxy" in flags:
                proxies.append(idl.name)
        for s in sources:
            src = self.find(s)
            if s.endswith(".c"):
                if "unix" not in source_pragmas(src):        # the Unix side of a module is not built
                    csrcs.append(src)
            elif s.endswith(".y"):
                csrcs.append(self.bison(src))
            elif s.endswith(".l"):
                csrcs.append(self.flex(src))
            elif s.endswith(".mc"):                             # message table: wmc -u -o <obj>.res
                wmc = ensure_wmc(self.wine)
                out = obj_dir / (src.stem + ".res")
                generate([wmc, "-u", "-o", out, f"--nls-dir={self.wine / 'nls'}", src], [out], [wmc, src])
                res.append(out)
            elif not s.endswith((".idl", ".rc", ".h", ".svg", ".spec")):
                notes.setdefault("ignored_sources", []).append(s)
        if proxies:
            shim = self.gen / "dlldata.c"
            text = DLLDATA_SHIM % {"module": self.d.relative_to(self.wine), "idls": ", ".join(proxies)}
            if not shim.exists() or shim.read_text() != text:
                shim.parent.mkdir(parents=True, exist_ok=True)
                shim.write_text(text)
            csrcs.append(shim)
        return csrcs, res

    def resources(self, sources, widl_res, obj_dir):
        """wrc (-u, makedep's defines) for every .rc that is not a `#pragma makedep header` include, then all .res
        files (wrc, widl, wmc) merged into one COFF object with windres. No --po-dir, as in makedep's rule for this
        configuration (po/ is in DISABLED_SUBDIRS, so LINGUAS is empty): the resources are the English ones."""
        parts = []
        wrc = self.wine / "tools/wrc/wrc"
        for s in sources:
            if not s.endswith(".rc"):
                continue
            rc = self.find(s)
            if "header" in source_pragmas(rc):
                continue
            out = obj_dir / (rc.stem + ".res")
            deps = [p for base in (rc.parent, self.gen) if base.is_dir() for p in base.iterdir() if p.is_file()]
            generate([wrc, "-u", "-o", out, "--nostdinc", *self.tool_defines(rc.name), "-D_WIN64", "-D__x86_64__",
                      *self.m.get("defines", []), rc], [out], [wrc, *deps], cwd=rc.parent)
            parts.append(out)
        parts += widl_res
        if not parts:
            return None
        combined, obj = obj_dir / "resources.res", obj_dir / "resources_rc.o"
        sig = "\n".join(map(str, parts))
        stamp = obj.with_suffix(".sig")
        if (obj.exists() and stamp.exists() and stamp.read_text() == sig
                and all(p.stat().st_mtime <= obj.stat().st_mtime for p in parts)):
            return obj
        concat_res(parts, combined)
        merge_string_tables(combined)
        run([WINDRES, "-J", "res", "-O", "coff", "-i", combined, "-o", obj])
        stamp.write_text(sig)
        return obj


def build_typelib(wine, m):
    """"kind": "typelib": a data-only Wine module (EXTRADLLFLAGS -Wb,--data-only) holding one type library, made as
    the raw MSFT file widl -t writes (the bytes Wine puts in the module's TYPELIB resource; the Shizuku LoadLibraryEx
    cannot map PE data files). Also the importlib() search path of every later widl run."""
    md = Makedep(wine, wine / m["dir"], m)
    idls = [md.find(s) for s in md.mk.get("SOURCES", []) if s.endswith(".idl")]
    if len(idls) != 1:
        raise SystemExit(f"{m['name']}: a typelib module needs exactly one .idl in SOURCES, found {len(idls)}")
    module = (md.mk.get("MODULE") or [f"{m['name']}.tlb"])[0]
    out = TLBDIR / module
    widl = wine / "tools/widl/widl"
    generate([widl, "-o", out, "-m64", "--nostdinc", f"-L{TLBDIR}", *md.tool_defines(idls[0].name), idls[0]],
             [out], [widl, idls[0], *include_closure(idls[0], [*md.search_path(False), TLBDIR])])
    return {"kind": "typelib", "tlb": out, "image_path": m["image_path"], "size": out.stat().st_size,
            "idl": str(idls[0].relative_to(wine))}


# ---------------------------------------------------------------- modules
def symbols_defined(objs, libs=()):
    r = subprocess.run([NM, "--defined-only", "-g", *map(str, objs)], capture_output=True, text=True)
    names = {l.split()[-1] for l in r.stdout.splitlines() if len(l.split()) >= 3}
    return names


def def_exports(path):
    names = set()
    if path.exists():
        for line in path.read_text().splitlines()[2:]:
            tok = line.split()
            if tok:
                names.add(tok[0])
    return names


def import_lib_available(lib, dirs):
    return any((d / f"lib{lib}.a").exists() for d in dirs)


def build_module(wine, rt, m, base, provided, trees, probe=False, notes=None):
    """One Wine DLL ("kind": "dll", the default) or program ("kind": "exe"). notes (a dict) receives what a probe
    report needs: import libraries left out of the link, sources that could not be built."""
    name = m["name"]
    kind = m.get("kind", "dll")
    notes = {} if notes is None else notes
    d = wine / m.get("dir", f"dlls/{name}")
    obj_dir = WOUT / "obj" / name
    # a probe build of a disabled module writes its .def, binary and import library aside, so that the outputs the
    # enabled configuration makes (and the export lists later modules see) stay as they are
    out = WOUT / "probe" if probe and m.get("disabled") else OUT
    out.mkdir(parents=True, exist_ok=True)
    if m.get("makedep"):
        md = Makedep(wine, d, m)
        mk = md.mk
        sources = m.get("sources")
        if sources is None:
            sources = [s for s in mk.get("SOURCES", []) if s not in m.get("exclude_sources", {})]
        if m.get("exclude_sources"):
            notes["excluded_sources"] = m["exclude_sources"]
        srcs, widl_res = md.generate_sources(sources, obj_dir, notes)
        srcs += [wine / s for s in m.get("extra_sources", [])] + [HERE / s for s in m.get("shizuku_sources", []) if s.endswith(".c")]
        objs = [obj_dir / (s.stem + "_" + hashlib.sha1(str(s).encode()).hexdigest()[:6] + ".o") for s in srcs]
        unixcall_obj = obj_dir / "shzw_unixcall.o"
        compile_all([*[(s, o, md.cflags(s.name)) for s, o in zip(srcs, objs)],
                     (HERE / "glue/unixcall.c", unixcall_obj, rt["glue_flags"])])
        res_obj = md.resources(sources, widl_res, obj_dir)
        objs += [unixcall_obj, *([res_obj] if res_obj else [])]
    else:
        mk = makefile_vars(d / "Makefile.in") if (d / "Makefile.in").exists() else {}
        sources = m.get("sources")
        if sources is None:
            sources = [s for s in mk.get("SOURCES", []) if s not in m.get("exclude_sources", {})]
        srcs = [d / s for s in sources if s.endswith(".c") and not is_unix_source(d / s)]
        srcs += [wine / s for s in m.get("extra_sources", [])]
        srcs += [HERE / s for s in m.get("shizuku_sources", []) if s.endswith(".c")]
        rcs = [d / s for s in sources if s.endswith(".rc")] + [HERE / s for s in m.get("shizuku_sources", []) if s.endswith(".rc")]
        includes = [d, *[wine / i for i in m.get("includes", [])], *[HERE / i for i in m.get("shizuku_includes", [])]]
        defines = [*mk.get("EXTRADEFS", []), *m.get("defines", [])]
        flags = [*WINE_CFLAGS, *defines, *[x for i in includes for x in ("-I", i)], "-I", wine / "include",
                 "-I", wine / "include/msvcrt"]
        objs = [obj_dir / (s.stem + "_" + hashlib.sha1(str(s).encode()).hexdigest()[:6] + ".o") for s in srcs]
        # former Unix-side sources ported to PE by the module's patches (m["unix_inproc"]): built with their own
        # includes
        usrcs = [d / s for s in m.get("unix_sources", [])]
        uflags = [*flags, *m.get("unix_defines", []),
                  *[x for i in m.get("unix_includes", []) for x in ("-I", trees[i["upstream"]] / i["path"])]]
        uobjs = [obj_dir / ("unix_" + s.stem + ".o") for s in usrcs]
        unixcall_obj = obj_dir / "shzw_unixcall.o"
        ucflags = [*rt["glue_flags"], *(["-DSHZW_UNIX_INPROC"] if m.get("unix_inproc") else [])]
        compile_all([*zip(srcs, objs, [flags] * len(srcs)), *zip(usrcs, uobjs, [uflags] * len(usrcs)),
                     (HERE / "glue/unixcall.c", unixcall_obj, ucflags)])
        objs += [*uobjs, unixcall_obj]
        for rc in rcs:
            objs.append(compile_rc(wine, rc, obj_dir / (rc.stem + "_rc.o"), includes, defines))
    if m.get("dynamic_imports"):
        s = dynamic_thunks(name, m["dynamic_imports"], obj_dir / "dynimports.S")
        o = obj_dir / "dynimports.o"
        run([CC, "-c", "-o", o, s])
        objs.append(o)

    # exports: the spec minus stubs, restricted to what the objects really define
    spec = HERE / m["shizuku_spec"] if m.get("shizuku_spec") else d / m.get("spec", f"{name}.spec")
    if not spec.exists() and kind == "dll":
        raise SystemExit(f"{name}: no spec file {spec}")
    entries = winespec.parse_spec(spec) if spec.exists() else []
    if m.get("import_as_real"):
        for e in entries:
            if e.kind == "import":
                e.kind = "real"
    # "-import" entries re-export a function of an imported DLL (winebuild makes a thunk): export them as forwarders
    # to the first linked DLL that provides the function
    for e in entries:
        if e.kind == "import":
            target = e.target or e.name
            for lib in [*m.get("link", []), "kernel32", "ntdll"]:
                if target in provided.get(lib, set()):
                    e.kind, e.target = "forward", f"{lib}.{target}"
                    break
    winespec.classify_entries(entries, srcs)
    for e in entries:                                   # real in Wine, but the work is done by the Unix side we lack
        if e.name in m.get("unported", {}):
            e.kind, e.reason = "unported", m["unported"][e.name]
    defined = symbols_defined(objs) | symbols_defined([rt["shzwine0"]])
    for e in entries:
        impl = e.target or e.name
        if e.kind in ("real", "semistub", "unlocated") and impl not in defined:
            e.kind, e.reason = "missing", f"{impl} is not defined by the compiled sources"
        elif e.kind == "unlocated":
            e.kind = "real"

    def forward_ok(target):
        dll, _, fn = target.partition(".")
        return fn in provided.get(dll.lower(), set())

    suffix = ".exe" if kind == "exe" else ".dll"
    lines, kept = winespec.def_lines(f"{name}{suffix}", entries, forward_ok)
    private = {winespec.def_name(e) for e in kept if "private" in e.flags}
    lines = [l + (" PRIVATE" if l.split()[0] in private else "") if l.startswith("  ") else l for l in lines]
    deffile = out / f"{name}.def"
    if entries:
        deffile.write_text("\n".join(lines) + "\n")

    delay_libs = []
    for dl in m.get("delay_imports", []):
        dspec = wine / "dlls" / dl / f"{dl}.spec"
        dents = [e for e in winespec.parse_spec(dspec) if e.kind not in ("stub",) and not e.noname]
        ddef = WOUT / "lib" / f"{dl}_delay.def"
        ddef.write_text(f"LIBRARY {dl}.dll\nEXPORTS\n" + "".join(f"  {e.name}\n" for e in dents if e.name != "@"))
        dlib = WOUT / "lib" / f"lib{dl}_delay.a"
        run([DLLTOOL, "-d", ddef, "-y", dlib])
        delay_libs.append(dlib)

    libdirs = [OUT, WOUT / "lib", *([WOUT / "probe"] if probe else [])]
    link = list(m.get("link", []))
    if probe:                                    # e.g. tridentrt before it exists: report what it has to provide
        notes["missing_import_libs"] = [l for l in link if not import_lib_available(l, libdirs)]
        link = [l for l in link if l not in notes["missing_import_libs"]]
    libs = [f"-l{l}" for l in link]
    statics = [WOUT / "lib" / f"lib{s}.a" for s in m.get("static", [])]
    binary = out / f"{name}{suffix}"
    if kind == "exe":
        # programs/: EXTRADLLFLAGS says GUI (-mwindows) or console (-mconsole) and whether the entry point is the
        # Unicode one (-municode: wmainCRTStartup -> wmain, and winecrt0's wmain -> wWinMain when the program has
        # only wWinMain); other -Wl, flags are passed through, except --large-address-aware, which is an i386 option
        # (a PE32+ image is large-address-aware anyway)
        xflags = [f for f in mk.get("EXTRADLLFLAGS", []) if f != "-Wl,--large-address-aware"]
        unicode = "-municode" in xflags
        subsystem = m.get("subsystem", "console" if "-mconsole" in xflags else "windows")
        entry = m.get("entry", "wmainCRTStartup" if unicode else "mainCRTStartup")
        cmd = [CC, "-nostdlib", f"-Wl,--entry,{entry}", f"-Wl,--subsystem,{subsystem}", "-Wl,--image-base,0x140000000",
               "-Wl,--dynamicbase", "-Wl,--gc-sections", "-Wl,--disable-auto-import",
               *[f for f in xflags if f.startswith("-Wl,")], "-o", binary, rt["crt0w"] if unicode else rt["crt0"],
               *objs, *([deffile] if entries else []), *statics, *[x for l in libdirs for x in ("-L", l)],
               "-Wl,--start-group", rt["shzwinexe"], rt["shzwine0"], rt["shzwcrt"], *delay_libs, "-Wl,--end-group",
               *libs, "-lkernel32", "-lntdll", "-lgcc"]
    else:
        entry = m.get("entry", "DllMainCRTStartup")
        cmd = [CC, "-shared", "-nostdlib", f"-Wl,--entry,{entry}", f"-Wl,--image-base,{base:#x}", "-Wl,--dynamicbase",
               "-Wl,--gc-sections",
               "-Wl,--subsystem,windows", "-Wl,--disable-auto-import", "-o", binary, *objs, deffile,
               *statics, *[x for l in libdirs for x in ("-L", l)],
               "-Wl,--start-group", rt["shzwine0"], rt["shzwcrt"], *delay_libs, "-Wl,--end-group", *libs,
               "-lkernel32", "-lntdll", "-lgcc"]
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if r.returncode:
        undef = sorted(set(re.findall(r"undefined reference to `([^']+)'", r.stderr)))
        if probe and entries:                    # dependants of a probed module link against its exports
            run([DLLTOOL, "-d", deffile, "-l", out / f"lib{name}.a"])
            provided[name] = {winespec.def_name(e) for e in kept}
        raise LinkError(f"link of {binary.name} failed" + (f"; undefined: {' '.join(undef)}" if undef else "") +
                        f"\n{r.stderr[-3000:] if not undef else ''}", undef)
    if entries:
        run([DLLTOOL, "-d", deffile, "-l", out / f"lib{name}.a"])
    provided[name] = {winespec.def_name(e) for e in kept}
    counts = {}
    for e in entries:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    info = {"kind": kind, "binary": binary, "image_path": f"\\SHZ\\SYS64\\{name}{suffix}", "exports": len(kept),
            "counts": counts, "not_exported": [e.as_dict() for e in entries if e not in kept],
            "semistub": [e.name for e in entries if e.kind == "semistub"],
            "sources": [str(s.relative_to(REPO)) for s in srcs], "link": [str(x) for x in cmd], **notes}
    if kind == "dll":
        info = {"dll": binary, "base": hex(base), **info}
    return info


# ---------------------------------------------------------------- Wine conformance tests
DRIVER = r'''/* generated by wineport/build.py: Wine test driver for %(name)s (selected subtests) */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#define STANDALONE
#define main winetest_main
#include "wine/test.h"
#undef main
%(externs)s
const struct test winetest_testlist[] = {
%(entries)s    { 0, 0 }
};
static const char *selected[64] = { %(selected)s NULL };
static char cfg_line[1024];

/* WINETEST.TXT next to the program (written by wineport/run_wine_tests.py) may replace the subtest list
 * ("%(name)s sub1 sub2 ...") and set WINEDEBUG for the children ("WINEDEBUG +crypt"). */
static void read_config(const char *self)
{
    char path[MAX_PATH], line[1024], *p;
    FILE *f;
    strcpy(path, self);
    if ((p = strrchr(path, '\\'))) p[1] = 0; else path[0] = 0;
    strcat(path, "WINETEST.TXT");
    if (!(f = fopen(path, "r"))) return;
    while (fgets(line, sizeof line, f)) {
        size_t n = strlen(line);
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
        if (!strncmp(line, "WINEDEBUG ", 10)) {
            /* children do not inherit the environment on Shizuku: winecrt0 also reads HKCU\\Software\\Wine\\Debug */
            HMODULE adv = LoadLibraryA("advapi32.dll");
            LONG (WINAPI *create)(HKEY, LPCSTR, DWORD, LPSTR, DWORD, REGSAM, void *, HKEY *, DWORD *) =
                adv ? (void *)GetProcAddress(adv, "RegCreateKeyExA") : NULL;
            LONG (WINAPI *set)(HKEY, LPCSTR, DWORD, DWORD, const BYTE *, DWORD) =
                adv ? (void *)GetProcAddress(adv, "RegSetValueExA") : NULL;
            HKEY key;
            SetEnvironmentVariableA("WINEDEBUG", line + 10);
            if (create && set && !create(HKEY_CURRENT_USER, "Software\\Wine\\Debug", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &key, NULL))
                set(key, "WINEDEBUG", 0, REG_SZ, (const BYTE *)line + 10, (DWORD)strlen(line + 10) + 1);
        }
        else if (!strncmp(line, "%(name)s ", sizeof("%(name)s ") - 1)) {
            unsigned k = 0;
            strcpy(cfg_line, line + sizeof("%(name)s ") - 1);
            for (p = strtok(cfg_line, " "); p && k < 63; p = strtok(NULL, " ")) selected[k++] = p;
            selected[k] = NULL;
        }
    }
    fclose(f);
}

/* No argument (how the Shizuku kernel starts T_*.EXE): run every selected subtest in its own child process, the way
 * Wine's winetest runs them, with a per-subtest time limit; exit 0 only if all of them exit 0. */
int main(int argc, char **argv)
{
    char self[MAX_PATH], cmd[MAX_PATH + 64];
    unsigned i, failed = 0, n = 0;
    /* The code under test is Wine's: its known deviations (todo_wine) are expected, as when winetest runs on Wine.
     * Child processes do not inherit the environment on Shizuku, so every process of the test sets it up itself. */
    GetModuleFileNameA(NULL, self, sizeof self);
    if (!GetEnvironmentVariableA("WINETEST_PLATFORM", cmd, sizeof cmd)) SetEnvironmentVariableA("WINETEST_PLATFORM", "wine");
    read_config(self);
    /* a Windows installation has its TEMP directory; the Shizuku file system starts without one */
    if (GetTempPathA(sizeof cmd, cmd) && GetFileAttributesA(cmd) == INVALID_FILE_ATTRIBUTES) CreateDirectoryA(cmd, NULL);
    if (argc > 1) return winetest_main(argc, argv);
    for (i = 0; selected[i]; i++) {
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        DWORD code = 0xdead, w;
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        sprintf(cmd, "\"%%s\" %%s", self, selected[i]);
        n++;
        if (!CreateProcessA(self, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            printf("wineport:%(name)s:%%s: CreateProcess failed %%lu\n", selected[i], GetLastError());
            failed++;
            continue;
        }
        w = WaitForSingleObject(pi.hProcess, %(timeout)d);
        if (w == WAIT_TIMEOUT) { TerminateProcess(pi.hProcess, 0x102); WaitForSingleObject(pi.hProcess, 5000); }
        GetExitCodeProcess(pi.hProcess, &code);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        printf("wineport:%(name)s:%%s: %%s (exit %%lu)\n", selected[i], w == WAIT_TIMEOUT ? "TIMEOUT" : code ? "FAIL" : "PASS", code);
        if (w == WAIT_TIMEOUT || code) failed++;
    }
    printf("wineport:%(name)s: %%u of %%u subtests passed\n", n - failed, n);
    return failed ? 1 : 0;
}
'''


def build_test_exe(wine, rt, name, exe_name, d, sources, subtests, t, extra_includes=(), label=None):
    mk = makefile_vars(d / "Makefile.in") if (d / "Makefile.in").exists() else {}
    names = [Path(s).stem for s in sources]
    obj_dir = WOUT / "obj" / exe_name.lower()
    # Wine builds its tests against msvcrt, whose wcstok takes two arguments; the UCRT headers used here provide that
    # form with _CRT_NON_CONFORMING_WCSTOK
    flags = [*WINE_CFLAGS, "-D_CRT_NON_CONFORMING_WCSTOK", *mk.get("EXTRADEFS", []), "-I", d,
             *[x for i in extra_includes for x in ("-I", i)],
             "-I", wine / "include", "-I", wine / "include/msvcrt", *t.get("defines", [])]
    srcs = [d / s for s in sources if Path(s).stem in subtests]
    drv = obj_dir / "driver.c"
    obj_dir.mkdir(parents=True, exist_ok=True)
    text = DRIVER % {
        "name": label or name,
        "externs": "\n".join(f"extern void func_{n}(void);" for n in names if n in subtests),
        "entries": "".join(f'    {{ "{n}", func_{n} }},\n' for n in names if n in subtests),
        "selected": " ".join(f'"{n}",' for n in subtests),
        "timeout": int(t.get("timeout_ms", 25000))}
    if not drv.exists() or drv.read_text() != text:
        drv.write_text(text)
    objs = [obj_dir / (s.stem + ".o") for s in srcs] + [obj_dir / "driver.o"]
    compile_all([*zip(srcs, objs[:-1], [flags] * len(srcs)), (drv, objs[-1], flags)])
    for rc in [d / s for s in mk.get("SOURCES", []) if s.endswith(".rc")]:
        objs.append(compile_rc(wine, rc, obj_dir / (rc.stem + "_rc.o"), [d], []))
    if t.get("dynamic_imports"):
        dyn = dynamic_thunks(name, t["dynamic_imports"], obj_dir / "dynimports.S")
        run([CC, "-c", "-o", obj_dir / "dynimports.o", dyn])
        objs.append(obj_dir / "dynimports.o")
    exe = WOUT / exe_name
    cmd = [CC, "-nostdlib", "-Wl,--entry,mainCRTStartup", "-Wl,--subsystem,console", "-Wl,--image-base,0x140000000",
           "-Wl,--dynamicbase", "-Wl,--disable-auto-import", "-o", exe, rt["crt0"], *objs,
           *[WOUT / "lib" / f"lib{x}.a" for x in t.get("static", [])], "-L", OUT, "-L", WOUT / "lib",
           "-Wl,--start-group", rt["shzwine0"], rt["shzwcrt"], "-Wl,--end-group",
           *[f"-l{l}" for l in t.get("link", [])], "-lkernel32", "-lntdll", "-lgcc"]
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if r.returncode:
        undef = sorted(set(re.findall(r"undefined reference to `([^']+)'", r.stderr)))
        raise SystemExit(f"link of {exe.name} failed" + (f"; undefined: {' '.join(undef)}" if undef else f"\n{r.stderr[-3000:]}"))
    return {"exe": exe, "subtests": subtests, "all_subtests": names, "in_plain_image": bool(t.get("in_plain_image")),
            "sources": [str(s.relative_to(REPO)) for s in srcs]}


def build_tests(wine, rt, m):
    """Wine's conformance tests of a module (T_WINE_<NAME>.EXE) and, if configured, the Shizuku checks written with
    Wine's test framework under wineport/tests/<name>/ (T_WP_<NAME>.EXE)."""
    out = {}
    t = m["tests"]
    name = m["name"]
    if "subtests" in t:                                  # a Shizuku-original module has no Wine tests
        d = wine / t.get("dir", f"dlls/{name}/tests")
        srcs = [s for s in makefile_vars(d / "Makefile.in").get("SOURCES", []) if s.endswith(".c")]
        out[f"wine_{name}"] = build_test_exe(wine, rt, name, f"T_WINE_{name.upper()}.EXE", d, srcs, t["subtests"], t)
    if t.get("shizuku"):
        st = {**t, **t["shizuku"]}
        sd = HERE / "tests" / name
        ssrcs = sorted(p.name for p in sd.glob("*.c"))
        out[f"wp_{name}"] = build_test_exe(wine, rt, name, f"T_WP_{name.upper()}.EXE", sd, ssrcs,
                                           st.get("subtests", [Path(s).stem for s in ssrcs]), st, label=f"wp_{name}")
        # MSFT type libraries the checks load, built with widl -t from Wine IDL files ({image path: idl})
        data = []
        for image_path, idl in st.get("typelibs", {}).items():
            tlb = WOUT / "obj" / f"t_wp_{name}.exe" / Path(image_path.replace("\\", "/")).name
            tlb.parent.mkdir(parents=True, exist_ok=True)
            run([wine / "tools/widl/widl", "-o", tlb, "-m64", "--nostdinc", "-I", (wine / idl).parent, "-I", wine / "include",
                 "-I", wine / "include/msvcrt", "-D_UCRT", "-D__WINESRC__", "-t", wine / idl])
            data.append((image_path, str(tlb)))
        out[f"wp_{name}"]["data"] = data
    return out


# ---------------------------------------------------------------- entry points
def build(only=None):
    """Build every configured module; returns {"modules": {name: info}, "tests": {name: info}, "files": [(img path, bytes)]}."""
    cfg = json.loads(CONFIG.read_text())
    trees = {}
    for up in cfg.get("upstreams", ["wine"]):
        trees[up] = ensure_tree(up)
    wine = trees["wine"]
    ensure_wine_host(wine, wine_keep_paths(cfg))
    patches = {up: apply_patches(up, tree) for up, tree in trees.items()}
    WOUT.mkdir(parents=True, exist_ok=True)
    (WOUT / "lib").mkdir(exist_ok=True)
    rt = build_runtime(wine)
    probe = os.environ.get("SHZ_WINEPORT_PROBE")          # report every module's unresolved imports, do not stop
    # "placeholder": true reserves a module's place (and its checkout) for work defined elsewhere: never built, not
    # even by a probe (its "dir" is only what the sparse checkout keeps)
    selected = [m for m in cfg["modules"] if m.get("kind") != "typelib" and not m.get("placeholder")
                and not (only and m["name"] not in only) and not (m.get("disabled") and not probe)]
    needed = {s for m in selected for s in m.get("static", [])}
    modules, tests, typelibs, probe_info = {}, {}, {}, {}
    for name, lcfg in cfg.get("static_libs", {}).items():
        if lcfg.get("on_demand") and name not in needed:  # built only for a module that links it
            continue
        try:
            build_extlib(trees[lcfg.get("upstream", "wine")], wine, name, lcfg)
        except SystemExit as e:
            if not probe:
                raise
            print(f"PROBE static {name}: {str(e)[:4000]}")
            probe_info[f"static:{name}"] = {"result": "compilation failed",
                                            "compile_errors": len(getattr(e, "errors", [None])),
                                            "errors": getattr(e, "errors", [str(e)])}
    # export lists for the forward checks: the Shizuku DLLs and enabled Wine modules (OUT). A probe build never
    # writes to OUT, so an OUT/<name>.def of a disabled Wine module that is not also a Shizuku DLL (win64/dlls/<name>)
    # is left over from an earlier configuration and is ignored. A probe adds the export lists of earlier probe
    # builds (WOUT/probe), after OUT as on its link path (-L OUT first), so both bind a name to the same library.
    shizuku = {p.name.lower() for p in (W64 / "dlls").iterdir() if p.is_dir()} | {"kernel32", "ntdll"}
    stale = {m["name"].lower() for m in cfg["modules"] if m.get("disabled") and m["name"].lower() not in shizuku}
    provided = {p.stem.lower(): def_exports(p) for p in OUT.glob("*.def") if p.stem.lower() not in stale}
    base = int(cfg["image_base"], 16)
    if probe:
        for p in (WOUT / "probe").glob("*.def"):
            provided.setdefault(p.stem.lower(), def_exports(p))
    # type libraries first, whatever `only` says: widl needs them for importlib() (stdole2.tlb). A disabled one is
    # still built for a probe or when a selected module runs widl ("makedep"); only enabled ones are packed.
    TLBDIR.mkdir(parents=True, exist_ok=True)
    runs_widl = any(m.get("makedep") for m in selected)
    for m in cfg["modules"]:
        if m.get("kind") != "typelib" or (m.get("disabled") and not (probe or runs_widl)):
            continue
        try:
            typelibs[m["name"]] = build_typelib(trees[m.get("upstream", "wine")], m)
        except SystemExit as e:
            if not probe:
                raise
            print(f"PROBE typelib {m['name']}: {str(e)[:4000]}")
            probe_info[f"typelib:{m['name']}"] = {"result": "compilation failed",
                                                  "compile_errors": len(getattr(e, "errors", [None])),
                                                  "errors": getattr(e, "errors", [str(e)])}

    for i, m in enumerate(cfg["modules"]):
        if m.get("kind") == "typelib":
            continue
        if (only and m["name"] not in only) or (m.get("disabled") and not probe):
            continue
        if m.get("placeholder"):
            if probe:
                probe_info[m["name"]] = {"result": "placeholder, not built", "message": m.get("disabled", "")}
            continue
        notes = {}
        try:
            modules[m["name"]] = build_module(trees[m.get("upstream", "wine")], rt, m,
                                              base + i * int(cfg["image_stride"], 16), provided, trees,
                                              probe=bool(probe), notes=notes)
            if probe:
                probe_info[m["name"]] = {"result": "built", "compile_errors": 0, "undefined": [], **notes}
        except SystemExit as e:
            if not probe:
                raise
            print(f"PROBE {m['name']}: {str(e)[:4000]}")
            if isinstance(e, CompileError):
                probe_info[m["name"]] = {"result": "compilation failed", "compile_errors": len(e.errors),
                                         "errors": e.errors, **notes}
            elif isinstance(e, LinkError):
                probe_info[m["name"]] = {"result": "link failed", "compile_errors": 0, "undefined": e.undefined,
                                         "message": str(e)[:3000], **notes}
            else:
                probe_info[m["name"]] = {"result": "failed", "message": str(e)[:3000], **notes}
    for m in cfg["modules"]:
        if m.get("tests") and m["name"] in modules:
            tests.update(build_tests(wine, rt, m))
    enabled = {m["name"] for m in cfg["modules"] if not m.get("disabled")}
    result = {
        "built_utc": shzlib.utc_now(),
        "upstreams": {up: {"commit": git(tree, "rev-parse", "HEAD"),
                           "patches": [str(p.relative_to(REPO)) for p in patches[up]]} for up, tree in trees.items()},
        "modules": {n: {k: (str(v) if isinstance(v, Path) else v) for k, v in info.items()} for n, info in modules.items()},
        "tests": {n: {k: (str(v) if isinstance(v, Path) else v) for k, v in info.items()} for n, info in tests.items()},
        "typelibs": {n: {k: str(v) if isinstance(v, Path) else v for k, v in info.items()}
                     for n, info in typelibs.items()},
    }
    if probe:
        result["probe"] = probe_info
    # the image gets enabled modules only (a probe build of a disabled module is a report, not a product)
    files = [(info["image_path"], info["binary"].read_bytes()) for n, info in sorted(modules.items()) if n in enabled]
    files += [(p, Path(src).read_bytes()) for t in tests.values() if t["in_plain_image"] for p, src in t.get("data", [])]
    result["image_files"] = {}
    for f in cfg.get("image_files", []):
        src = (trees[f["upstream"]] / f["path"]) if "upstream" in f else (HERE / f["path"])
        files.append((f["image_path"], src.read_bytes()))
        result["image_files"][f["image_path"]] = str(src)
    for n, info in typelibs.items():
        if n in enabled:
            files.append((info["image_path"], info["tlb"].read_bytes()))
            result["image_files"][info["image_path"]] = str(info["tlb"])
    shzlib.write_json(WOUT / "wineport-result.json", result)
    return {"modules": modules, "tests": tests, "files": files, "typelibs": typelibs, "probe": probe_info}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", help="build only these modules (their dependencies must exist)")
    args = ap.parse_args()
    for tool in (CC, AR, NM, DLLTOOL, WINDRES, HOSTCC):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    if not (OUT / "libkernel32.a").exists():
        raise SystemExit("build the Shizuku runtime first: python3 shizukudos/win64/build.py")
    res = build(args.only)
    for n, info in res["modules"].items():
        c = info["counts"]
        print(f"{info['binary'].name:16} exports {info['exports']:5}  " +
              "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
    for n, info in res["typelibs"].items():
        print(f"{info['tlb'].name:16} {info['size']} bytes -> {info['image_path']}")
    for n, info in res["tests"].items():
        print(f"{info['exe'].name:24} subtests: {' '.join(info['subtests'])}")
    for n, info in res["probe"].items():
        print(f"PROBE {n:12} {info['result']}: {info.get('compile_errors', 0)} compile errors, "
              f"{len(info.get('undefined', []))} unresolved" +
              (f", import libraries not found: {' '.join(info['missing_import_libs'])}"
               if info.get("missing_import_libs") else ""))


if __name__ == "__main__":
    main()
