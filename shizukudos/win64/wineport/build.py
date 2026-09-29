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
  wineport/T_WINE_<NAME>.EXE          Wine's own tests for a module (subtests selected in modules.json)
  wineport/wineport-result.json       per module: export counts by kind, every excluded stub, link command

The Shizuku build (win64/build.py) calls build() after its own modules; `python3 build.py` alone rebuilds only the
Wine port against an existing Shizuku build.
"""
import argparse
import hashlib
import json
import os
import re
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
JOBS = max(1, int(os.environ.get("SHZ_WINEPORT_JOBS", "2")))

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


def ensure_wine_host(wine):
    """Host configure + the tools and generated headers the PE build needs (widl, wrc, include/*.h from *.idl)."""
    if not (wine / "Makefile").exists():
        log = UPSTREAM / "wine-configure.log"
        with open(log, "w") as f:
            subprocess.run(["./configure", *WINE_CONFIGURE], cwd=wine, stdout=f, stderr=subprocess.STDOUT, check=True)
    need = [wine / "tools/widl/widl", wine / "tools/wrc/wrc", wine / "include/dwrite_3.h", wine / "include/wincrypt.h"]
    if not all(p.exists() for p in need):
        log = UPSTREAM / "wine-headers.log"
        with open(log, "w") as f:
            subprocess.run(["make", f"-j{JOBS}", "tools/widl/widl", "tools/wrc/wrc"], cwd=wine, stdout=f,
                           stderr=subprocess.STDOUT, check=True)
            idls = sorted(p.relative_to(wine).with_suffix(".h") for p in (wine / "include").glob("*.idl"))
            subprocess.run(["make", f"-j{JOBS}", "-k", *map(str, idls)], cwd=wine, stdout=f, stderr=subprocess.STDOUT)


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
        raise SystemExit("compilation failed:\n" + "\n".join(errors[:6]))


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
    crt_src = [s for s in crt_src if s.name != "wcrt_startup.c"]
    shzwcrt = build_static("shzwcrt", crt_src, crt_flags(wine), lib)
    crt0 = lib / "crt0" / "wcrt_startup.o"
    compile_all([(HERE / "crt/wcrt_startup.c", crt0, crt_flags(wine))])
    glue_flags = [*WINE_CFLAGS, "-I", wine / "include", "-I", wine / "include/msvcrt"]
    winecrt0 = [wine / "dlls/winecrt0" / f for f in ("debug.c", "delay_load.c", "crt_dllmain.c", "crt_fltused.c",
                                                      "dll_main.c", "dll_canunload.c", "dll_register.c")]
    glue = [*sorted(p for p in (HERE / "glue").glob("*.c") if p.name != "unixcall.c"), *winecrt0]
    shzwine0 = build_static("shzwine0", glue, glue_flags, lib)
    return {"shzwcrt": shzwcrt, "shzwine0": shzwine0, "crt0": crt0, "glue_flags": glue_flags}


def build_extlib(tree, wine, name, cfg):
    """A static library from an upstream tree: the SOURCES of its Wine Makefile.in, or an explicit source list. It is
    compiled against Wine's C runtime headers so that it uses the same runtime (wineport/crt) as the DLLs."""
    d = tree / cfg.get("dir", "")
    mk = makefile_vars(d / "Makefile.in") if (d / "Makefile.in").exists() else {}
    srcs = [d / s for s in (cfg.get("sources") or [s for s in mk.get("SOURCES", []) if s.endswith(".c")])]
    flags = [*WINE_CFLAGS, *cfg.get("defines", []), *mk.get("EXTRADEFS", []), "-I", d,
             *[x for i in cfg.get("includes", []) for x in ("-I", tree / i)],
             *[x for i in cfg.get("shizuku_includes", []) for x in ("-I", HERE / i)], "-I", wine / "include",
             "-I", wine / "include/msvcrt", "-w"]
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
                      f"    jmp *ptr_{fn}(%rip)",
                      f"fail_{fn}:", f"    movl ${fail}, %ecx", "    jmp shzw_dyn_fail"]
            data += [f"ptr_{fn}: .quad resolve_{fn}", f"    .globl __imp_{fn}", f"__imp_{fn}: .quad {fn}"]
            strs += [f"name_{fn}: .asciz \"{fn}\""]
    path.write_text("\n".join(lines + data + strs) + "\n")
    return path


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


def build_module(wine, rt, m, base, provided, trees):
    name = m["name"]
    d = wine / m.get("dir", f"dlls/{name}")
    mk = makefile_vars(d / "Makefile.in") if (d / "Makefile.in").exists() else {}
    obj_dir = WOUT / "obj" / name
    sources = m.get("sources")
    if sources is None:
        sources = [s for s in mk.get("SOURCES", [])]
    srcs = [d / s for s in sources if s.endswith(".c") and not is_unix_source(d / s)]
    srcs += [wine / s for s in m.get("extra_sources", [])]
    srcs += [HERE / s for s in m.get("shizuku_sources", [])]
    rcs = [d / s for s in sources if s.endswith(".rc")]
    includes = [d, *[wine / i for i in m.get("includes", [])], *[HERE / i for i in m.get("shizuku_includes", [])]]
    defines = [*mk.get("EXTRADEFS", []), *m.get("defines", [])]
    flags = [*WINE_CFLAGS, *defines, *[x for i in includes for x in ("-I", i)], "-I", wine / "include",
             "-I", wine / "include/msvcrt"]
    objs = [obj_dir / (s.stem + "_" + hashlib.sha1(str(s).encode()).hexdigest()[:6] + ".o") for s in srcs]
    # former Unix-side sources ported to PE by the module's patches (m["unix_inproc"]): built with their own includes
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
    spec = d / m.get("spec", f"{name}.spec")
    entries = winespec.parse_spec(spec)
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

    lines, kept = winespec.def_lines(f"{name}.dll", entries, forward_ok)
    lines = [l + (" PRIVATE" if any(e.name == l.split()[0] and "private" in e.flags for e in kept) else "")
             if l.startswith("  ") else l for l in lines]
    deffile = OUT / f"{name}.def"
    deffile.write_text("\n".join(lines) + "\n")

    delay_libs = []
    for dl in m.get("delay_imports", []):
        dspec = wine / "dlls" / dl / f"{dl}.spec"
        dents = [e for e in winespec.parse_spec(dspec) if e.kind not in ("stub",) and not e.noname]
        ddef = WOUT / "lib" / f"{dl}_delay.def"
        ddef.write_text(f"LIBRARY {dl}.dll\nEXPORTS\n" + "".join(f"  {e.name}\n" for e in dents))
        dlib = WOUT / "lib" / f"lib{dl}_delay.a"
        run([DLLTOOL, "-d", ddef, "-y", dlib])
        delay_libs.append(dlib)

    dll = OUT / f"{name}.dll"
    entry = m.get("entry", "DllMainCRTStartup")
    libs = [f"-l{l}" for l in m.get("link", [])]
    cmd = [CC, "-shared", "-nostdlib", f"-Wl,--entry,{entry}", f"-Wl,--image-base,{base:#x}", "-Wl,--dynamicbase",
           "-Wl,--gc-sections",
           "-Wl,--subsystem,windows", "-Wl,--disable-auto-import", "-o", dll, *objs, deffile,
           *[WOUT / "lib" / f"lib{s}.a" for s in m.get("static", [])], "-L", OUT, "-L", WOUT / "lib",
           "-Wl,--start-group", rt["shzwine0"], rt["shzwcrt"], *delay_libs, "-Wl,--end-group", *libs,
           "-lkernel32", "-lntdll", "-lgcc"]
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True)
    if r.returncode:
        undef = sorted(set(re.findall(r"undefined reference to `([^']+)'", r.stderr)))
        raise SystemExit(f"link of {name}.dll failed" + (f"; undefined: {' '.join(undef)}" if undef else "") +
                         f"\n{r.stderr[-3000:] if not undef else ''}")
    run([DLLTOOL, "-d", deffile, "-l", OUT / f"lib{name}.a"])
    provided[name] = {e.name for e in kept}
    counts = {}
    for e in entries:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    return {"dll": dll, "base": hex(base), "exports": len(kept), "counts": counts,
            "not_exported": [e.as_dict() for e in entries if e not in kept],
            "semistub": [e.name for e in entries if e.kind == "semistub"],
            "sources": [str(s.relative_to(REPO)) for s in srcs], "link": [str(x) for x in cmd]}


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
    d = wine / t.get("dir", f"dlls/{name}/tests")
    srcs = [s for s in makefile_vars(d / "Makefile.in").get("SOURCES", []) if s.endswith(".c")]
    out[f"wine_{name}"] = build_test_exe(wine, rt, name, f"T_WINE_{name.upper()}.EXE", d, srcs, t["subtests"], t)
    if t.get("shizuku"):
        st = {**t, **t["shizuku"]}
        sd = HERE / "tests" / name
        ssrcs = sorted(p.name for p in sd.glob("*.c"))
        out[f"wp_{name}"] = build_test_exe(wine, rt, name, f"T_WP_{name.upper()}.EXE", sd, ssrcs,
                                           st.get("subtests", [Path(s).stem for s in ssrcs]), st, label=f"wp_{name}")
    return out


# ---------------------------------------------------------------- entry points
def build(only=None):
    """Build every configured module; returns {"modules": {name: info}, "tests": {name: info}, "files": [(img path, bytes)]}."""
    cfg = json.loads(CONFIG.read_text())
    trees = {}
    for up in cfg.get("upstreams", ["wine"]):
        trees[up] = ensure_tree(up)
    wine = trees["wine"]
    ensure_wine_host(wine)
    patches = {up: apply_patches(up, tree) for up, tree in trees.items()}
    WOUT.mkdir(parents=True, exist_ok=True)
    (WOUT / "lib").mkdir(exist_ok=True)
    rt = build_runtime(wine)
    for name, lcfg in cfg.get("static_libs", {}).items():
        build_extlib(trees[lcfg.get("upstream", "wine")], wine, name, lcfg)
    provided = {p.stem.lower(): def_exports(p) for p in OUT.glob("*.def")}
    base = int(cfg["image_base"], 16)
    modules, tests = {}, {}
    probe = os.environ.get("SHZ_WINEPORT_PROBE")          # report every module's unresolved imports, do not stop

    for i, m in enumerate(cfg["modules"]):
        if (only and m["name"] not in only) or (m.get("disabled") and not probe):
            continue
        try:
            modules[m["name"]] = build_module(trees[m.get("upstream", "wine")], rt, m,
                                              base + i * int(cfg["image_stride"], 16), provided, trees)
        except SystemExit as e:
            if not probe:
                raise
            print(f"PROBE {m['name']}: {str(e)[:4000]}")
    for m in cfg["modules"]:
        if m.get("tests") and m["name"] in modules:
            tests.update(build_tests(wine, rt, m))
    for extra in cfg.get("data_files", []):
        pass
    result = {
        "built_utc": shzlib.utc_now(),
        "upstreams": {up: {"commit": git(tree, "rev-parse", "HEAD"),
                           "patches": [str(p.relative_to(REPO)) for p in patches[up]]} for up, tree in trees.items()},
        "modules": {n: {k: (str(v) if isinstance(v, Path) else v) for k, v in info.items()} for n, info in modules.items()},
        "tests": {n: {k: (str(v) if isinstance(v, Path) else v) for k, v in info.items()} for n, info in tests.items()},
    }
    files = [(f"\\SHZ\\SYS64\\{n}.dll", info["dll"].read_bytes()) for n, info in sorted(modules.items())]
    result["image_files"] = {}
    for f in cfg.get("image_files", []):
        src = (trees[f["upstream"]] / f["path"]) if "upstream" in f else (HERE / f["path"])
        files.append((f["image_path"], src.read_bytes()))
        result["image_files"][f["image_path"]] = str(src)
    shzlib.write_json(WOUT / "wineport-result.json", result)
    return {"modules": modules, "tests": tests, "files": files}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", nargs="*", help="build only these modules (their dependencies must exist)")
    args = ap.parse_args()
    for tool in (CC, AR, NM, DLLTOOL, WINDRES):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    if not (OUT / "libkernel32.a").exists():
        raise SystemExit("build the Shizuku runtime first: python3 shizukudos/win64/build.py")
    res = build(args.only)
    for n, info in res["modules"].items():
        c = info["counts"]
        print(f"{n + '.dll':16} exports {info['exports']:5}  " + "  ".join(f"{k}={v}" for k, v in sorted(c.items())))
    for n, info in res["tests"].items():
        print(f"{info['exe'].name:24} subtests: {' '.join(info['subtests'])}")


if __name__ == "__main__":
    main()
