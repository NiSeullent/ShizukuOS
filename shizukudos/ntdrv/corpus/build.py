#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the NT driver corpus: real, unmodified x64 kernel-mode drivers from ReactOS compiled with mingw-w64 GCC (and
clang for the C++ ones) against the ReactOS sdk/include headers, into PE32+ .sys images. No RosBE, no CMake, no WDK.

Why: the ShizukuDOS 10 NT driver host must be measured against drivers nobody here wrote. Every .sys produced here
is built from build/upstream/reactos exactly as shizukudos/ntdrv/corpus/fetch.py checked it out at the commit
pinned in shizukudos/upstream/manifest.json. Nothing under build/upstream is edited.

How: each driver is built from its OWN CMakeLists.txt. `CMakeLite` below evaluates the subset of CMake that ReactOS
driver and library CMakeLists use (set/list/if/foreach/include, add_definitions, include_directories,
add_library, target_compile_definitions/options/include_directories, target_link_libraries, and the ReactOS macros
add_importlibs, set_module_type, spec2def, add_asm_files, add_driver_inf). The directory-level state every
ReactOS target inherits is copied from the top-level CMakeLists.txt and sdk/cmake/gcc.cmake for ARCH=amd64 and
CMAKE_BUILD_TYPE=Release (see ROOT_DEFINES / root_options()). Static libraries a driver links (arbiter, dmilib,
virtio, sptilib, ntoskrnl_vista, libcntpr, ...) are found by indexing every add_library() in the tree and built the
same way. What ReactOS's build generates is generated here with ReactOS's own host tools, compiled unmodified:

  * hpp            sdk/include/xdk templates -> wdm.h, ntddk.h, ntifs.h, ntdef.h, winnt.h, devioctl.h
  * windmc         sdk/include/reactos/mc/*.mc -> bugcodes.h, ntstatus.h, ... (after UTF-8 -> UTF-16LE, as
                   ReactOS's utf16le tool does)
  * spec2def       import libraries (ntoskrnl, hal, ndis, storport, scsiport, classpnp, wdfldr, ...) and the .def /
                   stub file of modules that export an API (storport.sys, scsiport.sys, classpnp.sys)
  * pefixup        post-link section characteristics (INIT discardable, .rsrc read-only, ...), as ReactOS does
  * gcc_plugin_seh GCC amd64 structured exception handling (ReactOS's own GCC plugin, built against the cross
                   compiler's plugin headers; needs libgmp-dev). Without it, _SEH2_TRY bodies still compile but no
                   handler is registered; the result records which SEH mode each build used.
  * geninc         sdk/include/asm/ksamd64.inc for assembler sources (genincdata.c built as a module first)

Compilers (--cc): gcc = x86_64-w64-mingw32-gcc, ReactOS's primary amd64 configuration; clang =
clang --target=x86_64-w64-mingw32 with ReactOS's Clang branches of gcc.cmake (ReactOS's clang amd64 configuration uses
the dummy PSEH: try bodies run unprotected). C++ sources (uniata, wdf01000) need a C++ compiler for the mingw target:
x86_64-w64-mingw32-g++ when installed, else clang++. Linking is always done by the mingw GNU ld driver.

Outputs: build/shizukudos/ntdrv/corpus/<driver>/<cc>/<driver>.sys and build/shizukudos/ntdrv/corpus/build-result.json
(status, first errors, sha256, sections, imports per DLL, framework classification). --packages assembles driver
packages (the .sys + the driver's own INF, unchanged) under build/shizukudos/ntdrv/packages/<driver>/.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from shzlib import BUILD, REPO, UPSTREAM_DIR, load_manifest, sha256_file, write_json  # noqa: E402

ROS = UPSTREAM_DIR / "reactos"
OUT = BUILD / "ntdrv"
TOOLS = OUT / "tools"
SDKBIN = OUT / "rosbin"                  # plays the role of ${REACTOS_BINARY_DIR}
CORPUS = OUT / "corpus"
PACKAGES = OUT / "packages"

GCC = "x86_64-w64-mingw32-gcc"
GXX = "x86_64-w64-mingw32-g++"
CLANG = "clang"
CLANGXX = "clang++"
TRIPLE = "x86_64-w64-mingw32"
DLLTOOL = "x86_64-w64-mingw32-dlltool"
WINDRES = "x86_64-w64-mingw32-windres"
WINDMC = "x86_64-w64-mingw32-windmc"
OBJDUMP = "x86_64-w64-mingw32-objdump"
AR = "x86_64-w64-mingw32-ar"

# ------------------------------------------------------------------------------------------------------- the corpus
# name -> (ReactOS source dir, what it is). The build description (sources, defines, libraries, imports) comes from
# the directory's CMakeLists.txt, not from here.
CORPUS_DRIVERS = {
    "null":      ("drivers/base/null", "\\Device\\Null: the smallest WDM driver"),
    "beep":      ("drivers/base/beep", "legacy (non-PnP) NT driver, HAL port I/O"),
    "kbdclass":  ("drivers/input/kbdclass", "keyboard class driver (WDM upper filter)"),
    "mouclass":  ("drivers/input/mouclass", "mouse class driver (WDM upper filter)"),
    "i8042prt":  ("drivers/input/i8042prt", "PS/2 keyboard+mouse port driver (WDM, interrupts, WMI)"),
    "serial":    ("drivers/serial/serial", "16550 UART port driver (WDM PnP)"),
    "pci":       ("drivers/bus/pci", "PCI bus driver (ReactOS's own)"),
    "pcix":      ("drivers/bus/pcix", "PCI bus driver (Windows-2003-architecture rewrite, arbiters)"),
    "e1000":     ("drivers/network/dd/e1000", "Intel PRO/1000 NDIS miniport"),
    "rtl8139":   ("drivers/network/dd/rtl8139", "Realtek 8139 NDIS miniport"),
    "pcnet":     ("drivers/network/dd/pcnet", "AMD PCnet NDIS miniport"),
    "netkvm":    ("drivers/network/dd/netkvm", "virtio-net NDIS 5.1 miniport (older virtio-win NetKVM, as carried by ReactOS)"),
    "storahci":  ("drivers/storage/port/storahci", "AHCI StorPort miniport"),
    "uniata":    ("drivers/storage/ide/uniata", "IDE/SATA SCSI-port miniport (C++)"),
    "storport":  ("drivers/storage/port/storport", "StorPort port driver (framework provider)"),
    "scsiport":  ("drivers/storage/port/scsiport", "SCSI port driver (framework provider)"),
    "classpnp":  ("drivers/storage/class/classpnp", "storage class library (framework provider, Microsoft sample code)"),
    "disk":      ("drivers/storage/class/disk", "disk class driver over classpnp (Microsoft sample code)"),
    "cdrom":     ("drivers/storage/class/cdrom", "CD-ROM class driver, KMDF (Microsoft sample code)"),
    "hdaudbus":  ("drivers/wdm/audio/hdaudbus", "HD Audio bus driver, KMDF"),
    "wdfldr":    ("sdk/lib/drivers/wdf/wdfldr", "KMDF loader (framework provider)"),
    "wdf01000":  ("sdk/lib/drivers/wdf", "Wdf01000.sys KMDF 1.17 runtime (Microsoft WDF sources, MIT, C++)"),
}

# Import libraries: generated from the export spec of the module that provides them (dll name, spec path).
IMPORT_SPECS = {"ntoskrnl": ("ntoskrnl.exe", "ntoskrnl/ntoskrnl.spec"), "hal": ("hal.dll", "hal/hal.spec"),
                "ndis": ("ndis.sys", "drivers/network/ndis/ndis.spec"),
                "storport": ("storport.sys", "drivers/storage/port/storport/storport.spec"),
                "scsiport": ("scsiport.sys", "drivers/storage/port/scsiport/scsiport.spec"),
                "classpnp": ("classpnp.sys", "drivers/storage/class/classpnp/classpnp.spec"),
                "wdfldr": ("wdfldr.sys", "sdk/lib/drivers/wdf/wdfldr/wdfldr.spec"),
                "wmilib": ("wmilib.sys", "drivers/wmi/wmilib.spec"),
                "hidclass": ("hidclass.sys", "drivers/hid/hidclass/hidclass.spec"),
                "hidparse": ("hidparse.sys", "drivers/hid/hidparse/hidparse.spec"),
                "ks": ("ks.sys", "drivers/ksfilter/ks/ks.spec"),
                "portcls": ("portcls.sys", "drivers/wdm/audio/backpln/portcls/portcls.spec"),
                "usbd": ("usbd.sys", "drivers/usb/usbd/usbd.spec"),
                "videoprt": ("videoprt.sys", "win32ss/drivers/videoprt/videoprt.spec")}

MC_FILES = {"bugcodes": "-A", "ntstatus": "-U", "ntiologc": "-U", "pciclass": "-U", "errcodes": "-U",
            "neteventmsg": "-U", "netmsgmsg": "-U", "net_msg": "-U"}
XDK = [("wdm.template.h", "ddk/wdm.h"), ("ntddk.template.h", "ddk/ntddk.h"), ("ntifs.template.h", "ddk/ntifs.h"),
       ("devioctl.template.h", "psdk/devioctl.h"), ("ntdef.template.h", "psdk/ntdef.h"), ("winnt.template.h", "psdk/winnt.h")]

# ------------------------------------------------------------------ directory state every ReactOS target inherits
# Top-level CMakeLists.txt (ARCH amd64, DBG off) + sdk/cmake/gcc.cmake (Release), in their order.
ROOT_DEFINES = ["-D__REACTOS__", "-DDBG=0", "-DWINVER=0x502", "-D_WIN32_IE=0x603", "-D_WIN32_WINNT=0x502",
                "-D_WIN32_WINDOWS=0x502", "-D_SETUPAPI_VER=0x502", "-DMINGW_HAS_SECURE_API=1",
                "-DD3D_UMD_INTERFACE_VERSION=0x000C", "-DDXGKDDI_INTERFACE_VERSION=0x1052", "-DDLL_EXPORT_VERSION=0x502",
                "-D_M_AMD64", "-D_M_X64", "-D_AMD64_", "-D__x86_64__", "-D_WIN64", "-D_NEW_DELETE_OPERATORS_",
                "-DUSE_COMPILER_EXCEPTIONS", "-D_USE_PSEH3=1", "-U_X86_", "-UWIN32", "-D_GLIBCXX_HAVE_BROKEN_VSWPRINTF",
                "-D_CRT_SUPPRESS_RESTRICT"]
ROOT_INCLUDES = ["sdk/include", "sdk/include/crt", "sdk/include/ddk", "sdk/include/ndk", "sdk/include/psdk",
                 "sdk/include/reactos", "sdk/include/reactos/libs", "sdk/include/vcruntime", "sdk/include/winrt",
                 "@sdk/include", "@sdk/include/psdk", "@sdk/include/ddk", "@sdk/include/dxsdk", "@sdk/include/reactos",
                 "@sdk/include/reactos/mc", "sdk/include/dxsdk", "sdk/lib/pseh/include"]      # @ = binary dir
GCC_NO_BUILTIN = [f"-fno-builtin-{f}" for f in (
    "acosf acosl asinf asinl atan2f atan2l atanf atanl ceilf ceill coshf coshl cosf cosl expf expl fabsf fabsl floorf "
    "floorl fmodf fmodl frexpf frexpl hypotf hypotl ldexpf ldexpl logf logl log10f log10l modff modfl powf powl sinhf "
    "sinhl sinf sinl sqrtf sqrtl tanhf tanhl tanf tanl feraiseexcept feupdateenv ceil ceilf cos floor floorf pow sin "
    "sincos sqrt sqrtf erf erff execv execve execvp").split()]


def root_options(cc_id):
    """(language, flag) pairs of gcc.cmake's add_compile_options for Release amd64. language None = all."""
    opts = [(None, "-pipe"), (None, "-fms-extensions"), (None, "-fno-strict-aliasing"), (None, "-fno-common"),
            (None, "-mlong-double-64"), ("C", "-nostdinc"), ("ASM", "-nostdinc")]
    if cc_id == "GNU":
        opts += [(None, "-fno-aggressive-loop-optimizations")] + [(None, f) for f in GCC_NO_BUILTIN]
    else:
        opts += [(None, "-fno-associative-math"), (None, "-fno-builtin-stpcpy")]
    opts += [(None, "-march=athlon64"), (None, "-mtune=generic"), (None, "-Wall"), (None, "-Wpointer-arith")]
    opts += [(None, f) for f in ("-Wno-char-subscripts", "-Wno-multichar", "-Wno-unused-value", "-Wno-unused-const-variable",
                                 "-Wno-unused-local-typedefs", "-Wno-deprecated", "-Wno-unused-result", "-Wno-format",
                                 "-Wno-maybe-uninitialized", "-Wno-nonnull-compare")]
    if cc_id == "GNU":
        opts += [(None, "-Wno-unknown-pragmas")]
    else:
        opts += [("C", "-Wno-microsoft"), (None, "-Wno-pragma-pack"), (None, "-Wno-unknown-warning-option")]
    opts += [(None, "-O2"), (None, "-DNDEBUG="), (None, "-Wno-unused-variable"), (None, "-Wno-unused-but-set-variable")]
    if cc_id == "GNU":
        opts += [(None, "-mpreferred-stack-boundary=4")]
    opts += [(None, "-mcx16"), (None, f"-ffile-prefix-map={ROS}=")]
    opts += [("CXX", "-nostdinc"), ("CXX", "-fno-rtti"), ("CXX", "-fno-exceptions")]
    return opts


LINK_FLAGS = ["-shared", "-nostdlib", "-nostartfiles", "-Wl,--disable-stdcall-fixup",
              "-Wl,--major-image-version,5", "-Wl,--minor-image-version,01", "-Wl,--major-os-version,5",
              "-Wl,--minor-os-version,01", "-Wl,--exclude-all-symbols,-file-alignment=0x1000,-section-alignment=0x1000"]


# ============================================================================================================ CMakeLite
class CMakeError(Exception):
    pass


def cmake_parse(text, path):
    """-> list of (command, [(value, quoted)], lineno). Handles comments, quoted/bracket arguments, nested parens."""
    cmds, i, n, line = [], 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c == "#":
            if text.startswith("#[[", i) or re.match(r"#\[=*\[", text[i:i + 8]):
                m = re.match(r"#\[(=*)\[", text[i:])
                end = text.find("]" + m.group(1) + "]", i)
                line += text.count("\n", i, end)
                i = end + len(m.group(1)) + 2
            else:
                while i < n and text[i] != "\n":
                    i += 1
        else:
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", text[i:])
            if not m:
                raise CMakeError(f"{path}:{line}: unexpected {text[i:i + 20]!r}")
            name, start = m.group(0).lower(), line
            i += len(m.group(0))
            while i < n and text[i] in " \t":
                i += 1
            if i >= n or text[i] != "(":
                raise CMakeError(f"{path}:{line}: expected '(' after {name}")
            i += 1
            args, depth = [], 0
            while True:
                if i >= n:
                    raise CMakeError(f"{path}:{start}: unterminated {name}(")
                c = text[i]
                if c == "\n":
                    line += 1
                    i += 1
                elif c.isspace():
                    i += 1
                elif c == "#":
                    while i < n and text[i] != "\n":
                        i += 1
                elif c == "(":
                    depth += 1
                    args.append(("(", False))
                    i += 1
                elif c == ")":
                    if depth == 0:
                        i += 1
                        break
                    depth -= 1
                    args.append((")", False))
                    i += 1
                elif c == '"':
                    j, buf = i + 1, []
                    while text[j] != '"':
                        if text[j] == "\\" and j + 1 < n:
                            nxt = text[j + 1]
                            buf.append({"n": "\n", "t": "\t", "r": "\r", ";": "\\;"}.get(nxt, nxt) if nxt != "\n" else "")
                            j += 2
                            continue
                        if text[j] == "\n":
                            line += 1
                        buf.append(text[j])
                        j += 1
                    args.append(("".join(buf), True))
                    i = j + 1
                elif c == "[" and re.match(r"\[=*\[", text[i:i + 8]):
                    m = re.match(r"\[(=*)\[", text[i:])
                    end = text.find("]" + m.group(1) + "]", i)
                    args.append((text[i + len(m.group(0)):end], True))
                    line += text.count("\n", i, end)
                    i = end + len(m.group(1)) + 2
                else:
                    j = i
                    gdepth = 0
                    while j < n:
                        ch = text[j]
                        if ch == "$" and j + 1 < n and text[j + 1] == "<":
                            gdepth += 1
                            j += 2
                            continue
                        if ch == ">" and gdepth:
                            gdepth -= 1
                            j += 1
                            continue
                        if not gdepth and (ch.isspace() or ch in '()#"'):
                            break
                        if ch == "\\" and j + 1 < n:
                            j += 2
                            continue
                        j += 1
                    args.append((text[i:j], False))
                    i = j
            cmds.append((name, args, start))
    return cmds


FALSE_CONSTS = {"", "0", "OFF", "NO", "FALSE", "N", "IGNORE", "NOTFOUND"}


def cm_truthy(v):
    u = v.upper()
    if u in FALSE_CONSTS or u.endswith("-NOTFOUND"):
        return False
    return True


def version_tuple(v):
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.]", v or "0"))


class Target:
    def __init__(self, name, kind, srcdir, bindir):
        self.name, self.kind, self.srcdir, self.bindir = name, kind, Path(srcdir), Path(bindir)
        self.sources = []
        self.defs = {"PRIVATE": [], "INTERFACE": []}          # PUBLIC adds to both
        self.opts = {"PRIVATE": [], "INTERFACE": []}
        self.incs = {"PRIVATE": [], "INTERFACE": []}
        self.links = {"PRIVATE": [], "INTERFACE": []}
        self.importlibs = []                                  # via add_importlibs (lib<name>)
        self.module_type = None
        self.entry = None
        self.image_base = None
        self.link_opts = []
        self.infs = []
        self.spec = None                                      # (dll, spec) when the module exports an API
        self.dir_defs, self.dir_opts, self.dir_incs = [], [], []
        self.imported = None                                  # path of an IMPORTED library
        self.post_fixups = []


class CMakeLite:
    """Evaluates one ReactOS source directory's CMakeLists.txt (and the .cmake files it includes)."""

    def __init__(self, cc_id, cc_version, tool_paths, log):
        self.cc_id, self.log = cc_id, log
        self.vars = {"ARCH": "amd64", "ARCH2": "x86_64", "CMAKE_C_COMPILER_ID": cc_id, "CMAKE_CXX_COMPILER_ID": cc_id,
                     "CMAKE_C_COMPILER_VERSION": cc_version, "CMAKE_CXX_COMPILER_VERSION": cc_version,
                     "CMAKE_BUILD_TYPE": "Release", "CMAKE_CROSSCOMPILING": "TRUE", "MSVC": "", "MSVC_IDE": "",
                     "USE_CLANG_CL": "", "DBG": "0", "KDBG": "", "_WINKD_": "", "SARCH": "", "OPTIMIZE": "",
                     "USE_DUMMY_PSEH": "0", "USE_PSEH3": "1", "STACK_PROTECTOR": "", "CMAKE_HOST_WIN32": "",
                     "CMAKE_HOST_SYSTEM": "Linux", "PSEH_LIB": "pseh", "DLL_EXPORT_VERSION": "0x502",
                     "REACTOS_SOURCE_DIR": str(ROS), "REACTOS_BINARY_DIR": str(SDKBIN), "CMAKE_FILES_DIRECTORY": "/CMakeFiles",
                     "LTCG": "", "ENABLE_CCACHE": "", "SEPARATE_DBG": "", "NO_ROSSYM": "TRUE", "ENABLE_UNIATA": ""}
        self.tool_paths = tool_paths
        self.targets = {}
        self.functions = set()

    # ---- variable expansion
    def expand(self, s, local):
        for _ in range(8):
            m = re.search(r"\$\{([^${}]*)\}", s)
            if not m:
                break
            name = m.group(1)
            val = local.get(name, self.vars.get(name, os.environ.get(name[4:], "") if name.startswith("ENV{") else ""))
            s = s[:m.start()] + val + s[m.end():]
        return s

    def args(self, raw, local, keep_quoted=False):
        out = []
        for v, quoted in raw:
            e = self.expand(v, local)
            if quoted:
                out.append((e, True) if keep_quoted else e)
            else:
                parts = [p for p in re.split(r"(?<!\\);", e) if p != ""]
                out += [(p, False) for p in parts] if keep_quoted else parts
        return out

    # ---- if()
    def cond(self, toks, local):
        pos = [0]

        def peek():
            return toks[pos[0]] if pos[0] < len(toks) else (None, False)

        def take():
            t = peek()
            pos[0] += 1
            return t

        def value(tok):
            v, quoted = tok
            if not quoted and (v in local or v in self.vars):
                return local.get(v, self.vars.get(v))
            return v

        def truth(tok):
            v, quoted = tok
            if not quoted and v.upper() in FALSE_CONSTS | {"1", "ON", "YES", "TRUE", "Y"}:
                return cm_truthy(v)
            if not quoted and re.fullmatch(r"-?\d+(\.\d+)?", v):
                return float(v) != 0
            if not quoted:
                return cm_truthy(local.get(v, self.vars.get(v, "")))
            return cm_truthy(v)

        BIN = {"STREQUAL", "EQUAL", "LESS", "GREATER", "LESS_EQUAL", "GREATER_EQUAL", "MATCHES", "VERSION_LESS",
               "VERSION_GREATER", "VERSION_EQUAL", "VERSION_LESS_EQUAL", "VERSION_GREATER_EQUAL", "IN_LIST", "STRLESS",
               "STRGREATER"}

        def num(x):
            try:
                return int(x, 0)
            except ValueError:
                try:
                    return float(x)
                except ValueError:
                    return 0

        def primary():
            t = take()
            if t[0] == "(" and not t[1]:
                r = orx()
                take()
                return r
            if not t[1] and t[0] in ("DEFINED",):
                x = take()[0]
                return x in local or x in self.vars
            if not t[1] and t[0] in ("EXISTS", "IS_DIRECTORY"):
                return Path(value(take())).exists()
            if not t[1] and t[0] in ("TARGET", "COMMAND", "POLICY"):
                take()
                return t[0] == "POLICY"
            op = peek()
            if op[0] in BIN and not op[1]:
                take()
                rhs = take()
                a, b = value(t), value(rhs)
                o = op[0]
                if o == "STREQUAL":
                    return a == b
                if o == "EQUAL":
                    return num(a) == num(b)
                if o == "LESS":
                    return num(a) < num(b)
                if o == "GREATER":
                    return num(a) > num(b)
                if o == "LESS_EQUAL":
                    return num(a) <= num(b)
                if o == "GREATER_EQUAL":
                    return num(a) >= num(b)
                if o == "MATCHES":
                    return re.search(b, a) is not None
                if o == "IN_LIST":
                    return a in (local.get(rhs[0], self.vars.get(rhs[0], "")).split(";"))
                va, vb = version_tuple(a), version_tuple(b)
                return {"VERSION_LESS": va < vb, "VERSION_GREATER": va > vb, "VERSION_EQUAL": va == vb,
                        "VERSION_LESS_EQUAL": va <= vb, "VERSION_GREATER_EQUAL": va >= vb,
                        "STRLESS": a < b, "STRGREATER": a > b}[o]
            return truth(t)

        def notx():
            if peek()[0] == "NOT" and not peek()[1]:
                take()
                return not notx()
            return primary()

        def andx():
            r = notx()
            while peek()[0] == "AND" and not peek()[1]:
                take()
                r2 = notx()
                r = r and r2
            return r

        def orx():
            r = andx()
            while peek()[0] == "OR" and not peek()[1]:
                take()
                r2 = andx()
                r = r or r2
            return r
        return orx()

    # ---- generator expressions (only the forms ReactOS uses in driver/library CMakeLists)
    def genex(self, s, lang):
        """Evaluate $<...> for a given language; returns the string or '' when the condition is false."""
        def ev(x):
            while True:
                m = re.search(r"\$<([^$<>]*)>", x)
                if not m:
                    return x
                body = m.group(1)
                if body.startswith("COMPILE_LANGUAGE:"):
                    r = "1" if lang in body.split(":", 1)[1].split(",") else "0"
                elif body.startswith("NOT:"):
                    r = "0" if body[4:] == "1" else "1"
                elif body.startswith("BOOL:"):
                    r = "1" if cm_truthy(body[5:]) else "0"
                elif body.startswith("AND:"):
                    r = "1" if all(p == "1" for p in body[4:].split(",")) else "0"
                elif body.startswith("OR:"):
                    r = "1" if any(p == "1" for p in body[3:].split(",")) else "0"
                elif body.startswith("TARGET_FILE:"):
                    r = self.tool_paths.get(body.split(":", 1)[1], "")
                elif body.startswith("1:"):
                    r = body[2:]
                elif body.startswith("0:"):
                    r = ""
                elif body.startswith("IF:"):
                    c, a, b = (body[3:].split(",") + ["", ""])[:3]
                    r = a if c == "1" else b
                elif body.startswith("TARGET_PROPERTY:") or body.startswith("IN_LIST:"):
                    r = "0"
                else:
                    self.log.append(f"genex not understood, dropped: $<{body}>")
                    r = ""
                x = x[:m.start()] + r + x[m.end():]
        return ev(s)

    # ---- evaluation
    def run_dir(self, srcdir):
        srcdir = Path(srcdir)
        rel = srcdir.relative_to(ROS)
        state = {"defs": [], "opts": [], "incs": [], "removed": [], "created": []}
        local = {"CMAKE_CURRENT_SOURCE_DIR": str(srcdir), "CMAKE_CURRENT_BINARY_DIR": str(SDKBIN / rel)}
        (SDKBIN / rel).mkdir(parents=True, exist_ok=True)
        self._exec(cmake_parse((srcdir / "CMakeLists.txt").read_text(errors="replace"), srcdir / "CMakeLists.txt"),
                   srcdir, local, state)
        # directory properties apply to every target of the directory (CMake semantics)
        for t in state["created"]:
            t.dir_defs = [d for d in state["defs"] if d not in state["removed"]]
            t.removed_defs = list(state["removed"])
            t.dir_opts = list(state["opts"])
            t.dir_incs = list(state["incs"])
        return state["created"]

    def _block(self, cmds, i, openers, closers, mids=()):
        """Index of the matching closer and the positions of middle keywords at depth 0."""
        depth, mid = 0, []
        for j in range(i + 1, len(cmds)):
            nm = cmds[j][0]
            if nm in openers:
                depth += 1
            elif nm in closers:
                if depth == 0:
                    return j, mid
                depth -= 1
            elif nm in mids and depth == 0:
                mid.append(j)
        raise CMakeError(f"unterminated {cmds[i][0]} at line {cmds[i][2]}")

    def _exec(self, cmds, srcdir, local, state):
        i = 0
        while i < len(cmds):
            name, raw, lineno = cmds[i]
            if name == "if":
                end, mids = self._block(cmds, i, {"if"}, {"endif"}, ("elseif", "else"))
                branches, start, cond_raw = [], i, raw
                for m in mids + [end]:
                    branches.append((cond_raw, cmds[start + 1:m], cmds[start][0]))
                    start, cond_raw = m, cmds[m][1]
                for craw, body, kind in branches:
                    if kind == "else" or self.cond(self.args(craw, local, keep_quoted=True), local):
                        self._exec(body, srcdir, local, state)
                        break
                i = end + 1
                continue
            if name == "foreach":
                end, _ = self._block(cmds, i, {"foreach"}, {"endforeach"})
                a = self.args(raw, local)
                var, items = a[0], a[1:]
                if items and items[0] == "IN":
                    items = [x for kw in items[1:] if kw not in ("LISTS", "ITEMS")
                             for x in (local.get(kw, self.vars.get(kw, "")).split(";") if kw in local or kw in self.vars else [kw]) if x]
                for it in items:
                    local[var] = it
                    self._exec(cmds[i + 1:end], srcdir, local, state)
                i = end + 1
                continue
            if name in ("function", "macro"):
                end, _ = self._block(cmds, i, {"function", "macro"}, {"endfunction", "endmacro"})
                self.functions.add(self.args(raw, local)[0].lower())
                i = end + 1
                continue
            self._command(name, self.args(raw, local), srcdir, local, state, lineno)
            i += 1

    def _t(self, name):
        if name not in self.targets:                          # e.g. a target made by a CMake function we do not run
            self.log.append(f"target property set on unknown target {name}: ignored")
            return Target(name, "UNKNOWN", ROS, SDKBIN)
        return self.targets[name]

    @staticmethod
    def _scoped(args, default="PRIVATE"):
        scope, out = default, []
        for a in args:
            if a in ("PRIVATE", "PUBLIC", "INTERFACE"):
                scope = a
            elif a in ("BEFORE", "AFTER", "SYSTEM"):
                continue
            else:
                out.append((scope, a))
        return out

    @staticmethod
    def _add_scoped(prop, pairs):
        for scope, v in pairs:
            if scope in ("PRIVATE", "PUBLIC"):
                prop["PRIVATE"].append(v)
            if scope in ("INTERFACE", "PUBLIC"):
                prop["INTERFACE"].append(v)

    def _path(self, p, srcdir, local):
        if p.startswith("$<"):
            return p
        pp = Path(p)
        return str(pp if pp.is_absolute() else Path(srcdir) / pp)

    def _command(self, name, a, srcdir, local, state, lineno):
        if name == "set":
            if not a:
                return
            vals = [x for x in a[1:] if x not in ("CACHE", "PARENT_SCOPE", "FORCE", "INTERNAL", "STRING", "BOOL", "PATH")]
            if "CACHE" in a[1:]:
                vals = a[1:a.index("CACHE")]
                if a[0] in self.vars or a[0] in local:
                    return
            local[a[0]] = ";".join(vals)
        elif name == "unset":
            local.pop(a[0], None)
        elif name == "list":
            op, var = a[0], a[1]
            cur = [x for x in local.get(var, self.vars.get(var, "")).split(";") if x]
            if op in ("APPEND",):
                cur += a[2:]
            elif op == "PREPEND":
                cur = a[2:] + cur
            elif op == "REMOVE_ITEM":
                cur = [x for x in cur if x not in a[2:]]
            elif op == "REMOVE_DUPLICATES":
                cur = list(dict.fromkeys(cur))
            else:
                self.log.append(f"{srcdir}:{lineno}: list({op}) ignored")
            local[var] = ";".join(cur)
        elif name == "include":
            f = Path(a[0])
            f = f if f.is_absolute() else Path(srcdir) / f
            if f.suffix != ".cmake" or not f.exists():
                self.log.append(f"{srcdir}:{lineno}: include({a[0]}) skipped")
                return
            self._exec(cmake_parse(f.read_text(errors="replace"), f), srcdir, local, state)   # include() keeps the source dir
        elif name in ("add_definitions", "add_compile_definitions"):
            state["defs"] += [x if x.startswith(("-D", "-U", "/D")) else "-D" + x for x in a]
        elif name == "remove_definitions":
            state["removed"] += a
        elif name == "add_compile_options":
            state["opts"] += a
        elif name == "include_directories":
            state["incs"] += [self._path(x, srcdir, local) for x in a if x not in ("BEFORE", "AFTER", "SYSTEM")]
        elif name == "add_library":
            tname = a[0]
            kind = "STATIC"
            rest = a[1:]
            if rest and rest[0] in ("MODULE", "STATIC", "SHARED", "INTERFACE", "OBJECT"):
                kind, rest = rest[0], rest[1:]
            if rest and rest[0] == "IMPORTED":
                return
            t = Target(tname, kind, srcdir, local["CMAKE_CURRENT_BINARY_DIR"])
            t.sources = [self._path(x, srcdir, local) for x in rest if x not in ("EXCLUDE_FROM_ALL",)]
            t.spec = getattr(self, "pending_spec", {}).get(tname)     # spec2def() usually precedes add_library()
            self.targets[tname] = t
            state["created"].append(t)
        elif name == "add_asm_files":                     # gcc.cmake add_asm_files(): MASM .asm/.inc go through asmpp
            out = []
            for x in a[1:]:
                src = Path(self._path(x, srcdir, local))
                relx = src.relative_to(srcdir) if Path(srcdir) in src.parents else Path(src.name)
                if src.suffix == ".asm":
                    dst = Path(local["CMAKE_CURRENT_BINARY_DIR"]) / f"{relx}.s"
                elif src.suffix == ".inc":
                    dst = Path(local["CMAKE_CURRENT_BINARY_DIR"]) / f"{relx}.h"
                else:
                    out.append(str(src))
                    continue
                self.asm_convert = getattr(self, "asm_convert", {})
                self.asm_convert[str(dst)] = str(src)
                out.append(str(dst))
            local[a[0]] = ";".join(out)
        elif name == "target_compile_definitions":
            self._add_scoped(self._t(a[0]).defs, [(s, v if v.startswith("-D") else "-D" + v) for s, v in self._scoped(a[1:])])
        elif name == "target_compile_options":
            self._add_scoped(self._t(a[0]).opts, self._scoped(a[1:]))
        elif name == "target_include_directories":
            self._add_scoped(self._t(a[0]).incs, [(s, self._path(v, srcdir, local)) for s, v in self._scoped(a[1:])])
        elif name == "target_link_libraries":
            self._add_scoped(self._t(a[0]).links, [(("PRIVATE" if s == "PRIVATE" else "PUBLIC"), v) for s, v in self._scoped(a[1:], "PUBLIC")])
        elif name == "target_link_options":
            self._t(a[0]).link_opts += [v for _, v in self._scoped(a[1:])]
        elif name == "add_importlibs":
            self._t(a[0]).importlibs += a[1:]
        elif name == "set_module_type":
            t = self._t(a[0])
            t.module_type = a[1]
            rest = a[2:]
            if "UNICODE" in rest:
                t.defs["PRIVATE"] += ["-DUNICODE", "-D_UNICODE"]
            if "IMAGEBASE" in rest:
                t.image_base = rest[rest.index("IMAGEBASE") + 1]
            if "ENTRYPOINT" in rest:
                t.entry = rest[rest.index("ENTRYPOINT") + 1]
            if a[1] == "kmdfdriver":                         # CMakeMacros.cmake set_module_type(... kmdfdriver)
                t.incs["PRIVATE"].append(str(ROS / "sdk/include/wdf/kmdf/1.17"))
                t.incs["INTERFACE"].append(str(ROS / "sdk/include/wdf/kmdf/1.17"))
                t.importlibs.append("wdfldr")
                t.links["PRIVATE"].append("wdfdriverentry")
        elif name == "set_entrypoint":
            self._t(a[0]).entry = a[1]
        elif name == "spec2def":
            dll, spec = a[0], a[1]
            base = Path(dll).stem
            tgt = self.targets.get(base)
            local["_spec_" + base] = f"{dll}|{self._path(spec, srcdir, local)}"
            self.pending_spec = getattr(self, "pending_spec", {})
            self.pending_spec[base] = (dll, self._path(spec, srcdir, local))
            if tgt:
                tgt.spec = self.pending_spec[base]
        elif name == "add_driver_inf":
            self._t(a[0]).infs += [self._path(x, srcdir, local) for x in a[1:]]
        elif name == "set_target_properties":
            t = self.targets.get(a[0])
            if t and "OUTPUT_NAME" in a:
                t.output_name = a[a.index("OUTPUT_NAME") + 1]
        elif name == "add_custom_command":
            if "POST_BUILD" in a and "COMMAND" in a:
                t = self.targets.get(a[a.index("TARGET") + 1]) if "TARGET" in a else None
                cmd = a[a.index("COMMAND") + 1:]
                if t and cmd and cmd[0] == "native-pefixup":
                    t.post_fixups.append([x for x in cmd[1:] if x not in ("VERBATIM",) and not x.startswith("$<TARGET_FILE")])
        elif name == "add_idl_headers":
            self.idl_headers = getattr(self, "idl_headers", [])
            self.idl_headers.append((Path(srcdir), Path(local["CMAKE_CURRENT_BINARY_DIR"]), a[1:], state))
        elif name in ("add_pch", "add_dependencies", "add_cd_file", "add_registry_inf", "message", "add_subdirectory",
                      "set_source_files_properties", "add_rc_deps", "add_custom_target", "project", "cmake_parse_arguments",
                      "set_property", "get_filename_component", "get_target_property", "file", "string", "math",
                      "add_message_headers", "add_dependency_node", "add_dependency_edge", "add_executable",
                      "set_cpp", "add_rpc_files", "add_iid_library", "add_typelib", "generate_idl_iids", "return",
                      "option", "add_link", "add_kd_file", "sign_driver_if_needed", "enable_language"):
            if name == "set_source_files_properties":
                self.log.append(f"{srcdir}:{lineno}: set_source_files_properties ignored")
        elif name in self.functions:
            self.log.append(f"{srcdir}:{lineno}: call of CMake function {name} defined in this file ignored")
        else:
            self.log.append(f"{srcdir}:{lineno}: CMake command {name}() not evaluated")


# ================================================================================================ host tools, SDK
def run(cmd, cwd=None, check=True, env=None, timeout=900):
    cmd = [str(c) for c in cmd]
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False, env=env,
                       timeout=timeout, errors="replace")
    if check and r.returncode:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}\n{(r.stdout or '')[-4000:]}")
    return r


def host_tool(name, src, compiler="gcc", extra=()):
    """Compile a ReactOS host tool, unmodified, with the host compiler (once)."""
    exe = TOOLS / name
    if exe.exists() and exe.stat().st_mtime >= Path(src).stat().st_mtime:
        return exe
    TOOLS.mkdir(parents=True, exist_ok=True)
    run([compiler, "-O2", "-w", "-D__REACTOS__", "-DTARGET_amd64", *extra, "-o", exe, src])   # top-level CMakeLists.txt defines
    return exe


def build_seh_plugin(log):
    """ReactOS sdk/tools/gcc_plugin_seh, against the mingw cross compiler's plugin headers. None when not buildable."""
    so = TOOLS / "gcc_plugin_seh.so"
    src = ROS / "sdk/tools/gcc_plugin_seh/main.cpp"
    if so.exists() and so.stat().st_mtime >= src.stat().st_mtime:
        return so
    plugdir = run([GCC, "-print-file-name=plugin"]).stdout.strip()
    r = run(["g++", "-shared", "-fPIC", "-O2", "-fno-rtti", "-I", f"{plugdir}/include", "-o", so, src], check=False)
    if r.returncode:
        log.append("gcc_plugin_seh not built (GCC SEH falls back to unregistered handlers): " + " | ".join(first_errors(r.stdout, 2)))
        return None
    log.append("gcc_plugin_seh built from sdk/tools/gcc_plugin_seh/main.cpp")
    return so


def first_errors(text, n=6):
    text = (text or "").replace(str(ROS) + "/", "").replace(str(REPO) + "/", "").replace("/usr/bin/x86_64-w64-mingw32-ld: ", "ld: ")
    lines = [l for l in text.splitlines() if re.search(r"\berror\b|undefined reference|cannot find|No such file|fatal", l)]
    lines = [re.sub(r"^ld: \S+\.o\):", "ld: ", re.sub(r"^ld: \S*/", "ld: ", l)) for l in lines]
    if any("undefined reference" in l for l in lines):          # link errors: one line per missing symbol
        syms = sorted({m.group(1) for l in lines for m in [re.search(r"undefined reference to `([^']+)'", l)] if m})
        return [f"undefined reference: {', '.join(syms[:40])}"] + [l for l in lines if "undefined reference" not in l][:n - 1]
    return lines[:n] if lines else text.strip().splitlines()[-n:]


def prepare_sdk(log):
    """Everything the ReactOS build generates that drivers include, via ReactOS's own host tools."""
    for sub in ("sdk/include/ddk", "sdk/include/psdk", "sdk/include/reactos/mc", "sdk/include/dxsdk", "sdk/include/asm", "lib"):
        (SDKBIN / sub).mkdir(parents=True, exist_ok=True)
    tools = {"hpp": host_tool("hpp", ROS / "sdk/tools/hpp/hpp.c"),
             "spec2def": host_tool("spec2def", ROS / "sdk/tools/spec2def/spec2def.c"),
             # sdk/tools/CMakeLists.txt: pefixup gets _TARGET_PE64 for amd64 and the host_includes directory
             "pefixup": host_tool("pefixup", ROS / "sdk/tools/pefixup.c", extra=("-D_TARGET_PE64", "-I", ROS / "sdk/include/host")),
             "geninc": host_tool("geninc", ROS / "sdk/tools/geninc/geninc.c"),
             "asmpp": host_tool("asmpp", ROS / "sdk/tools/asmpp/asmpp.cpp", compiler="g++",
                                extra=("-std=c++11", "-I", ROS / "sdk/include/host"))}
    for template, out in XDK:
        dest = SDKBIN / "sdk/include" / out
        if not dest.exists():
            run([tools["hpp"], template, dest], cwd=ROS / "sdk/include/xdk")
            log.append(f"hpp {template} -> {out}")
    # add_message_headers(): UTF-8 -> UTF-16LE without BOM (ReactOS's utf16le tool), then windmc -u <-A|-U> -b
    mcdir = SDKBIN / "sdk/include/reactos/mc"
    for mc, flag in MC_FILES.items():
        if not (mcdir / f"{mc}.h").exists():
            conv = mcdir / f"{mc}.mc"
            conv.write_bytes((ROS / "sdk/include/reactos/mc" / f"{mc}.mc").read_text(encoding="utf-8").encode("utf-16-le"))
            run([WINDMC, "-u", flag, "-b", "-h", str(mcdir) + "/", "-r", str(mcdir) + "/", conv])
            log.append(f"utf16le+windmc {flag} {mc}.mc -> {mc}.h")
    # buildno.h / version.h from their .cmake templates (sdk/include/reactos/version.cmake), fixed values
    commit = load_manifest()["upstreams"]["reactos"]["commit"]
    values = {"KERNEL_VERSION_BUILD": "custom", "REVISION": commit[:10], "KERNEL_VERSION": "0.4.16-dev",
              "COMMIT_HASH": commit, "REACTOS_DLL_VERSION_MAJOR": "42", "DLL_VERSION_STR": "42.0.4.16-dev",
              "KERNEL_VERSION_MAJOR": "0", "KERNEL_VERSION_MINOR": "4", "KERNEL_VERSION_PATCH_LEVEL": "16",
              "COPYRIGHT_YEAR": "2026", "KERNEL_VERSION_BUILD_HEX": "0"}
    for tpl in ("buildno.h.cmake", "version.h.cmake"):
        text = (ROS / "sdk/include/reactos" / tpl).read_text()
        for k, v in values.items():
            text = text.replace(f"@{k}@", v).replace(f"${{{k}}}", v)
        (SDKBIN / "sdk/include/reactos" / tpl[:-6]).write_text(text)
    for name, (dll, spec) in IMPORT_SPECS.items():
        make_import_lib(name, dll, ROS / spec, tools, log)
    gen_idl_headers(build_widl(log), log)
    return tools


def make_import_lib(name, dll, spec, tools, log):
    """gcc.cmake generate_import_lib(): spec2def --implib, then dlltool --kill-at."""
    lib = SDKBIN / "lib" / f"lib{name}.a"
    if lib.exists() or not Path(spec).exists():
        return lib if lib.exists() else None
    deffile = SDKBIN / "lib" / f"lib{name}_implib.def"
    run([tools["spec2def"], "--version=0x502", f"-n={dll}", "-a=x86_64", "--implib", f"-d={deffile}", spec])
    run([DLLTOOL, "--def", deffile, "--kill-at", f"--output-lib={lib}", "-t", f"lib{name}"])
    n = sum(1 for l in deffile.read_text().splitlines() if l.strip() and not l.startswith(("LIBRARY", "EXPORTS", ";")))
    log.append(f"spec2def --implib {Path(spec).relative_to(ROS)} -> lib{name}.a ({n} exports)")
    return lib


def build_widl(log):
    """ReactOS sdk/tools/widl + sdk/tools/wpp host tools (flex/bison generated parsers, as their CMakeLists do)."""
    exe = TOOLS / "widl"
    if exe.exists():
        return exe
    if not (shutil.which("flex") and shutil.which("bison")):
        log.append("widl not built: flex/bison missing (IDL-generated psdk headers unavailable)")
        return None
    gen = TOOLS / "widl-gen"
    gen.mkdir(parents=True, exist_ok=True)
    w, p = ROS / "sdk/tools/widl", ROS / "sdk/tools/wpp"
    run(["flex", "-o", gen / "parser.yy.c", w / "parser.l"])
    run(["bison", "-d", "-o", gen / "parser.tab.c", w / "parser.y"])
    run(["flex", "-o", gen / "ppl.yy.c", p / "ppl.l"])
    run(["bison", "-d", "-o", gen / "ppy.tab.c", p / "ppy.y"])
    srcs = [w / f for f in ("attribute.c", "client.c", "expr.c", "hash.c", "header.c", "proxy.c", "register.c", "server.c",
                            "typegen.c", "typelib.c", "typetree.c", "utils.c", "widl.c", "write_msft.c", "write_sltg.c")]
    srcs += [gen / "parser.yy.c", gen / "parser.tab.c", ROS / "sdk/tools/port/getopt.c", ROS / "sdk/tools/port/getopt1.c",
             ROS / "sdk/tools/port/mkstemps.c", p / "wpp.c", gen / "ppl.yy.c", gen / "ppy.tab.c"]
    r = run(["gcc", "-O2", "-w", "-D__REACTOS__", "-DTARGET_amd64", "-D_CRT_DECLARE_NONSTDC_NAMES=1", "-D_CRT_NONSTDC_NO_DEPRECATE", "-DINT16=SHORT",
             "-DLANG_SCOTTISH_GAELIC=0x91", '-DINCLUDEDIR="unused"', '-DLIBDIR="unused"', "-I", gen, "-I", w, "-I", p,
             "-I", ROS / "sdk/include/host", "-o", exe, *srcs], check=False)
    if r.returncode:
        log.append("widl not built: " + " | ".join(first_errors(r.stdout, 3)))
        return None
    log.append("widl built from sdk/tools/widl + sdk/tools/wpp (flex/bison)")
    return exe


def gen_idl_headers(widl, log):
    """sdk/include/psdk/CMakeLists.txt add_idl_headers(): widl <includes> <defines> -m64 --win64 -b amd64-x-y -nostdinc
    -Oicf -h (sdk/cmake/widl-support.cmake)."""
    if not widl:
        return 0
    cm = CMakeLite("GNU", "13", {}, log)
    cm.run_dir(ROS / "sdk/include/psdk")
    made = 0
    for srcdir, bindir, files, state in getattr(cm, "idl_headers", []):
        bindir.mkdir(parents=True, exist_ok=True)
        incs = [str(srcdir), str(bindir)] + state["incs"] + \
            [str(SDKBIN / p[1:]) if p.startswith("@") else str(ROS / p) for p in ROOT_INCLUDES]
        defs = [d for d in ROOT_DEFINES + state["defs"] if d.startswith("-D")]
        for f in files:
            out = bindir / (Path(f).name.rsplit(".", 1)[0] + ".h")
            if out.exists():
                continue
            r = run([widl, *[x for i in incs for x in ("-I", i)], *defs, "-m64", "--win64", "-b", "amd64-x-y", "-nostdinc",
                     "-Oicf", "-h", "-o", out, Path(f).name], cwd=srcdir, check=False)
            if r.returncode:
                log.append(f"widl {Path(f).name}: " + " | ".join(first_errors(r.stdout, 2)))
            else:
                made += 1
    log.append(f"widl: {made} psdk IDL headers generated")
    return made


def gen_ksamd64(tc, tools, log):
    """sdk/include/asm/CMakeLists.txt: build genincdata.c as a module, extract ksamd64.inc with geninc."""
    inc = SDKBIN / "sdk/include/asm/ksamd64.inc"
    if inc.exists():
        return True
    cm = CMakeLite(tc.cc_id, tc.version, tc.tool_paths, log)
    tgts = {t.name: t for t in cm.run_dir(ROS / "sdk/include/asm")}
    t = tgts.get("genincdata")
    if not t:
        return False
    rec = tc.build_target(t, cm, CORPUS / "_genincdata" / tc.name, tools, need_link=True, entry_zero=True)
    if rec["status"] != "built":
        log.append("genincdata failed: " + "; ".join(rec["errors"][:2]))
        return False
    r = run([tools["geninc"], REPO / rec["sys"], inc], check=False)
    log.append(f"geninc -> ksamd64.inc: {'ok' if r.returncode == 0 else r.stdout[-200:]}")
    return r.returncode == 0


# ============================================================================================================= toolchain
class Toolchain:
    def __init__(self, cc, seh_plugin):
        self.name = cc
        self.seh_plugin = seh_plugin
        if cc == "gcc":
            self.cc_id, self.cc = "GNU", [GCC]
            self.cxx = [GXX] if shutil.which(GXX) else [CLANGXX, f"--target={TRIPLE}"]
            self.cxx_id = "GNU" if shutil.which(GXX) else "Clang"
            self.version = run([GCC, "-dumpfullversion"], check=False).stdout.strip() or "13"
        else:
            self.cc_id, self.cc = "Clang", [CLANG, f"--target={TRIPLE}"]
            self.cxx, self.cxx_id = [CLANGXX, f"--target={TRIPLE}"], "Clang"
            self.version = run([CLANG, "-dumpversion"], check=False).stdout.strip() or "18"
        self.tool_paths = {"native-gcc_plugin_seh": str(seh_plugin) if seh_plugin else ""}
        self.lib_cache = {}                                  # static library name -> (path | None, errors)

    @property
    def seh_mode(self):
        if self.cc_id == "GNU":
            return "gcc_plugin_seh (ReactOS amd64 GCC SEH)" if self.seh_plugin else "GCC without SEH plugin: handlers not registered"
        return "dummy PSEH (ReactOS clang amd64 configuration: try bodies unprotected)"

    # ---- usage requirements
    def collect(self, t, cm, seen=None):
        """Transitive INTERFACE usage requirements of t's link libraries + the libraries to link."""
        seen = seen if seen is not None else set()
        defs, opts, incs, libs = [], [], [], []
        for name in t.links["PRIVATE"] + t.links["INTERFACE"]:
            if name in seen:
                continue
            seen.add(name)
            dep = self.find_lib(name, cm)
            if dep is None:
                libs.append(name)
                continue
            defs += dep.defs["INTERFACE"]
            opts += dep.opts["INTERFACE"]
            incs += dep.incs["INTERFACE"]
            libs.append(name)
            d2, o2, i2, l2 = self.collect(dep, cm, seen)
            defs, opts, incs, libs = defs + d2, opts + o2, incs + i2, libs + l2
        return defs, opts, incs, libs

    def find_lib(self, name, cm):
        if name in cm.targets:
            return cm.targets[name]
        where = library_index().get(name)
        if not where:
            return None
        for tt in cm.run_dir(where):
            pass
        return cm.targets.get(name)

    def parts(self, t, cm, lang):
        """(options, defines, include dirs) of t for one language: root state, directory state, the target's own
        PRIVATE/PUBLIC properties and the INTERFACE properties of everything it links (generator expressions evaluated)."""
        cc_id = self.cxx_id if lang == "CXX" else self.cc_id
        opts = [f for l, f in root_options(cc_id) if l in (None, lang)]
        incs = [str(SDKBIN / p[1:]) if p.startswith("@") else str(ROS / p) for p in ROOT_INCLUDES]
        idefs, iopts, iincs, _ = self.collect(t, cm)
        removed = getattr(t, "removed_defs", [])
        defs = [d for d in ROOT_DEFINES + t.dir_defs if d not in removed] + t.defs["PRIVATE"] + idefs
        opts += t.dir_opts + t.opts["PRIVATE"] + iopts
        # CMAKE_INCLUDE_CURRENT_DIR is ON in the top-level CMakeLists.txt: source and binary dir come first
        incs = [str(t.srcdir), str(t.bindir)] + t.dir_incs + t.incs["PRIVATE"] + iincs + incs

        def ev(items):
            out = []
            for x in items:
                v = cm.genex(x, lang) if "$<" in x else x
                out += [p for p in v.split(";") if p and p != "-fplugin="]   # -fplugin= : SEH plugin not available
            return out
        return ev(opts), ev(defs), list(dict.fromkeys(ev(incs)))

    def flags(self, t, cm, lang):
        opts, defs, incs = self.parts(t, cm, lang)
        return opts + defs + [x for i in incs for x in ("-I", i)]

    # ---- build one CMake target
    def build_target(self, t, cm, outdir, tools, need_link=True, entry_zero=False, jobs=2):
        outdir.mkdir(parents=True, exist_ok=True)
        rec = {"target": t.name, "dir": str(t.srcdir.relative_to(ROS)), "cc": self.name, "status": "built", "errors": [],
               "warnings": 0, "sources": 0, "seh": self.seh_mode}
        t0 = time.time()
        srcs = [Path(s) for s in t.sources if Path(s).suffix.lower() in (".c", ".cpp", ".cc", ".s", ".S")]
        srcs = [s for s in srcs if s.suffix != ".s" or True]
        rcs = [Path(s) for s in t.sources if Path(s).suffix.lower() == ".rc"]
        defs = [Path(s) for s in t.sources if Path(s).suffix.lower() == ".def"]
        rec["sources"] = len(srcs)
        for dst, src in getattr(cm, "asm_convert", {}).items():      # native-asmpp <src> > <dst>
            if not Path(dst).exists():
                Path(dst).parent.mkdir(parents=True, exist_ok=True)
                r = run([tools["asmpp"], src], check=False)
                if r.returncode:
                    cm.log.append(f"asmpp {src}: {r.stdout[-200:]}")
                else:
                    Path(dst).write_text(r.stdout)
        if any(s.suffix.lower() == ".s" for s in srcs) and not gen_ksamd64(self, tools, cm.log):
            rec.update(status="failed", errors=["assembler sources need sdk/include/asm/ksamd64.inc (geninc failed)"])
            return rec
        # spec2def module .def + stubs (modules exporting an API)
        if t.spec:
            dll, spec = t.spec
            t.bindir.mkdir(parents=True, exist_ok=True)
            mdef, stubs = t.bindir / f"{Path(dll).stem}.def", t.bindir / f"{Path(dll).stem}_stubs.c"
            run([tools["spec2def"], f"-n={dll}", "-a=x86_64", f"-d={mdef}", f"-s={stubs}", "--version=0x502", spec])
            srcs.append(stubs)
            defs = [d for d in defs if d.name != mdef.name] + [mdef]
        failures, objs = [], []

        def compile_one(src):
            suffix = src.suffix.lower()
            lang = "CXX" if suffix in (".cpp", ".cc") else ("ASM" if suffix == ".s" else "C")
            obj = outdir / (re.sub(r"[^A-Za-z0-9_.-]", "_", str(src.relative_to(ROS) if ROS in src.parents else src.name)) + ".o")
            if lang == "ASM":
                cmd = self.cc + ["-x", "assembler-with-cpp", "-o", obj, "-I", ROS / "sdk/include/asm", "-I", SDKBIN / "sdk/include/asm"] + \
                    self.flags(t, cm, "ASM") + ["-D__ASM__", "-c", src]
            else:
                cc = self.cxx if lang == "CXX" else self.cc
                cmd = cc + self.flags(t, cm, lang) + ["-o", obj, "-c", src]
            # object cache: reuse when the exact command line was used before and the object is newer than the source
            # (headers under build/upstream never change: the tree is pinned)
            stamp = obj.with_suffix(".cmd")
            key = hashlib.sha256("\0".join(str(c) for c in cmd).encode()).hexdigest()
            if obj.exists() and stamp.exists() and stamp.read_text() == key and obj.stat().st_mtime >= src.stat().st_mtime:
                return src, obj, subprocess.CompletedProcess(cmd, 0, "", None), cmd
            r = run(cmd, check=False, cwd=t.srcdir)
            if r.returncode == 0:
                stamp.write_text(key)
            return src, obj, r, cmd

        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            for src, obj, r, cmd in pool.map(compile_one, srcs):
                rec["warnings"] += r.stdout.count("warning:")
                if r.returncode:
                    failures.append((src, first_errors(r.stdout)))
                    rec.setdefault("failed_command", " ".join(str(c) for c in cmd))
                else:
                    objs.append(obj)
        if failures:
            rec["status"] = "compile-failed"
            rec["failed_sources"] = [str(s.relative_to(t.srcdir)) if t.srcdir in s.parents else s.name for s, _ in failures]
            rec["errors"] = [f"{s.name}: {e}" for s, errs in failures for e in errs][:14]
            rec["seconds"] = round(time.time() - t0, 1)
            return rec
        if t.kind in ("STATIC", "OBJECT") or not need_link:
            lib = outdir / f"lib{t.name}.a"
            if lib.exists():
                lib.unlink()
            if objs:
                run([AR, "rcs", lib, *objs])
            rec["lib"] = str(lib)
            rec["seconds"] = round(time.time() - t0, 1)
            return rec
        for rc in rcs:                                        # gcc.cmake CMAKE_RC_COMPILE_OBJECT
            res = outdir / (rc.stem + ".res.o")
            _, dfs, incs = self.parts(t, cm, "RC")
            cmd = [WINDRES, "-O", "coff", f"--preprocessor={GCC}", "--preprocessor-arg=-E", "--preprocessor-arg=-nostdinc",
                   "--preprocessor-arg=-xc-header", *[x for i in incs for x in ("-I", i)], "-DRC_INVOKED", "-D__WIN32__=1",
                   "-D__FLAT__=1", "-DLANGUAGE_EN_US", *[d for d in dfs if " " not in d], rc, res]
            r = run(cmd, check=False, cwd=t.srcdir)
            if r.returncode:
                rec.setdefault("resource_errors", []).extend(first_errors(r.stdout, 3))
            else:
                objs.append(res)
        # link: sdk/cmake gcc.cmake set_module_type_toolchain + CMakeMacros set_module_type
        _, _, _, libs = self.collect(t, cm)
        libpaths, missing = [], []
        for name in libs:
            p = self.static_lib(name, cm, tools)
            if p:
                libpaths.append(p)
            elif name not in ("pseh",) and not name.startswith("lib"):
                missing.append(name)
        imps = []
        for name in t.importlibs:
            p = SDKBIN / "lib" / f"lib{name}.a"
            if not p.exists():
                spec = IMPORT_SPECS.get(name)
                if spec:
                    make_import_lib(name, spec[0], ROS / spec[1], tools, cm.log)
            if p.exists():
                imps.append(p)
            else:
                missing.append(f"lib{name} (import library)")
        suffix = ".sys" if t.module_type in ("kernelmodedriver", "wdmdriver", "kmdfdriver") else ".dll"
        out = outdir / f"{getattr(t, 'output_name', t.name)}{suffix}"
        entry = "0" if entry_zero else (t.entry or {"kernelmodedriver": "DriverEntry", "wdmdriver": "DriverEntry",
                                                   "kmdfdriver": "FxDriverEntry"}.get(t.module_type, "0"))
        cmd = [GCC] + LINK_FLAGS + ["-Wl,--subsystem,native:5.01", f"-Wl,-entry,{entry}",
                                    f"-Wl,--image-base,{t.image_base or '0x00010000'}", f"-Wl,-T,{ROS / 'sdk/cmake/init-section.lds'}"]
        if t.module_type == "wdmdriver":
            cmd.append("-Wl,--wdmdriver")
        cmd += [x for x in t.link_opts if not x.startswith("$<")]
        cmd += ["-o", out, "-Wl,--start-group", *objs, *[str(d) for d in defs], *libpaths, *imps, "-Wl,--end-group"]
        # compiler support library (___chkstk_ms for frames > 4 KiB, 128-bit arithmetic): only members that resolve
        # otherwise undefined symbols are pulled in; which ones is recorded (libgcc_members)
        cmd += [run([GCC, "-print-libgcc-file-name"]).stdout.strip(), "-Wl,--trace-symbol=___chkstk_ms"]
        r = run(cmd, check=False)
        rec["link_command"] = " ".join(str(c) for c in cmd)
        rec["libgcc_chkstk"] = bool(re.search(r"libgcc\.a\([^)]*\): definition of ___chkstk_ms", r.stdout or ""))
        if missing:
            rec["missing_libraries"] = missing
        if r.returncode or not out.exists():
            rec["status"] = "link-failed"
            rec["errors"] = first_errors(r.stdout, 14)
            rec["seconds"] = round(time.time() - t0, 1)
            return rec
        # native-pefixup --kernelmodedriver (+ the module's own POST_BUILD fixups)
        if t.module_type in ("kernelmodedriver", "wdmdriver", "kmdfdriver"):
            ty = "wdmdriver" if t.module_type in ("wdmdriver", "kmdfdriver") else "kernelmodedriver"
            fx = run([tools["pefixup"], f"--{ty}", out], check=False)
            rec["pefixup"] = "ok" if fx.returncode == 0 else fx.stdout[-200:]
            for extra in t.post_fixups:
                run([tools["pefixup"], *extra, out], check=False)
        rec.update(describe_pe(out))
        rec["sys"] = str(out.relative_to(REPO))
        rec["seconds"] = round(time.time() - t0, 1)
        return rec

    def static_lib(self, name, cm, tools):
        if name in self.lib_cache:
            return self.lib_cache[name][0]
        t = self.find_lib(name, cm)
        if t is None or t.kind == "INTERFACE":
            self.lib_cache[name] = (None, [])
            return None
        rec = self.build_target(t, cm, CORPUS / "_lib" / self.name / name, tools, need_link=False)
        path = rec.get("lib") if rec["status"] == "built" else None
        self.lib_cache[name] = (path, rec["errors"])
        if not path:
            cm.log.append(f"static library {name} ({rec['dir']}) failed for {self.name}: {rec['errors'][:2]}")
        return path


_LIBINDEX = {}


def library_index():
    """add_library() name -> directory, over sdk/lib and drivers (a CMake project would know this from add_subdirectory)."""
    if _LIBINDEX:
        return _LIBINDEX
    for cm in list((ROS / "sdk/lib").rglob("CMakeLists.txt")) + list((ROS / "sdk/lib").rglob("*.cmake")) + \
            list((ROS / "drivers").rglob("CMakeLists.txt")):
        try:
            text = cm.read_text(errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"^\s*add_library\(\s*([A-Za-z0-9_+.-]+)\s+(?!.*IMPORTED)", text, re.M):
            _LIBINDEX.setdefault(m.group(1), cm.parent)
    return _LIBINDEX


# ============================================================================================================= PE facts
def describe_pe(path):
    out = run([OBJDUMP, "-p", path], check=False).stdout
    hdr = run([OBJDUMP, "-h", path], check=False).stdout
    rec = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    m = re.search(r"Subsystem\s+([0-9a-f]+)", out)
    rec["subsystem"] = int(m.group(1), 16) if m else None
    m = re.search(r"AddressOfEntryPoint\s+([0-9a-f]+)", out)
    rec["entry_rva"] = "0x" + m.group(1).lstrip("0") if m else None
    m = re.search(r"DllCharacteristics\s+([0-9a-f]+)", out)
    rec["dll_characteristics"] = "0x" + m.group(1)[-4:] if m else None
    rec["sections"] = re.findall(r"^\s+\d+\s+(\S+)\s+[0-9a-f]{8}\s+[0-9a-f]{16}", hdr, re.M)
    imports, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s*DLL Name: (\S+)", line)
        if m:
            cur = m.group(1).lower()
            imports.setdefault(cur, [])
            continue
        if cur:
            m = re.match(r"\s*[0-9a-f]+\s+\d+\s+(\S+)\s*$", line)
            if m:
                imports[cur].append(m.group(1))
            elif not line.strip() and imports[cur]:
                cur = None
    rec["imports"] = {k: sorted(set(v)) for k, v in imports.items() if v}
    rec["import_count"] = sum(len(v) for v in rec["imports"].values())
    return rec


FRAMEWORKS = [("wdfldr.sys", "KMDF (Wdf01000 via wdfldr)"), ("ndis.sys", "NDIS miniport"), ("storport.sys", "StorPort miniport"),
              ("scsiport.sys", "SCSI port miniport"), ("classpnp.sys", "storage class (classpnp)"), ("portcls.sys", "PortCls audio"),
              ("ks.sys", "kernel streaming"), ("hidclass.sys", "HID minidriver"), ("usbd.sys", "USB"),
              ("videoprt.sys", "XDDM video miniport"), ("dxgkrnl.sys", "WDDM (dxgkrnl)")]


def classify(rec, t):
    imps = rec.get("imports", {})
    fw = [label for dll, label in FRAMEWORKS if dll in imps]
    ndis = None
    if "ndis.sys" in imps:
        defs = " ".join(t.dir_defs + t.defs["PRIVATE"])
        m = re.search(r"-DNDIS(\d)(\d)_MINIPORT", defs)
        api = "NdisMRegisterMiniportDriver (NDIS 6.x)" if "NdisMRegisterMiniportDriver" in imps["ndis.sys"] else \
            ("NdisMRegisterMiniport (NDIS 5.x)" if "NdisMRegisterMiniport" in imps["ndis.sys"] else "?")
        ndis = f"NDIS {m.group(1)}.{m.group(2)} miniport (-DNDIS{m.group(1)}{m.group(2)}_MINIPORT), registers via {api}" if m else api
    return ("; ".join(fw) or "WDM (ntoskrnl/hal only)"), ndis


# ================================================================================================================ main
def build_corpus_driver(name, tc, tools, log, jobs):
    sub, what = CORPUS_DRIVERS[name]
    srcdir = ROS / sub
    rec = {"driver": name, "what": what, "dir": sub, "cc": tc.name}
    if not (srcdir / "CMakeLists.txt").exists():
        rec.update(status="missing", errors=[f"{sub}/CMakeLists.txt not in the pinned tree"])
        return rec
    cm = CMakeLite(tc.cc_id, tc.version, tc.tool_paths, log)
    try:
        created = cm.run_dir(srcdir)
    except CMakeError as e:
        rec.update(status="cmake-failed", errors=[str(e)])
        return rec
    t = next((x for x in created if x.name == name), None) or next((x for x in created if x.kind in ("MODULE", "SHARED")), None)
    if t is None:
        rec.update(status="cmake-failed", errors=[f"no module target in {sub}/CMakeLists.txt"])
        return rec
    tc.lib_cache = {}
    r = tc.build_target(t, cm, CORPUS / name / tc.name, tools, jobs=jobs)
    rec.update(r)
    rec["module_type"] = t.module_type
    rec["cmake"] = {"defines": t.dir_defs + t.defs["PRIVATE"], "link_libraries": list(dict.fromkeys(t.links["PRIVATE"] + t.links["INTERFACE"])),
                    "importlibs": t.importlibs, "infs": [str(Path(i).relative_to(ROS)) for i in t.infs],
                    "exports_api": bool(t.spec)}
    rec["framework"], rec["ndis"] = classify(rec, t) if rec["status"] == "built" else (None, None)
    rec["static_libraries"] = {k: ("ok" if v[0] else (v[1][:2] or "not a buildable library")) for k, v in tc.lib_cache.items()}
    return rec


def make_package(name, rec):
    """Driver package (the .sys + its own INF, unchanged, as a vendor ships it) for store.py / shzpnp tests."""
    if rec.get("status") != "built" or not rec["cmake"]["infs"]:
        return None
    pkg = PACKAGES / name
    if pkg.exists():
        shutil.rmtree(pkg)
    pkg.mkdir(parents=True)
    shutil.copy2(REPO / rec["sys"], pkg / Path(rec["sys"]).name)
    for inf in rec["cmake"]["infs"]:
        shutil.copy2(ROS / inf, pkg / Path(inf).name)
    return str(pkg.relative_to(REPO))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("drivers", nargs="*", help="driver names (default: all)")
    ap.add_argument("--cc", choices=["gcc", "clang"], action="append", help="compiler(s); default: gcc, then clang for what gcc could not build")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--packages", action="store_true", help="assemble build/shizukudos/ntdrv/packages/<driver>/")
    args = ap.parse_args()
    if args.list:
        for n, (d, what) in CORPUS_DRIVERS.items():
            print(f"{n:10} {d:38} {what}")
        return 0
    for tool in (GCC, DLLTOOL, WINDRES, WINDMC, OBJDUMP, AR, "gcc", "g++"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    if not ROS.is_dir():
        raise SystemExit("ReactOS tree missing: run shizukudos/ntdrv/corpus/fetch.py")
    names = args.drivers or list(CORPUS_DRIVERS)
    for n in names:
        if n not in CORPUS_DRIVERS:
            raise SystemExit(f"unknown driver {n}; known: {', '.join(CORPUS_DRIVERS)}")
    log = []
    tools = prepare_sdk(log)
    plugin = build_seh_plugin(log)
    result_path = CORPUS / "build-result.json"
    results = json.loads(result_path.read_text()) if result_path.exists() else {"drivers": {}}
    results.update({"built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "reactos_commit": load_manifest()["upstreams"]["reactos"]["commit"],
                    "toolchain": {"gcc": run([GCC, "--version"], check=False).stdout.splitlines()[0],
                                  "clang": (run([CLANG, "--version"], check=False).stdout.splitlines() or ["-"])[0] if shutil.which(CLANG) else None,
                                  "gcc_plugin_seh": bool(plugin)}})
    ccs = args.cc or ["gcc", "clang"]
    for cc in ccs:
        if cc == "clang" and not shutil.which(CLANG):
            log.append("clang not installed: clang builds skipped")
            continue
        tc = Toolchain(cc, plugin)
        for n in names:
            prior = results["drivers"].get(n, {})
            if not args.cc and cc == "clang" and prior.get("gcc", {}).get("status") == "built":
                continue                                      # default mode: clang only where gcc did not build
            try:
                rec = build_corpus_driver(n, tc, tools, log, args.jobs)
            except Exception as e:                            # noqa: BLE001 - record and continue with the next driver
                rec = {"driver": n, "cc": cc, "status": "script-error", "errors": [f"{type(e).__name__}: {e}"[:400]]}
            results["drivers"].setdefault(n, {})[cc] = rec
            extra = f" {rec.get('bytes', 0)} bytes, {rec.get('import_count', 0)} imports from {', '.join(rec.get('imports', {}))}" \
                if rec["status"] == "built" else ""
            print(f"{n:10} {cc:5} {rec['status']:14}{extra}", flush=True)
            for e in rec.get("errors", [])[:3]:
                print(f"           {e[:220]}", flush=True)
    for n in names:
        best = next((results["drivers"][n][c] for c in ("gcc", "clang") if results["drivers"][n].get(c, {}).get("status") == "built"), None)
        results["drivers"][n]["best"] = best["cc"] if best else None
        if args.packages and best:
            results["drivers"][n]["package"] = make_package(n, best)
    results["log"] = sorted(set(log))
    write_json(result_path, results)
    built = sum(1 for n in names if results["drivers"][n].get("best"))
    print(f"\n{built} of {len(names)} drivers built; results in {result_path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
