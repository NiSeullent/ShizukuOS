#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the NT driver corpus: real, unmodified x64 WDM/NDIS/StorPort driver sources (ReactOS, virtio-win) compiled
with mingw-w64 or clang into PE32+ .sys images, without RosBE, CMake or the WDK.

Why: the ShizukuDOS 10 NT driver host (docs/shizukudos10/NTDRV.md, agent "ntdrv-host") must be measured against
drivers nobody here wrote. Every .sys produced here is built from the upstream sources exactly as fetched by
shizukudos/ntdrv/corpus/fetch.py (pinned in shizukudos/upstream/manifest.json). Nothing under build/upstream is
edited; the only things this script generates are what the ReactOS build would generate itself:

  * sdk/include/xdk templates -> wdm.h, ntddk.h, ntifs.h, ntdef.h, winnt.h, devioctl.h (ReactOS's own `hpp` tool,
    compiled unmodified from sdk/tools/hpp/hpp.c with the host compiler);
  * sdk/include/reactos/mc/*.mc -> bugcodes.h, ntstatus.h, pciclass.h, ... (binutils windmc);
  * buildno.h / version.h from their .cmake templates (fixed values);
  * import libraries for ntoskrnl.exe, hal.dll, ndis.sys, storport.sys, scsiport.sys, classpnp.sys from the ReactOS
    .spec files (ReactOS's `spec2def` host tool, unmodified, then dlltool);
  * the static helper libraries ReactOS links into some drivers (arbiter, dmilib, pseh dummy), from their sources.

SDK profiles (--sdk):
  reactos  ReactOS headers only (-nostdinc), exactly the include path ReactOS uses. Shows which drivers need
           ReactOS-internal headers (ndk/, reactos/drivers/, debug.h ...).
  mingw    the mingw-w64 DDK headers (/usr/x86_64-w64-mingw32/include/ddk) and its libntoskrnl/libhal/libndis.
           A driver that builds here is a "plain DDK" driver.
Compilers (--cc): gcc = x86_64-w64-mingw32-gcc; clang = clang --target=x86_64-w64-mingw32 (real SEH via
__C_specific_handler, C++ for uniata). Structured exception handling: ReactOS builds amd64 GCC with a GCC plugin
(sdk/tools/gcc_plugin_seh); without it, gcc builds use the dummy PSEH (_USE_DUMMY_PSEH: try bodies run
unprotected) and clang builds use native __try/__except (_USE_NATIVE_SEH), both pure compiler-flag choices.

Outputs: build/shizukudos/ntdrv/corpus/<driver>/<driver>.sys and build/shizukudos/ntdrv/corpus/build-result.json
(status, command lines, first errors, sha256, imports per DLL). Driver packages (.sys + INF) for the store tests:
build/shizukudos/ntdrv/packages/<driver>/.
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
VIRTIO = UPSTREAM_DIR / "virtio-win"
OUT = BUILD / "ntdrv"
TOOLS = OUT / "tools"
SDK = OUT / "rossdk"                     # generated ReactOS SDK pieces
CORPUS = OUT / "corpus"
PACKAGES = OUT / "packages"
MINGW_ROOT = Path("/usr/x86_64-w64-mingw32")

GCC = "x86_64-w64-mingw32-gcc"
CLANG = "clang"
CLANGXX = "clang++"
TRIPLE = "x86_64-w64-mingw32"
DLLTOOL = "x86_64-w64-mingw32-dlltool"
WINDRES = "x86_64-w64-mingw32-windres"
WINDMC = "x86_64-w64-mingw32-windmc"
OBJDUMP = "x86_64-w64-mingw32-objdump"

# ReactOS CMakeLists.txt / sdk/cmake/gcc.cmake for ARCH=amd64 (see the docstring; values copied, not invented)
ROS_DEFINES = ["-D__REACTOS__", "-D_AMD64_", "-D__x86_64__", "-D_WIN64", "-D_M_AMD64", "-D_M_X64", "-U_X86_", "-UWIN32",
               "-DWINVER=0x502", "-D_WIN32_IE=0x603", "-D_WIN32_WINNT=0x502", "-D_WIN32_WINDOWS=0x502", "-D_SETUPAPI_VER=0x502",
               "-DMINGW_HAS_SECURE_API=1", "-DD3D_UMD_INTERFACE_VERSION=0x000C", "-DDXGKDDI_INTERFACE_VERSION=0x1052",
               "-DDLL_EXPORT_VERSION=0x502", "-DDBG=0", "-DUSE_COMPILER_EXCEPTIONS", "-D_NEW_DELETE_OPERATORS_",
               "-D_USE_PSEH3=1", "-D_GLIBCXX_HAVE_BROKEN_VSWPRINTF", "-D_CRT_SUPPRESS_RESTRICT", "-D__RELFILE__=__FILE__"]
ROS_CFLAGS = ["-pipe", "-fms-extensions", "-fno-strict-aliasing", "-fno-common", "-mlong-double-64", "-O2", "-g0",
              "-fno-aggressive-loop-optimizations", "-mcx16", "-Wall", "-Wno-unused-but-set-variable", "-Wno-unused-variable",
              "-Wno-unused-function", "-Wno-misleading-indentation", "-Wno-pragma-pack", "-Wno-unused-const-variable"]
GCC_ONLY = ["-mpreferred-stack-boundary=4"]
LINK_FLAGS = ["-shared", "-nostdlib", "-nostartfiles", "-Wl,--subsystem,native:5.01", "-Wl,-entry,DriverEntry",
              "-Wl,--image-base,0x00010000", "-Wl,--exclude-all-symbols,-file-alignment=0x1000,-section-alignment=0x1000",
              "-Wl,--major-image-version,5", "-Wl,--minor-image-version,01", "-Wl,--major-os-version,5", "-Wl,--minor-os-version,01"]
INIT_LDS = ROS / "sdk/cmake/init-section.lds"

# import libraries generated from ReactOS .spec files: name -> (spec, dll name)
SPECS = {"ntoskrnl": ("ntoskrnl/ntoskrnl.spec", "ntoskrnl.exe"), "hal": ("hal/hal.spec", "hal.dll"),
         "ndis": ("drivers/network/ndis/ndis.spec", "ndis.sys"), "storport": ("drivers/storage/port/storport/storport.spec", "storport.sys"),
         "scsiport": ("drivers/storage/port/scsiport/scsiport.spec", "scsiport.sys"),
         "classpnp": ("drivers/storage/class/classpnp/classpnp.spec", "classpnp.sys")}
MC_FILES = ["bugcodes", "ntstatus", "ntiologc", "pciclass", "errcodes", "neteventmsg", "netmsgmsg", "net_msg"]
XDK = [("wdm.template.h", "ddk/wdm.h"), ("ntddk.template.h", "ddk/ntddk.h"), ("ntifs.template.h", "ddk/ntifs.h"),
       ("devioctl.template.h", "psdk/devioctl.h"), ("ntdef.template.h", "psdk/ntdef.h"), ("winnt.template.h", "psdk/winnt.h")]

# ---------------------------------------------------------------------------------------------------------- the corpus
# Each entry mirrors the driver's own CMakeLists.txt: sources (relative to `dir`), extra defines, include dirs, the
# import libraries (add_importlibs) and static libraries (target_link_libraries). "framework" is what the driver is
# written against, for the report. "package_inf" is the driver's shipping INF when it has one.
D = {}


def drv(name, dir, sources, rc=None, defines=(), includes=(), importlibs=("ntoskrnl", "hal"), libs=(), framework="WDM",
        cxx=False, seh=False, package_inf=None, extra_cflags=(), note="", tree="reactos", pch=None):
    D[name] = dict(name=name, dir=dir, sources=list(sources), rc=rc, defines=list(defines), includes=list(includes),
                   importlibs=list(importlibs), libs=list(libs), framework=framework, cxx=cxx, seh=seh, package_inf=package_inf,
                   extra_cflags=list(extra_cflags), note=note, tree=tree, pch=pch)


drv("null", "drivers/base/null", ["null.c"], rc="null.rc", libs=["pseh"], framework="WDM (wdm.h)")
drv("beep", "drivers/base/beep", ["beep.c"], rc="beep.rc", framework="WDM (ntddk.h + ntddbeep.h)")
drv("kbdclass", "drivers/input/kbdclass", ["kbdclass.c", "misc.c", "guid.c"], rc="kbdclass.rc", libs=["pseh"], seh=True,
    framework="WDM class driver (ntifs.h, ntddkbd.h)")
drv("mouclass", "drivers/input/mouclass", ["misc.c", "mouclass.c", "guid.c"], rc="mouclass.rc", libs=["pseh"], seh=True,
    framework="WDM class driver (ntifs.h, ntddmou.h)")
drv("i8042prt", "drivers/input/i8042prt", ["createclose.c", "hwhacks.c", "i8042prt.c", "keyboard.c", "misc.c", "mouse.c", "pnp.c",
    "ps2pp.c", "readwrite.c", "registry.c", "guid.c"], rc="i8042prt.rc", libs=["dmilib"], includes=["sdk/lib/dmilib"],
    framework="WDM port driver (ntifs.h, kbdmou.h, ntdd8042.h, WMI)")
drv("serial", "drivers/serial/serial", ["circularbuffer.c", "cleanup.c", "close.c", "create.c", "devctrl.c", "info.c", "legacy.c", "misc.c",
    "pnp.c", "power.c", "rw.c", "serial.c", "guid.c"], rc="serial.rc", framework="WDM (ntddk.h, ntddser.h)")
drv("pci", "drivers/bus/pci", ["fdo.c", "pci.c", "pdo.c"], rc="pci.rc", includes=["sdk/include/reactos/drivers"],
    framework="WDM bus driver (ntifs.h, cmreslist.h, ntstrsafe.h)")
drv("pcix", "drivers/bus/pcix", ["arb/ar_busno.c", "arb/ar_memio.c", "arb/arb_comn.c", "arb/tr_irq.c", "intrface/agpintrf.c",
    "intrface/busintrf.c", "intrface/cardbus.c", "intrface/devhere.c", "intrface/ideintrf.c", "intrface/intrface.c", "intrface/lddintrf.c",
    "intrface/locintrf.c", "intrface/pmeintf.c", "intrface/routintf.c", "pci/busno.c", "pci/config.c", "pci/devhere.c", "pci/ecam.c",
    "pci/express.c", "pci/id.c", "pci/ppbridge.c", "pci/romimage.c", "pci/state.c", "debug.c", "device.c", "dispatch.c", "enum.c", "fdo.c",
    "hookhal.c", "init.c", "pcivrify.c", "pdo.c", "power.c", "usage.c", "utils.c", "guid.c"], rc="pci.rc",
    includes=["sdk/include/reactos/drivers", "sdk/lib/drivers/arbiter"], libs=["arbiter"],
    framework="WDM bus driver, Windows-XP-style pci.sys (ntifs.h, ndk/*, reactos/drivers/pci, arbiter)")
drv("e1000", "drivers/network/dd/e1000", ["ndis.c", "hardware.c", "info.c", "interrupt.c", "debug.c", "send.c"], rc="e1000.rc",
    defines=["-DNDIS50_MINIPORT", "-DNDIS_MINIPORT_DRIVER", "-DNDIS_LEGACY_MINIPORT=1"], importlibs=["ndis", "ntoskrnl", "hal"],
    framework="NDIS 5.0 miniport (NDIS50_MINIPORT)", package_inf="nete1000.inf")
drv("rtl8139", "drivers/network/dd/rtl8139", ["ndis.c", "hardware.c", "info.c", "interrupt.c", "debug.c"], rc="rtl8139.rc",
    defines=["-DNDIS50_MINIPORT", "-DNDIS_MINIPORT_DRIVER", "-DNDIS_LEGACY_MINIPORT=1"], importlibs=["ndis", "ntoskrnl", "hal"],
    framework="NDIS 5.0 miniport (NDIS50_MINIPORT)", package_inf="netrtl.inf")
drv("pcnet", "drivers/network/dd/pcnet", ["pcnet.c", "requests.c"], rc="pcnet.rc",
    defines=["-DNDIS50_MINIPORT", "-DNDIS_MINIPORT_DRIVER", "-DNDIS_LEGACY_MINIPORT=1"], importlibs=["ndis", "ntoskrnl", "hal"],
    framework="NDIS 5.0 miniport (NDIS50_MINIPORT)", package_inf="netamd.inf")
drv("netkvm", "drivers/network/dd/netkvm", ["netkvm.c", "hw.c", "packet.c"], rc="netkvm.rc",
    defines=["-DNDIS50_MINIPORT", "-DNDIS_MINIPORT_DRIVER", "-DNDIS_LEGACY_MINIPORT=1"], importlibs=["ndis", "ntoskrnl", "hal"],
    framework="NDIS 5.0 miniport for virtio-net (ReactOS port)", package_inf="netkvm.inf")
drv("storahci", "drivers/storage/port/storahci", ["storahci.c"], rc="storahci.rc", defines=["-DDEBUG"],
    importlibs=["storport", "ntoskrnl", "hal"], framework="StorPort miniport (storport.h, ata.h)", package_inf="storahci.inf")
drv("uniata", "drivers/storage/ide/uniata", ["atacmd_map.cpp", "bm_devs.cpp", "id_ata.cpp", "id_badblock.cpp", "id_dma.cpp", "id_init.cpp",
    "id_probe.cpp", "id_queue.cpp", "id_sata.cpp", "ros_glue/ros_glue.cpp"], rc="idedma.rc", includes=["drivers/storage/ide/uniata/inc"],
    defines=["-D_CRT_NON_CONFORMING_SWPRINTFS"], importlibs=["scsiport", "ntoskrnl", "hal"], cxx=True,
    extra_cflags=["-Wno-narrowing", "-Wno-unused-but-set-variable"], framework="SCSI port miniport in C++ (scsiport.h)",
    package_inf="uniata_comm.inf", note="C++: needs clang++ (no mingw g++ on this host)")
drv("storport", "drivers/storage/port/storport", ["fdo.c", "misc.c", "pdo.c", "storport.c", "stubs.c"], rc="storport.rc",
    framework="StorPort port driver itself (provider for StorPort miniports)", note="exports the StorPort API: a framework provider")
drv("scsiport", "drivers/storage/port/scsiport", ["fdo.c", "pdo.c", "power.c", "registry.c", "scsi.c", "scsiport.c", "stubs.c"], rc="scsiport.rc",
    framework="SCSI port driver itself (provider for SCSI miniports)", note="exports the ScsiPort API: a framework provider")
drv("classpnp", "drivers/storage/class/classpnp", ["autorun.c", "class.c", "classwmi.c", "create.c", "data.c", "debug.c", "dictlib.c",
    "guid.c", "lock.c", "obsolete.c", "power.c", "retry.c", "utils.c", "xferpkt.c", "clntirp.c", "srblib.c"], rc="class.rc",
    defines=["-DCLASS_GLOBAL_USE_DELAYED_RETRY=1", "-DCLASS_GLOBAL_SECONDS_TO_WAIT_FOR_SYNCHRONOUS_SRB=100"],
    framework="storage class library driver (classpnp.h): provider for disk.sys", note="framework provider; sources are Microsoft's WDK sample code as carried by ReactOS")
drv("disk", "drivers/storage/class/disk", ["data.c", "disk.c", "diskwmi.c", "enum.c", "geometry.c", "part.c", "pnp.c"], rc="disk.rc",
    importlibs=["classpnp", "ntoskrnl", "hal"], framework="storage class driver over classpnp.sys", package_inf=None)


def sources_of(d):
    return [ROS / d["dir"] / s for s in d["sources"]]


# ------------------------------------------------------------------------------------------------------------ helpers
def run(cmd, cwd=None, capture=True, check=True, env=None):
    cmd = [str(c) for c in cmd]
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE if capture else None, stderr=subprocess.STDOUT if capture else None,
                       text=True, check=False, env=env)
    if check and r.returncode:
        raise RuntimeError(f"command failed ({r.returncode}): {' '.join(cmd)}\n{(r.stdout or '')[-4000:]}")
    return r


def host_tool(name, src, extra=()):
    """Compile a ReactOS host tool unmodified with the host gcc (once)."""
    exe = TOOLS / name
    if exe.exists() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe
    TOOLS.mkdir(parents=True, exist_ok=True)
    run(["gcc", "-O2", "-w", *extra, "-o", exe, src])
    return exe


def first_errors(text, n=6):
    lines = [l for l in text.splitlines() if re.search(r"\berror\b|undefined reference|cannot find|No such file", l)]
    return lines[:n] if lines else text.strip().splitlines()[-n:]


# --------------------------------------------------------------------------------------------------------- the ROS SDK
def prepare_rossdk(log):
    """Generate everything the ReactOS build generates that drivers include or link against."""
    (SDK / "include/ddk").mkdir(parents=True, exist_ok=True)
    (SDK / "include/psdk").mkdir(parents=True, exist_ok=True)
    (SDK / "include/reactos/mc").mkdir(parents=True, exist_ok=True)
    (SDK / "lib").mkdir(parents=True, exist_ok=True)
    hpp = host_tool("hpp", ROS / "sdk/tools/hpp/hpp.c")
    spec2def = host_tool("spec2def", ROS / "sdk/tools/spec2def/spec2def.c")
    for template, out in XDK:
        dest = SDK / "include" / out
        if not dest.exists():
            run([hpp, template, dest], cwd=ROS / "sdk/include/xdk")
            log.append(f"hpp {template} -> {out}")
    for mc in MC_FILES:
        dest = SDK / "include/reactos/mc" / f"{mc}.h"
        if not dest.exists():
            run([WINDMC, "-A", "-b", "-h", str(SDK / "include/reactos/mc") + "/", "-r", str(SDK / "include/reactos/mc") + "/",
                 ROS / "sdk/include/reactos/mc" / f"{mc}.mc"])
            log.append(f"windmc {mc}.mc -> {mc}.h")
    # buildno.h / version.h from the .cmake templates, fixed values (sdk/include/reactos/version.cmake)
    commit = load_manifest()["upstreams"]["reactos"]["commit"]
    values = {"KERNEL_VERSION_BUILD": "custom", "REVISION": commit[:7], "KERNEL_VERSION": "0.4.17-amd64-dev", "COMMIT_HASH": commit,
              "REACTOS_DLL_VERSION_MAJOR": "42", "DLL_VERSION_STR": "42.4.17-dev", "CMAKE_C_COMPILER_ID": "GNU",
              "CMAKE_C_COMPILER_VERSION": "13", "KERNEL_VERSION_MAJOR": "0", "KERNEL_VERSION_MINOR": "4",
              "KERNEL_VERSION_PATCH_LEVEL": "17", "COPYRIGHT_YEAR": "2026"}
    for tpl, out in (("buildno.h.cmake", "buildno.h"), ("version.h.cmake", "version.h")):
        text = (ROS / "sdk/include/reactos" / tpl).read_text()
        for k, v in values.items():
            text = text.replace(f"@{k}@", v)
        (SDK / "include/reactos" / out).write_text(text)
    # import libraries from the spec files
    for name, (spec, dll) in SPECS.items():
        deffile, lib = SDK / "lib" / f"{name}.def", SDK / "lib" / f"lib{name}.a"
        if lib.exists():
            continue
        run([spec2def, f"-n={dll}", "-a=x86_64", "--version=0x502", "--implib", f"-d={deffile}", ROS / spec])
        run([DLLTOOL, "-d", deffile, "-l", lib])
        log.append(f"spec2def+dlltool {spec} -> lib{name}.a ({sum(1 for l in deffile.read_text().splitlines() if l.strip() and not l.startswith(('LIBRARY', 'EXPORTS')))} exports)")


def ros_includes(profile="reactos"):
    src = ROS / "sdk/include"
    return [src, src / "crt", src / "ddk", src / "ndk", src / "psdk", src / "reactos", src / "reactos/libs", src / "vcruntime",
            src / "winrt", SDK / "include", SDK / "include/psdk", SDK / "include/ddk", src / "dxsdk", SDK / "include/reactos",
            SDK / "include/reactos/mc", ROS / "sdk/lib/pseh/include"]


def mingw_includes():
    return [MINGW_ROOT / "include/ddk", ROS / "sdk/lib/pseh/include"]


class Toolchain:
    def __init__(self, cc, sdk):
        self.cc_name, self.sdk = cc, sdk
        if cc == "gcc":
            self.cc, self.cxx = [GCC], None
        else:
            self.cc, self.cxx = [CLANG, f"--target={TRIPLE}"], [CLANGXX, f"--target={TRIPLE}"]

    def cflags(self, d, cxx=False):
        flags = list(ROS_CFLAGS) + d["extra_cflags"]
        if self.cc_name == "gcc":
            flags += GCC_ONLY
        else:
            flags += ["-Wno-microsoft", "-Wno-unknown-pragmas", "-Wno-ignored-attributes", "-Wno-unused-value", "-Wno-parentheses-equality",
                      "-Wno-microsoft-enum-forward-reference", "-Wno-unknown-warning-option", "-Wno-int-to-void-pointer-cast",
                      "-Wno-tautological-constant-out-of-range-compare", "-Wno-incompatible-pointer-types", "-Wno-implicit-function-declaration",
                      "-Wno-pointer-sign", "-Wno-comment", "-Wno-switch", "-Wno-enum-conversion", "-Wno-address-of-packed-member",
                      "-Wno-sometimes-uninitialized"]
        if cxx:
            flags += ["-fno-exceptions", "-fno-rtti", "-nostdinc++", "-fno-threadsafe-statics", "-Wno-writable-strings", "-Wno-reorder-ctor",
                      "-Wno-deprecated", "-Wno-c++11-narrowing", "-Wno-register", "-Wno-invalid-offsetof", "-Wno-deprecated-copy"]
        # Structured exception handling: see the docstring
        flags += ["-D_USE_NATIVE_SEH"] if self.cc_name == "clang" else ["-D_USE_DUMMY_PSEH=1"]
        if self.sdk == "reactos":
            flags += ["-nostdinc"] + ROS_DEFINES
            for i in ros_includes():
                flags += ["-I", str(i)]
        else:
            flags += ["-D_AMD64_", "-D__x86_64__", "-D_WIN64", "-D_M_AMD64", "-D_M_X64", "-DNTDDI_VERSION=0x06010000", "-D_WIN32_WINNT=0x0601",
                      "-DDBG=0", "-D__REACTOS__"]
            for i in mingw_includes():
                flags += ["-I", str(i)]
        for i in d["includes"]:
            flags += ["-I", str(ROS / i)]
        flags += d["defines"]
        return flags

    def link(self, out, objs, d, libdirs, extra_ldflags=()):
        cmd = list(self.cc) + LINK_FLAGS + [f"-Wl,-T,{INIT_LDS}"] + list(extra_ldflags) + ["-o", out, *objs]
        for ld in libdirs:
            cmd += ["-L", str(ld)]
        for lib in d["libs"]:
            cmd += [f"-l{lib}"]
        for lib in d["importlibs"]:
            cmd += [f"-l{lib}"]
        return cmd


def build_static_libs(tc, log):
    """arbiter, dmilib and the PSEH dummy library, from their ReactOS sources, for this toolchain."""
    libdir = SDK / "lib" / tc.cc_name / tc.sdk
    libdir.mkdir(parents=True, exist_ok=True)
    table = {
        "arbiter": (ROS / "sdk/lib/drivers/arbiter", ["arbiter.c", "entry.c", "handler.c", "ordering.c", "range.c", "transaction.c"], ["-D_NTSYSTEM_"]),
        "dmilib": (ROS / "sdk/lib/dmilib", ["dmilib.c"], []),
        "pseh": (ROS / "sdk/lib/pseh", ["dummy.c"], []),
    }
    results = {}
    for name, (src_dir, files, defs) in table.items():
        lib = libdir / f"lib{name}.a"
        objs, errors = [], []
        pseudo = dict(name=name, includes=[], defines=defs, extra_cflags=[])
        for f in files:
            o = libdir / f"{name}_{Path(f).stem}.o"
            if not o.exists():
                r = run(list(tc.cc) + tc.cflags(pseudo) + ["-c", "-o", o, src_dir / f], check=False)
                if r.returncode:
                    errors += first_errors(r.stdout)
                    continue
            objs.append(o)
        if objs and not errors:
            if lib.exists():
                lib.unlink()
            run(["x86_64-w64-mingw32-ar", "rcs", lib, *objs])
            results[name] = "ok"
        else:
            results[name] = errors or ["no objects"]
            log.append(f"static lib {name} failed for {tc.cc_name}/{tc.sdk}: {errors[:2]}")
    return libdir, results


# ------------------------------------------------------------------------------------------------------- build a driver
def imports_of(sys_path):
    """{dll: [function, ...]} from the import table (objdump -p)."""
    out = run([OBJDUMP, "-p", sys_path], check=False).stdout
    imports, cur = {}, None
    for line in out.splitlines():
        m = re.match(r"\s*DLL Name: (\S+)", line)
        if m:
            cur = m.group(1).lower()
            imports[cur] = []
            continue
        if cur:
            m = re.match(r"\s*[0-9a-f]+\s+\d+\s+(\S+)\s*$", line)
            if m and m.group(1) not in ("<none>",):
                imports[cur].append(m.group(1))
            elif line.strip() == "" and imports[cur]:
                cur = None
    return {k: sorted(set(v)) for k, v in imports.items() if v}


def build_driver(name, tc, static_libdir, jobs=2):
    d = D[name]
    outdir = CORPUS / name / f"{tc.cc_name}-{tc.sdk}"
    outdir.mkdir(parents=True, exist_ok=True)
    rec = {"driver": name, "framework": d["framework"], "sdk": tc.sdk, "cc": tc.cc_name, "note": d["note"], "sources": len(d["sources"]),
           "status": "built", "errors": [], "commands": [], "warnings": 0, "seconds": 0.0}
    t0 = time.time()
    if d["cxx"] and tc.cxx is None:
        rec.update(status="skipped", errors=["C++ sources need clang++ (--cc clang); x86_64-w64-mingw32-g++ is not installed"])
        return rec
    if not (ROS / d["dir"]).is_dir():
        rec.update(status="failed", errors=[f"source directory {d['dir']} missing"])
        return rec
    objs = []
    failures = []

    def compile_one(src):
        o = outdir / (src.stem + ".o")
        cxx = src.suffix == ".cpp"
        cc = tc.cxx if cxx else tc.cc
        cmd = list(cc) + tc.cflags(d, cxx=cxx) + ["-c", "-o", o, src]
        r = run(cmd, check=False, cwd=ROS / d["dir"])
        return src, o, r, cmd

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        for src, o, r, cmd in pool.map(compile_one, sources_of(d)):
            rec["commands"].append(" ".join(str(c) for c in cmd))
            rec["warnings"] += r.stdout.count("warning:")
            if r.returncode:
                failures.append((src.name, first_errors(r.stdout)))
            else:
                objs.append(o)
    if failures:
        rec["status"] = "failed"
        rec["errors"] = [f"{s}: {e}" for s, errs in failures for e in errs][:12]
        rec["failed_sources"] = [s for s, _ in failures]
        rec["seconds"] = round(time.time() - t0, 1)
        return rec
    # resources (best effort: the .sys is complete without them, ReactOS's own rc files need its psdk)
    if d["rc"]:
        res = outdir / "resources.o"
        rc_cmd = [WINDRES, "-O", "coff", "--preprocessor-arg=-nostdinc" if tc.sdk == "reactos" else "--preprocessor-arg=-D__DUMMY", "-o", res, ROS / d["dir"] / d["rc"]]
        for i in ros_includes():
            rc_cmd += ["-I", str(i)]
        for x in ROS_DEFINES:
            if x.startswith("-D") and "=" in x and " " not in x:
                rc_cmd += ["--define", x[2:]]
        r = run(rc_cmd, check=False, cwd=ROS / d["dir"])
        if r.returncode:
            rec["resources"] = "skipped: " + "; ".join(first_errors(r.stdout, 2))
        else:
            objs.append(res)
            rec["resources"] = "ok"
    sys_path = outdir / f"{name}.sys"
    libdirs = [static_libdir, SDK / "lib"] + ([MINGW_ROOT / "lib"] if tc.sdk == "mingw" else [])
    cmd = tc.link(sys_path, objs, d, libdirs)
    r = run(cmd, check=False)
    rec["commands"].append(" ".join(str(c) for c in cmd))
    if r.returncode or not sys_path.exists():
        rec["status"] = "link-failed"
        rec["errors"] = first_errors(r.stdout, 12)
    else:
        rec["sys"] = str(sys_path.relative_to(REPO))
        rec["bytes"] = sys_path.stat().st_size
        rec["sha256"] = sha256_file(sys_path)
        rec["imports"] = imports_of(sys_path)
        rec["import_count"] = sum(len(v) for v in rec["imports"].values())
        pe = run([OBJDUMP, "-p", sys_path], check=False).stdout
        m = re.search(r"Subsystem\s+0000000(\d)", pe)
        rec["subsystem"] = int(m.group(1)) if m else None
        m = re.search(r"AddressOfEntryPoint\s+([0-9a-f]+)", pe)
        rec["entry_rva"] = m.group(1) if m else None
    rec["seconds"] = round(time.time() - t0, 1)
    return rec


def make_package(name, rec):
    """Driver package directory (the .sys + its INF, as a vendor would ship it) for store.py / shzpnp tests."""
    d = D[name]
    if rec.get("status") != "built":
        return None
    pkg = PACKAGES / name
    pkg.mkdir(parents=True, exist_ok=True)
    shutil.copy2(REPO / rec["sys"], pkg / f"{name}.sys")
    inf = None
    if d["package_inf"] and (ROS / d["dir"] / d["package_inf"]).exists():
        inf = ROS / d["dir"] / d["package_inf"]
    if inf:
        shutil.copy2(inf, pkg / inf.name)
    return str(pkg.relative_to(REPO))


# ------------------------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("drivers", nargs="*", help="driver names (default: all)")
    ap.add_argument("--sdk", choices=["reactos", "mingw"], action="append", help="SDK profile(s); default: both")
    ap.add_argument("--cc", choices=["gcc", "clang"], action="append", help="compiler(s); default: both")
    ap.add_argument("--jobs", type=int, default=2)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--packages", action="store_true", help="also assemble build/shizukudos/ntdrv/packages/<driver>/ from the best build")
    args = ap.parse_args()
    if args.list:
        for n, d in D.items():
            print(f"{n:10} {d['dir']:38} {len(d['sources']):3} sources  {d['framework']}")
        return 0
    for tool in (GCC, DLLTOOL, WINDRES, WINDMC, OBJDUMP, "gcc"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    if not ROS.is_dir():
        raise SystemExit("ReactOS tree missing: run shizukudos/ntdrv/corpus/fetch.py")
    log = []
    prepare_rossdk(log)
    names = args.drivers or list(D)
    for n in names:
        if n not in D:
            raise SystemExit(f"unknown driver {n}; known: {', '.join(D)}")
    combos = [(cc, sdk) for cc in (args.cc or ["gcc", "clang"]) for sdk in (args.sdk or ["reactos", "mingw"])]
    results = {"built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "reactos_commit": load_manifest()["upstreams"]["reactos"]["commit"],
               "sdk_log": log, "static_libs": {}, "drivers": {}}
    for cc, sdk in combos:
        tc = Toolchain(cc, sdk)
        if cc == "clang" and not shutil.which(CLANG):
            log.append("clang not installed: clang combinations skipped")
            continue
        static_libdir, libres = build_static_libs(tc, log)
        results["static_libs"][f"{cc}-{sdk}"] = libres
        for n in names:
            rec = build_driver(n, tc, static_libdir, jobs=args.jobs)
            results["drivers"].setdefault(n, {})[f"{cc}-{sdk}"] = rec
            status = rec["status"]
            extra = f" {rec.get('bytes', 0)} bytes, {rec.get('import_count', 0)} imports from {', '.join(rec.get('imports', {}))}" if status == "built" else ""
            print(f"{n:10} {cc:5} {sdk:8} {status:12}{extra}")
            for e in rec["errors"][:3]:
                print(f"           {e[:200]}")
    if args.packages:
        for n in names:
            best = next((r for k, r in results["drivers"][n].items() if r["status"] == "built"), None)
            if best:
                results["drivers"][n]["package"] = make_package(n, best)
    write_json(CORPUS / "build-result.json", results)
    built = sum(1 for n in names if any(r["status"] == "built" for r in results["drivers"][n].values()))
    print(f"\n{built} of {len(names)} drivers built in at least one configuration; results in {CORPUS / 'build-result.json'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
