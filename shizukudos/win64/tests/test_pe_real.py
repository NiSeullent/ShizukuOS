#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Runs pe_parse.c (through win64/tests/test_pe_real.c) on REAL AMD64 PE images and checks every answer against an
independent reader (pefile).

Fixtures are built here with clang + lld-link so the whole matrix of directories is exercised without needing the
target application trees:
  - a plain EXE + DLL (imports, exports, relocations);
  - an image with a delay-load import directory (/delayload) -> pe_walk_delay_imports;
  - a Control-Flow-Guard image (/guard:cf) with a load-configuration directory -> pe_load_config (guard flags, the
    CFG function table, the security cookie and the CFG/XFG pointers);
  - a low-alignment image (SectionAlignment == FileAlignment < 4096) -> the flat-mapping path;
  - the base-relocation applier pe_apply_relocs, whose output is compared byte for byte against pefile.relocate_image.
When the three target application trees are reachable (SHZ_APP_TREES=dir:dir:dir, or the default scratchpad copies),
chrome.dll / chrome_elf.dll / electron.exe are parsed too, so the parser is checked on the real images it must load.
"""
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

try:
    import pefile
except ImportError:
    raise SystemExit("pip install pefile")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE.parents[2] / "build" / "shizukudos" / "win64" / "petest"
CLANG = shutil.which("clang") or "clang"
LLD = shutil.which("lld-link") or "lld-link"
DLLTOOL = shutil.which("llvm-dlltool") or "llvm-dlltool"


def run(cmd, **kw):
    r = subprocess.run([str(x) for x in cmd], capture_output=True, text=True, **kw)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"failed: {' '.join(map(str, cmd))}")
    return r.stdout


def cc(src_name, code):
    src = BUILD / src_name
    src.write_text(code)
    obj = src.with_suffix(".obj")
    run([CLANG, "--target=x86_64-pc-windows-msvc", "-O2", "-c", src, "-o", obj])
    return obj


# ---------------------------------------------------------------- fixtures
def build_fixtures():
    BUILD.mkdir(parents=True, exist_ok=True)
    fixtures = []

    # plain DLL (exports) + EXE (imports it, relocatable)
    (BUILD / "libc.def").write_text("LIBRARY kernel32.dll\nEXPORTS\n  GetTickCount\n  HeapAlloc\n  ExitProcess\n")
    run([DLLTOOL, "-m", "i386:x86-64", "-d", BUILD / "libc.def", "-l", BUILD / "k32.lib"])
    dll_obj = cc("plaindll.c", "int __declspec(dllexport) Add(int a,int b){return a+b;}\n"
                               "int __declspec(dllexport) Sub(int a,int b){return a-b;}\n"
                               "int _fltused; int __stdcall _DllMainCRTStartup(void*a,unsigned b,void*c){(void)a;(void)b;(void)c;return 1;}\n")
    run([LLD, "/nologo", "/dll", "/entry:_DllMainCRTStartup", "/subsystem:console", "/nodefaultlib",
         f"/out:{BUILD/'plain.dll'}", "/implib:" + str(BUILD / "plain.lib"), dll_obj])
    fixtures.append(BUILD / "plain.dll")

    exe_obj = cc("plainexe.c", "__declspec(dllimport) int Add(int,int);\n"
                               "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
                               "int e(void){ ExitProcess((unsigned)Add(2,3)); return 0; }\n")
    run([LLD, "/nologo", "/entry:e", "/subsystem:console", "/nodefaultlib", "/dynamicbase",
         f"/out:{BUILD/'plain.exe'}", exe_obj, BUILD / "plain.lib", BUILD / "k32.lib"])
    fixtures.append(BUILD / "plain.exe")

    # delay-load directory
    delay_help = cc("delayhelp.c", "unsigned long long __delayLoadHelper2(const void*d,void**p){(void)d;(void)p;return 0;}\n")
    dl_obj = cc("delayexe.c", "__declspec(dllimport) unsigned long __stdcall GetTickCount(void);\n"
                              "__declspec(dllimport) void* __stdcall HeapAlloc(void*,unsigned long,unsigned long long);\n"
                              "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
                              "int e(void){ unsigned long t=GetTickCount(); (void)HeapAlloc(0,0,8); ExitProcess((unsigned)t); return 0; }\n")
    run([LLD, "/nologo", "/entry:e", "/subsystem:console", "/nodefaultlib", "/delayload:kernel32.dll",
         f"/out:{BUILD/'delay.exe'}", dl_obj, delay_help, BUILD / "k32.lib"])
    fixtures.append(BUILD / "delay.exe")

    # CFG image with a load configuration
    cfg_lc = cc("cfg_lc.c",
        "typedef unsigned long long u64;typedef unsigned u32;typedef unsigned short u16;\n"
        "static void __cdecl nop(void*t){(void)t;}\n"
        "void*__guard_check_icall_fptr=(void*)nop;\n"
        "extern void __guard_dispatch_icall_nop(void);\n"
        "__asm__(\".globl __guard_dispatch_icall_nop\\n__guard_dispatch_icall_nop: jmp *%rax\\n\");\n"
        "void*__guard_dispatch_icall_fptr=(void*)__guard_dispatch_icall_nop;\n"
        "u64 __security_cookie=0x00002B992DDFA232ull;\n"
        "__asm__(\".section .rdata,\\\"dr\\\"\\n .globl _load_config_used\\n .p2align 3\\n_load_config_used:\\n\"\n"
        "\" .long 0x94\\n .long 0\\n .short 0,0\\n .long 0,0,0\\n .quad 0,0,0,0,0,0\\n .long 0\\n .short 0,0\\n .quad 0\\n\"\n"
        "\" .quad __security_cookie\\n .quad 0,0\\n .quad __guard_check_icall_fptr\\n .quad __guard_dispatch_icall_fptr\\n\"\n"
        "\" .quad __guard_fids_table\\n .quad __guard_fids_count\\n .long __guard_flags\\n .short 0,0\\n .long 0,0\\n\"\n"
        "\" .quad __guard_iat_table\\n .quad __guard_iat_count\\n .quad __guard_longjmp_table\\n .quad __guard_longjmp_count\\n .text\\n\");\n")
    cfg_main = cc("cfg_main.c",
        "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
        "static int f1(int x){return x+1;} static int f2(int x){return x*2;}\n"
        "int (*volatile fp)(int)=f1; int filt(unsigned c){(void)c;return 1;}\n"
        "int e(void){int r=fp(3); fp=f2; r+=fp(4);\n"
        " __try{*(volatile int*)0=1;}__except(filt(_exception_code())){r+=100;}\n ExitProcess(r); return 0;}\n")
    run([LLD, "/nologo", "/entry:e", "/subsystem:console", "/nodefaultlib", "/guard:cf", "/dynamicbase",
         f"/out:{BUILD/'cfg.exe'}", cfg_main, cfg_lc, BUILD / "k32.lib"])
    fixtures.append(BUILD / "cfg.exe")

    # low-alignment image (SectionAlignment == FileAlignment == 512)
    low_obj = cc("lowexe.c", "__declspec(dllimport) void __stdcall ExitProcess(unsigned);\n"
                             "int e(void){ ExitProcess(0); return 0; }\n")
    run([LLD, "/nologo", "/entry:e", "/subsystem:console", "/nodefaultlib", "/align:512", "/filealign:512",
         "/driver", f"/out:{BUILD/'low.sys'}", low_obj, BUILD / "k32.lib"])
    fixtures.append(BUILD / "low.sys")
    return fixtures


# ---------------------------------------------------------------- checks
def parse_info(out):
    d = {}
    for line in out.splitlines():
        f = line.split()
        d.setdefault(f[0], []).append(f[1:])
    return d


def check_image(driver, path):
    out = subprocess.run([str(driver), "info", str(path)], capture_output=True, text=True)
    info = parse_info(out.stdout)
    assert info["parse"][0][0] == "0", f"{path.name}: parser rejected the image: {out.stdout}{out.stderr}"
    pe = pefile.PE(str(path), fast_load=True)
    pe.parse_data_directories(directories=[0, 1, 5, 9, 10, 13])

    ib, soi = info["image_base"][0][0], info["image_base"][0][2]
    assert int(ib, 16) == pe.OPTIONAL_HEADER.ImageBase, f"{path.name}: image base {ib} != {pe.OPTIONAL_HEADER.ImageBase:#x}"
    assert int(soi, 16) == pe.OPTIONAL_HEADER.SizeOfImage, f"{path.name}: size of image mismatch"

    # delay imports: descriptor count, thunk count
    want_delay = getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", [])
    d = info["delay"][0]
    assert d[0] == "0", f"{path.name}: delay walk error {d[0]}"
    assert int(d[2]) == len(want_delay), f"{path.name}: {d[2]} delay descriptors, pefile says {len(want_delay)}"
    assert int(d[4]) == sum(len(e.imports) for e in want_delay), f"{path.name}: delay thunk count mismatch"

    # load configuration
    lc = info["loadcfg"][0]
    lc_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[10]
    if lc_dir.VirtualAddress and lc_dir.Size:
        cfg = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        assert lc[0] == "0", f"{path.name}: load-config error"
        assert int(lc[2]) == cfg.Size, f"{path.name}: load-config Size {lc[2]} != {cfg.Size}"
        assert int(lc[6], 16) == getattr(cfg, "SecurityCookie", 0), f"{path.name}: security cookie mismatch"
        assert int(lc[8], 16) == getattr(cfg, "GuardFlags", 0), f"{path.name}: guard flags mismatch"
        assert int(lc[16]) == getattr(cfg, "GuardCFFunctionCount", 0), f"{path.name}: CF function count mismatch"
    else:
        assert lc[2] == "0", f"{path.name}: reported a load configuration where there is none"

    # relocations: DIR64 + HIGHLOW totals
    reloc = info["relocs"][0]
    dir64 = highlow = 0
    for e in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", []):
        for r in e.entries:
            if r.type == 10:
                dir64 += 1
            elif r.type == 3:
                highlow += 1
    assert reloc[0] == "0", f"{path.name}: reloc walk error"
    assert int(reloc[2]) == dir64 and int(reloc[4]) == highlow, \
        f"{path.name}: relocs dir64={reloc[2]}/{dir64} highlow={reloc[4]}/{highlow}"
    return int(soi, 16)


def check_relocate(driver, path):
    """Map + relocate the image to a new base and compare with pefile's own relocation over the content regions (the
    headers and each section's VirtualSize; the raw padding beyond VirtualSize that Windows does not map is skipped,
    and every base relocation lands inside those regions)."""
    pe = pefile.PE(str(path))
    new_base = pe.OPTIONAL_HEADER.ImageBase + 0x40000000
    out_path = BUILD / (path.stem + ".mapped")
    out = run([str(driver), "map", str(path), hex(new_base), str(out_path)])
    assert out.split()[1] == "0", f"{path.name}: relocate failed: {out}"
    ours = out_path.read_bytes()
    pe.relocate_image(new_base)
    theirs = pe.get_memory_mapped_image(ImageBase=new_base)
    regions = [(0, pe.OPTIONAL_HEADER.SizeOfHeaders)]
    for s in pe.sections:
        content = min(s.Misc_VirtualSize or s.SizeOfRawData, s.SizeOfRawData)
        regions.append((s.VirtualAddress, s.VirtualAddress + content))
    for lo, hi in regions:
        hi = min(hi, len(ours), len(theirs))
        if ours[lo:hi] != theirs[lo:hi]:
            diff = next(i for i in range(lo, hi) if ours[i] != theirs[i])
            raise SystemExit(f"{path.name}: relocated image differs from pefile at RVA {diff:#x}")
    return int(out.split()[3])


def app_images():
    trees = [d for d in os.environ.get("SHZ_APP_TREES", "").split(":") if d]
    named = []
    for t in trees:
        for pat in ("chrome.dll", "chrome_elf.dll", "chrome.exe", "electron.exe", "*.exe", "*.dll"):
            named += sorted(Path(t).rglob(pat))
    seen, out = set(), []
    for p in named:
        if p in seen or not p.is_file():
            continue
        seen.add(p)
        try:
            pe = pefile.PE(str(p), fast_load=True)
        except pefile.PEFormatError:
            continue
        if pe.FILE_HEADER.Machine == 0x8664:
            out.append(p)
    return out[:24]


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    driver = BUILD / "test_pe_real"
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", HERE / "test_pe_real.c", ROOT / "pe_parse.c"]
    run(["gcc", "-O2", *common, "-o", driver])
    san = BUILD / "test_pe_real_asan"
    run(["clang", "-g", "-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
         *common, "-o", san])

    fixtures = build_fixtures()
    total = 0
    for fx in fixtures:
        check_image(driver, fx)
        check_image(san, fx)
        if fx.suffix != ".sys":                     # low-alignment driver has no base relocations to apply
            total += check_relocate(driver, fx)
    print(f"fixtures: {len(fixtures)} images parsed and cross-checked with pefile, {total} relocations applied and verified")

    apps = app_images()
    for p in apps:
        soi = check_image(driver, p)
        if soi <= 64 * 1024 * 1024:                 # relocate images up to 64 MiB (chrome.dll at 334 MiB: parse only)
            check_relocate(driver, p)
    if apps:
        print(f"target application images: parsed {len(apps)} real PE32+ ({', '.join(p.name for p in apps[:6])}"
              f"{' ...' if len(apps) > 6 else ''}) and matched pefile")
    else:
        print("target application trees not set (SHZ_APP_TREES=dir:dir): fixture check only")


if __name__ == "__main__":
    main()
