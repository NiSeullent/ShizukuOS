#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the native Win98 GOP driver in a private tree; never install or start a VM."""
import argparse
import difflib
import hashlib
import json
import re
import shutil
import struct
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "shizukudos" / "tools"))
import shzlib

HERE = Path(__file__).resolve().parent
VMDISP_COMMIT = "d778a911035d414dea9ac852a638a7052c21c400"
FIXLINK_COMMIT = "a2a74447daea3197255f3a4fb5cfb0c5a453dcc8"
REF = REPO / "build" / "vmdisp9x-reference"
FIXREF = REPO / "build" / "fixlink-reference"
DEFAULT_OUT = shzlib.BUILD / "shizuku-gop"
C16 = ["dbgprint", "dibcall", "dddrv", "drvlib", "enable", "init", "control",
       "palette", "scrsw_vesa", "pm16_calls_vesa", "modes_vesa"]
A16 = ["dibthunk", "sswhook"]
C32 = ["vxd_main_vesa", "vmware/pci", "vxd_fbhda", "vxd_fbhda_dd", "vxd_lib",
       "vxd_vesa", "vxd_vdd_vesa", "vxd_mouse", "vxd_mtrr", "vxd_wram",
       "vxd_async", "vxd_terror", "dbgprint32"]
SOURCE_EXTENSIONS = {".c", ".h", ".asm", ".def", ".lbc", ".rc", ".rcv"}


def digest(path):
    return shzlib.sha256_file(path)


def pinned_tree(path, repository, commit):
    if not (path / ".git").exists():
        if path.exists():
            raise RuntimeError(f"Refusing unverified reference directory {path}")
        shzlib.run(["git", "clone", "--no-checkout", repository, path], timeout=600)
        shzlib.run(["git", "-C", path, "checkout", "--detach", commit])
    head = shzlib.run(["git", "-C", path, "rev-parse", "HEAD"], capture=True).stdout.strip()
    status = shzlib.run(["git", "-C", path, "status", "--porcelain", "--untracked-files=no"], capture=True).stdout
    if head != commit or status:
        raise RuntimeError(f"Reference must be clean at {commit}: {path}")
    return path


def source_manifest(tree):
    return {str(p.relative_to(tree)): digest(p) for p in sorted(tree.rglob("*"))
            if p.is_file() and ".git" not in p.relative_to(tree).parts
            and (p.suffix.lower() in SOURCE_EXTENSIONS or p.name in ("LICENSE", "licence.txt", "makefile"))}


def adapt(work):
    before = source_manifest(work)
    original = {}

    def replace(name, old, new):
        path = work / name
        text = path.read_text()
        original.setdefault(name, text)
        if text.count(old) != 1:
            raise RuntimeError(f"Pinned adaptation context changed: {name}: {old[:60]!r}")
        path.write_text(text.replace(old, new, 1))

    replace("vxd.h", '#elif defined(VESA)\n#define VXD_DEVICE_ID VXD_DEVICE_VMDISP9X_ID\n#define VXD_DEVICE_NAME "VESAVXD"',
            '#elif defined(VESA)\n#define VXD_DEVICE_ID 0x4353\n#define VXD_DEVICE_NAME "SHZGOP  "')
    replace("init.c", 'extern char __based( __segname( "_TEXT" ) ) *pText;',
            '/* A based data declaration creates an empty FAR_DATA segment which\n'
            ' * WLINK removes from NE, leaving an invalid selector relocation.\n'
            ' * This initialization routine shares the actual driver code segment. */\n'
            'WORD shzgop_code_selector(void);\n'
            '#pragma aux shzgop_code_selector = "mov ax,cs" value [ax] modify [];')
    replace("init.c", 'GlobalSmartPageLock( (__segment)pText );',
            'GlobalSmartPageLock( shzgop_code_selector() );')
    replace("init.c", '\t\tmouse_buffer(&mouse_buf, &mouse_buf_lin);',
            '\t\t/* Fixed firmware mode: do not reuse stale SYSTEM.INI geometry. */\n'
            '\t\twScrX = (WORD)hda->width;\n\t\twScrY = (WORD)hda->height;\n'
            '\t\twBpp = 32;\n\t\twPalettized = 0;\n'
            '\t\tmouse_buffer(&mouse_buf, &mouse_buf_lin);')
    replace("control.c", '  LONG rc = -1;\n  ',
            '  LONG rc = -1;\n'
            '  /* This package supplies GDI/DIBEngine, not the upstream HAL/ICD DLLs. */\n'
            '  if(!hda || function == DCICOMMAND || function == OPENGL_GETINFO) return 0;\n'
            '  if(function == QUERYESCSUPPORT)\n  {\n'
            '    WORD requested;\n    if(!lpInput) return 0;\n    requested = *((LPWORD)lpInput);\n'
            '    if(requested == DCICOMMAND || requested == OPENGL_GETINFO) return 0;\n  }\n  ')
    replace("vxd_main.c", 'void __stdcall Device_Init_proc(DWORD VM);',
            'BOOL __stdcall Device_Init_proc(DWORD VM);')
    replace("vxd_main.c", 'DWORD ThisVM = 0;',
            'DWORD ThisVM = 0;\nstatic BOOL shzgop_initialized = FALSE;')
    replace("vxd_main.c", '\t\tjnz control_2\n\t\t\tpush ebx ; VM handle\n\t\t  call Device_Init_proc\n\t\t\tpopad\n\t\t\tclc',
            '\t\tjnz control_2\n\t\t\tpushad\n\t\t\tpush ebx ; VM handle\n'
            '\t\t  call Device_Init_proc\n\t\t\tsub eax, 1 ; CF reflects FALSE initialization\n\t\t\tpopad')
    replace("vxd_main.c", '\t\t  call Device_Init_proc\n\t\t  popad\n\t\t\tclc',
            '\t\t  call Device_Init_proc\n\t\t\tsub eax, 1 ; CF reflects FALSE initialization\n\t\t  popad')
    replace("vxd_main.c", '\t\tcontrol_5:\n\t\tcmp eax,System_Exit',
            '\t\tcontrol_5:\n\t\tcmp eax,Sys_Dynamic_Device_Exit\n\t\tjnz control_system_exit\n'
            '\t\t\tcmp shzgop_initialized, 0\n\t\t\tje control_unload_ok\n'
            '\t\t\tstc ; Active MiniVDD/timer hooks have no dynamic teardown.\n\t\t\tret\n'
            '\t\tcontrol_unload_ok:\n\t\t\tclc\n\t\t\tret\n'
            '\t\tcontrol_system_exit:\n\t\tcmp eax,System_Exit')
    replace("vxd_main.c", 'void Device_Init_proc(DWORD VM)\n{\n\tcritical_section_enter();',
            'BOOL Device_Init_proc(DWORD VM)\n{\n\tif(shzgop_initialized) return TRUE;\n\tcritical_section_enter();')
    replace("vxd_main.c", '#ifdef VESA\n\tVESA_init_hw();\n#endif',
            '#ifdef VESA\n\tVDD_Get_Mini_Dispatch_Table();\n'
            '\tif(!DispatchTable || DispatchTableLength < 0x31)\n\t{\n'
            '\t\tcritical_section_leave();\n\t\treturn FALSE;\n\t}\n'
            '\tif(!VESA_init_hw() || !FBHDA_setup())\n\t{\n'
            '\t\tcritical_section_leave();\n\t\treturn FALSE;\n\t}\n#endif')
    replace("vxd_main.c", '\t/* register miniVDD functions */\n\tVDD_Get_Mini_Dispatch_Table();',
            '\t/* register the already validated MiniVDD dispatch table */')
    replace("vxd_main.c", '\tconfigure_FBHDA();',
            '\t/* The fixed software GOP backend ignores unrelated global GPU settings. */\n'
            '\t/* configure_FBHDA is deliberately not called. */')
    replace("vxd_main.c", '\tdbg_printf("Address=0x%lX\\n", port_info);\n}',
            '\tdbg_printf("Address=0x%lX\\n", port_info);\n\tshzgop_initialized = TRUE;\n\treturn TRUE;\n}')
    replace("vxd_main.c", '\tWORD service = state->Client_EDX & 0xFFFF;',
            '\tWORD service = state->Client_EDX & 0xFFFF;\n'
            '\tif(!shzgop_initialized || !FBHDA_setup())\n\t{\n'
            '\t\tstate->Client_ECX = 0;\n\t\treturn 0xFFFF;\n\t}')
    replace("vxd_main.c", '\tDWORD *inBuf  = (DWORD*)params->lpInBuffer;\n\tDWORD *outBuf = (DWORD*)params->lpOutBuffer;\n\tDWORD rc = 1;',
            '\tDWORD *inBuf;\n\tDWORD *outBuf;\n\tDWORD rc = 1;\n'
            '\tif(!shzgop_initialized || !FBHDA_setup() || !params) return 1;\n'
            '\tinBuf = (DWORD*)params->lpInBuffer;\n\toutBuf = (DWORD*)params->lpOutBuffer;')
    replace("vxd_main.c", 'void Device_Init_Complete(DWORD VM)\n{',
            'void Device_Init_Complete(DWORD VM)\n{\n\tif(!shzgop_initialized || !FBHDA_setup()) return;')
    replace("vxd_fbhda.c", '\t\t\t_PageFree(hda, 0);\n\t\t\treturn FALSE;',
            '\t\t\t/* hda points inside wram, not to a separately allocated page. */\n'
            '\t\t\thda = NULL;\n\t\t\treturn FALSE;')
    replace("vxd_fbhda.c", '\tdbg_printf("FBHDA_clean\\n");',
            '\tif(!hda) return;\n\tdbg_printf("FBHDA_clean\\n");')
    replace("version.h", '#define DRV_VER_MINOR 2025', '#define DRV_VER_MINOR 2026')
    replace("res/vesamini.rc", '#define VER_ORIGINALFILENAME_STR "vesamini.drv"',
            '#define VER_ORIGINALFILENAME_STR "SHZGOP.DRV"')
    replace("res/display.rcv", '#define VER_FILEDESCRIPTION_STR    "Windows 9x Display Minidriver"',
            '#define VER_FILEDESCRIPTION_STR    "Shizuku basic graphics driver"')
    replace("res/display.rcv", '#define VER_PRODUCTNAME_STR         "Windows 9x Display Driver\\0"',
            '#define VER_PRODUCTNAME_STR         "Shizuku basic graphics driver\\0"')
    # Backend and bounded wire parser are original root-owned GPL sources.
    original["vxd_vesa.c"] = (work / "vxd_vesa.c").read_text()
    shutil.copy2(HERE / "backend.c", work / "vxd_vesa.c")
    shutil.copy2(HERE / "gop_contract.h", work / "gop_contract.h")
    diff = []
    for name, old in original.items():
        diff.extend(difflib.unified_diff(old.splitlines(keepends=True), (work / name).read_text().splitlines(keepends=True),
                                        fromfile="a/" + name, tofile="b/" + name))
    return before, source_manifest(work), "".join(diff)


def validate_ne(drv):
    """Validate the actual NE selector/import relocations before packaging."""
    def bounded(at, size):
        if at < 0 or size < 0 or at > len(drv) or size > len(drv) - at:
            raise RuntimeError("NE structure exceeds its frozen file")
        return at

    def word(at):
        return struct.unpack_from("<H", drv, bounded(at, 2))[0]

    if len(drv) < 64 or drv[:2] != b"MZ":
        raise RuntimeError("DRV must have a complete MZ header")
    ne = struct.unpack_from("<I", drv, 0x3c)[0]
    bounded(ne, 64)
    if drv[ne:ne + 2] != b"NE" or word(ne + 0x3e) != 0x400:
        raise RuntimeError("DRV must be NE with expected Windows version 4.0")
    count, module_count = word(ne + 0x1c), word(ne + 0x1e)
    if not 1 <= count <= 255 or not 1 <= module_count <= 255:
        raise RuntimeError("NE segment/module counts exceed the bounded display-driver profile")
    segment_at = bounded(ne + word(ne + 0x22), count * 8)
    module_at = bounded(ne + word(ne + 0x28), module_count * 2)
    names_at = bounded(ne + word(ne + 0x2a), 1)
    shift = word(ne + 0x32) or 9
    if shift > 16:
        raise RuntimeError("NE file alignment exceeds the bounded profile")

    def name(offset):
        at = bounded(names_at + offset, 1)
        length = drv[at]
        bounded(at + 1, length)
        if not length or any(c < 32 or c > 126 for c in drv[at + 1:at + 1 + length]):
            raise RuntimeError("NE import name is empty or invalid")
        return drv[at + 1:at + 1 + length].decode("ascii")

    modules = [name(word(module_at + i * 2)) for i in range(module_count)]
    segments = []
    for i in range(count):
        page, size, flags, memory = struct.unpack_from("<4H", drv, segment_at + i * 8)
        size, memory = size or 65536, memory or 65536
        if not page or memory < size:
            raise RuntimeError("NE packaged segment lacks backing or sufficient memory")
        at = bounded(page << shift, size)
        segments.append((at, size, flags, memory))
    entry_at, entry_size = word(ne + 4), word(ne + 6)
    pos = bounded(ne + entry_at, entry_size)
    end, ordinal, entries = pos + entry_size, 1, {}
    while pos < end:
        bundle_count = drv[pos]
        pos += 1
        if not bundle_count:
            break
        if pos >= end:
            raise RuntimeError("NE entry bundle lacks its segment identifier")
        kind = drv[pos]
        pos += 1
        if kind:
            stride = 6 if kind == 255 else 3
            if kind == 254 or pos + bundle_count * stride > end:
                raise RuntimeError("NE entry bundle is unsupported or incomplete")
            for i in range(bundle_count):
                segment = drv[pos + 3] if kind == 255 else kind
                offset = word(pos + (4 if kind == 255 else 1))
                if not 1 <= segment <= count or offset >= segments[segment - 1][3]:
                    raise RuntimeError("NE entry targets a missing segment or invalid offset")
                entries[ordinal + i] = (segment, offset)
                pos += stride
        ordinal += bundle_count
    ip, cs = word(ne + 0x14), word(ne + 0x16)
    if not 1 <= cs <= count or ip >= segments[cs - 1][1] or segments[cs - 1][2] & 1:
        raise RuntimeError("NE initialization entry does not point into backed code")
    auto = word(ne + 0xe)
    if not 1 <= auto <= count or not segments[auto - 1][2] & 1:
        raise RuntimeError("NE automatic data segment is invalid")
    imports, relocation_count = set(), 0
    widths = {0: 1, 2: 2, 3: 4, 5: 2, 11: 6, 13: 4}
    for at, size, flags, memory in segments:
        if not flags & 0x100:
            continue
        record_at = bounded(at + size, 2)
        records = word(record_at)
        record_at = bounded(record_at + 2, records * 8)
        relocation_count += records
        for i in range(records):
            source_type, target_flags, source, target, target_offset = struct.unpack_from("<BBHHH", drv, record_at + i * 8)
            kind = target_flags & 3
            if source_type not in widths or target_flags & ~7:
                raise RuntimeError("NE relocation type/flags are unsupported")
            if kind == 0:
                target_segment = target & 255
                if target >> 8:
                    raise RuntimeError("NE internal relocation targets a missing segment")
                if target_segment == 255:
                    if target_offset not in entries:
                        raise RuntimeError("NE internal relocation targets a missing entry ordinal")
                elif not 1 <= target_segment <= count:
                    raise RuntimeError("NE internal relocation targets a missing segment")
                elif source_type != 2 and target_offset >= segments[target_segment - 1][3]:
                    raise RuntimeError("NE internal relocation exceeds target memory")
            elif kind in (1, 2):
                if not 1 <= target <= module_count:
                    raise RuntimeError("NE import relocation targets a missing module")
                symbol = target_offset if kind == 1 else name(target_offset)
                if kind == 1 and not symbol:
                    raise RuntimeError("NE import ordinal is zero")
                imports.add((modules[target - 1], kind, symbol))
            else:
                raise RuntimeError("NE OS fixups are outside the native display-driver profile")
            seen = set()
            while True:
                if source in seen or source + widths[source_type] > size:
                    raise RuntimeError("NE relocation source chain is cyclic or outside backing")
                seen.add(source)
                if target_flags & 4:
                    break
                if source + 2 > size:
                    raise RuntimeError("NE relocation chain link exceeds backing")
                source = word(at + source)
                if source == 0xffff:
                    break
    return {"segments": count, "entry_cs": cs, "entry_ip": ip,
            "relocation_records": relocation_count, "relocation_targets": "all valid",
            "import_modules": modules,
            "imports": [{"module": m, "kind": "ordinal" if k == 1 else "name", "symbol": s}
                        for m, k, s in sorted(imports)]}


def validate_binaries(work):
    drv = (work / "SHZGOP.DRV").read_bytes()
    vxd = (work / "SHZGOP.VXD").read_bytes()
    ne_validation = validate_ne(drv)
    ne = struct.unpack_from("<I", drv, 0x3c)[0]
    le = struct.unpack_from("<I", vxd, 0x3c)[0]
    if drv[:2] != b"MZ" or drv[ne:ne + 2] != b"NE" or struct.unpack_from("<H", drv, ne + 0x3e)[0] != 0x400:
        raise RuntimeError("DRV must be NE with expected Windows version 4.0")
    entry_at, entry_bytes = struct.unpack_from("<HH", drv, ne + 4)
    pos, end, ordinal, ordinals = ne + entry_at, ne + entry_at + entry_bytes, 1, []
    while pos < end:
        n = drv[pos]
        pos += 1
        if not n:
            break
        kind = drv[pos]
        pos += 1
        if kind:
            stride = 6 if kind == 255 else 3
            if pos + n * stride > end:
                raise RuntimeError("NE export bundle exceeds its entry table")
            ordinals.extend(range(ordinal, ordinal + n))
            pos += n * stride
        ordinal += n
    required = set(range(1, 33)) | {101, 102, 103, 104, 450, 500, 700}
    if not required.issubset(ordinals):
        raise RuntimeError("NE display driver lacks required DIBEngine display exports")
    if vxd[:2] != b"MZ" or vxd[le:le + 2] != b"LE":
        raise RuntimeError("VxD must be LE")
    table, count = struct.unpack_from("<II", vxd, le + 0x40)
    if not 1 <= count <= 32 or le + table + count * 24 > len(vxd):
        raise RuntimeError("Invalid LE object table")
    objects = [dict(zip(("size", "base", "flags", "page_index", "pages", "reserved"),
                        struct.unpack_from("<6I", vxd, le + table + i * 24))) for i in range(count)]
    if any(obj["base"] != 0 or not obj["flags"] & 4 for obj in objects):
        raise RuntimeError("fixlink must mark every LE object executable with base zero")
    entry = le + struct.unpack_from("<I", vxd, le + 0x5c)[0]
    n, kind, objno, flags, offset = struct.unpack_from("<BBHBI", vxd, entry)
    if n != 1 or kind != 3 or not flags & 1 or not 1 <= objno <= count or vxd[entry + 9] != 0:
        raise RuntimeError("LE must export one ordinal-1 32-bit DDB")
    obj = objects[objno - 1]
    page_size = struct.unpack_from("<I", vxd, le + 0x28)[0]
    if page_size != 4096 or offset + 80 > obj["size"] or not obj["flags"] & 2:
        raise RuntimeError("DDB must be complete and writable")
    map_at = le + struct.unpack_from("<I", vxd, le + 0x48)[0]
    page = obj["page_index"] - 1 + offset // page_size
    mapping = vxd[map_at + 4 * page:map_at + 4 * page + 4]
    if len(mapping) != 4 or mapping[3] != 0:
        raise RuntimeError("DDB page must have ordinary physical backing")
    page_number = int.from_bytes(mapping[:3], "big")
    data_at = struct.unpack_from("<I", vxd, le + 0x80)[0]
    ddb_at = data_at + (page_number - 1) * page_size + offset % page_size
    ddb = vxd[ddb_at:ddb_at + 80]
    if len(ddb) != 80 or ddb[:4] != bytes(4) or ddb[12:20] != b"SHZGOP  " or struct.unpack_from("<H", ddb, 6)[0] != 0x4353:
        raise RuntimeError("DDB private device identity mismatch")
    if struct.unpack_from("<H", ddb, 4)[0] != struct.unpack_from("<H", vxd, le + 0xc2)[0] or struct.unpack_from("<I", ddb, 64)[0] != 80:
        raise RuntimeError("DDB/header SDK or DDB size mismatch")
    return {"DRV": {"format": "NE", "windows_version": "4.0", **ne_validation, "export_ordinals": ordinals},
            "VXD": {"format": "LE", "objects": objects,
                    "ddb": {"ordinal": 1, "object": objno, "offset": offset, "bytes": 80,
                            "device_id": "0x4353", "name": "SHZGOP  ", "sdk": struct.unpack_from("<H", ddb, 4)[0]}},
            "native_load_and_render": "pending"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    out = args.out.resolve()
    if out == shzlib.BUILD.resolve() or not out.is_relative_to(shzlib.BUILD.resolve()):
        parser.error("--out must be a component directory inside build/shizukudos")
    out.mkdir(parents=True, exist_ok=True)
    work = out / "work"
    vmd = pinned_tree(REF, "https://github.com/JHRobotics/vmdisp9x.git", VMDISP_COMMIT)
    fix = pinned_tree(FIXREF, "https://github.com/JHRobotics/fixlink.git", FIXLINK_COMMIT)
    original_inputs = {name: digest(HERE / name) for name in ("backend.c", "gop_contract.h", "build.py", "SHZGOP.INF", "README.md", "NOTICE.md")}
    upstream_inputs = source_manifest(vmd)
    fixlink_inputs = source_manifest(fix)
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(vmd, work, ignore=shutil.ignore_patterns(".git", "fixlink", "docs", "tools", "*.obj", "*.drv", "*.vxd", "*.res", "*.bin"))
    before, after, patch = adapt(work)
    (out / "source-adaptations.patch").write_text(patch)
    env = shzlib.ow_env()
    env.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": "1785283200"})
    ow = Path(env["WATCOM"])
    commands = []
    log = out / "build.log"
    log.write_text("")

    def run(argv):
        argv = [str(arg) for arg in argv]
        result = shzlib.run(argv, cwd=work, env=env, capture=True, check=False)
        commands.append({"argv": argv, "exit": result.returncode})
        with log.open("a") as stream:
            stream.write("$ " + " ".join(argv) + "\n" + result.stdout + "\n")
        if result.returncode:
            raise RuntimeError(f"Build failed ({result.returncode}); see {log}: {' '.join(argv)}")

    incs = ["-I" + str(ow / "h" / "win"), "-Iddk", "-Ivmware", "-I" + str(ow / "h")]
    flags = ["-DDRV_VER_BUILD=1", "-DDBGPRINT", "-DCOM1"]
    for name in C16:
        run(["wcc", "-q", "-wx", "-s", "-zu", "-zls", "-4", "-fp3", "-zW", *incs, *flags, "-fo=" + Path(name).name + ".obj", name + ".c"])
    for name in A16:
        run(["wasm", "-q", *flags, "-fo=" + name + ".obj", name + ".asm"])
    for name in C32:
        run(["wcc386", "-q", "-wx", "-s", "-zls", "-mf", "-DVXD32", "-fpi87", "-ei", "-oeatxhn", "-4s", "-fp3", *incs, *flags,
             "-fo=" + Path(name).name + ".obj", name + ".c"])
    for name in ("colortab", "config", "fonts", "fonts120"):
        run(["wcc", "-q", *incs, "-fo=" + name + ".obj", "res/" + name + ".c"])
        run(["wlink", "op", "quiet", "disable", "1014,1023", "name", "res/" + name + ".bin", "sys", "dos", "output", "raw", "file", name + ".obj"])
    run(["wlib", "-b", "-q", "-n", "-fo", "-ii", "@ddk/dibeng.lbc", "dibeng.lib"])
    run(["gcc", "-std=c99", "-O2", "-Wall", "-Dstricmp=strcasecmp", "-include", "strings.h", fix / "fixlink.c", "-o", work / "fixlink"])
    makefile = (vmd / "makefile").read_text()
    link16 = makefile.split("<<vesamini.lnk\n", 1)[1].split("\n<<", 1)[0]
    link16 = link16.replace("name vesamini.drv", "name SHZGOP.DRV").replace("map=vesamini.map", "map=SHZGOP16.map")
    (work / "SHZGOP16.lnk").write_text("option quiet, start=DriverInit_\ndisable 2055\nfile dbgprint.obj\n" + link16 + "\n")
    run(["wlink", "@SHZGOP16.lnk"])
    run(["wrc", "-q", "-r", "-bt=windows", "-fo=SHZGOP.res", "-Ires", "-I.", *incs, *flags, "res/vesamini.rc"])
    run(["wrc", "-q", "SHZGOP.res", "SHZGOP.DRV"])
    run([work / "fixlink", "-40", "SHZGOP.DRV"])
    link32 = "system win_vxd dynamic\noption quiet, nodefaultlibs\nname SHZGOP.VXD\noption map=SHZGOP32.map\n"
    link32 += "".join("file " + Path(name).name + ".obj\n" for name in C32)
    link32 += "".join("segment '" + name + "' PRELOAD NONDISCARDABLE\n" for name in ("_TEXT", "_DATA", "CONST", "CONST2", "_BSS"))
    link32 += "export VXD_DDB.1\n"
    (work / "SHZGOP32.lnk").write_text(link32)
    run(["wlink", "@SHZGOP32.lnk"])
    pre_fix_sha = digest(work / "SHZGOP.VXD")
    run([work / "fixlink", "-vxd32", "SHZGOP.VXD"])
    formats = validate_binaries(work)
    for name, expected in original_inputs.items():
        if digest(HERE / name) != expected:
            raise RuntimeError(f"Original input changed while building: {name}; rebuild from a stable snapshot")
    if source_manifest(vmd) != upstream_inputs or source_manifest(fix) != fixlink_inputs:
        raise RuntimeError("Pinned reference sources changed while building")
    package = out / "package"
    if package.exists():
        shutil.rmtree(package)
    package.mkdir()
    for name in ("SHZGOP.DRV", "SHZGOP.VXD"):
        shutil.copy2(work / name, package / name)
    shutil.copy2(HERE / "SHZGOP.INF", package / "SHZGOP.INF")
    (package / "README.txt").write_bytes((HERE / "README.md").read_text().replace("\n", "\r\n").encode("ascii"))
    (package / "NOTICE.txt").write_bytes((HERE / "NOTICE.md").read_text().replace("\n", "\r\n").encode("ascii"))
    shutil.copy2(vmd / "LICENSE", package / "LICENSE.MIT")
    shutil.copy2(fix / "licence.txt", package / "FIXLINK.MIT")
    shutil.copy2(REPO / "LICENSE", package / "GPL-2.0.txt")
    shutil.copy2(ow / "license.txt", package / "WATCOM.txt")
    with zipfile.ZipFile(package / "SOURCE.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        def add(path, name):
            info = zipfile.ZipInfo(name, date_time=(2026, 7, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
        for name in after:
            add(work / name, "vmdisp9x/" + name)
        for name in original_inputs:
            add(HERE / name, "drivers/shizuku_gop/" + name)
        add(fix / "fixlink.c", "fixlink/fixlink.c")
        add(fix / "licence.txt", "fixlink/licence.txt")
        add(out / "source-adaptations.patch", "source-adaptations.patch")
        add(work / "SHZGOP16.lnk", "vmdisp9x/SHZGOP16.lnk")
        add(work / "SHZGOP32.lnk", "vmdisp9x/SHZGOP32.lnk")
        add(REPO / "shizukudos/tools/shzlib.py", "shizukudos/tools/shzlib.py")
        add(REPO / "shizukudos/upstream/manifest.json", "shizukudos/upstream/manifest.json")
    artifacts = {p.name: {"sha256": digest(p), "bytes": p.stat().st_size} for p in sorted(package.iterdir())}
    delivery = out / "SHZGOP.zip"
    with zipfile.ZipFile(delivery, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(package.iterdir()):
            info = zipfile.ZipInfo(path.name, date_time=(2026, 7, 29, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes())
    receipt = {"schema": 1, "status": "HOST-BUILD-PASS", "built_utc": shzlib.utc_now(),
               "profile": "Shizuku basic graphics driver: native Win98 NE DRV + LE VxD",
               "runtime_validation": "pending: native install/load/GDI rendering requires guest evidence",
               "upstreams": {"vmdisp9x": {"repository": "https://github.com/JHRobotics/vmdisp9x", "commit": VMDISP_COMMIT, "license": "MIT", "sources": upstream_inputs},
                             "fixlink": {"repository": "https://github.com/JHRobotics/fixlink", "commit": FIXLINK_COMMIT, "license": "MIT", "sources": fixlink_inputs}},
               "original_inputs": original_inputs, "adaptations_sha256": digest(out / "source-adaptations.patch"),
               "copied_sources_before": before, "compiled_sources": after,
               "generated_link_inputs": {name: digest(work / name) for name in ("SHZGOP16.lnk", "SHZGOP32.lnk")},
               "open_watcom_snapshot": shzlib.open_watcom_snapshot()[0],
               "toolchain": {name: {"path": str(ow / "binl64" / name), "sha256": digest(ow / "binl64" / name)}
                             for name in ("wcc", "wcc386", "wlink", "wasm", "wrc", "wlib")},
               "commands": commands,
               "formats": formats, "vxd_before_fixlink_sha256": pre_fix_sha,
               "delivery_zip": {"name": delivery.name, "sha256": digest(delivery), "bytes": delivery.stat().st_size},
               "package_allowlist": sorted(artifacts), "artifacts": artifacts}
    shzlib.write_json(out / "build-result.json", receipt)
    print(json.dumps({"status": receipt["status"], "artifacts": artifacts, "receipt": str(out / "build-result.json")}, indent=2))


if __name__ == "__main__":
    main()
