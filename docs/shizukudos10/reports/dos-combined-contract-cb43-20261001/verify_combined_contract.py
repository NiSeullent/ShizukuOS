#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check frozen combined production DOS handlers and real linked table bytes.

Creates an independent output directory. Never starts DOS/Windows/VMs or modifies
the supplied source tree. The host far-pointer and CDS layouts are adapters;
the separately compiled Watcom assertion checks the real DOS CDS layout.
"""
import argparse
import ast
import hashlib
import json
import pathlib
import re
import struct
import subprocess

EXPECTED = {
    "kernel/inthndlr.c": "e44dc4ccb2dd964d00ef067a2d24a881cdf8d7c5f1a2dc1722cd6b6f291f16ab",
    "kernel/dosfns.c": "9be568d1aef728738aea0d906c55beafc198b7625a036e269fbc1ce11b2cc816",
    "hdr/win.h": "f9ea9584c81a8228b9dcd53758732941bb11435773dbd5ec7b4383375a61f17b",
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def between(text, start, end):
    a = text.index(start)
    return text[a:text.index(end, a + len(start))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path(__file__).resolve().parents[4])
    args = parser.parse_args()
    tree, out, repo = args.kernel_tree.resolve(), args.output.resolve(), args.repo.resolve()
    if out == tree or tree in out.parents:
        raise SystemExit("use an independent output directory")
    for name, expected in EXPECTED.items():
        if sha(tree / name) != expected:
            raise SystemExit("combined production source hash mismatch: " + name)
    out.mkdir(parents=True, exist_ok=False)
    original_fixture = repo / "shizukudos/dos16/tests/test_cb43_dos_internals.py"
    template_ast = ast.parse(original_fixture.read_text())
    main_ast = next(n for n in template_ast.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    header = next(n.value.value for n in main_ast.body if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "header" for t in n.targets))
    test_main = next(n.value.value for n in main_ast.body if isinstance(n, ast.AugAssign)
                     and isinstance(n.value, ast.Constant) and "int main(void)" in str(n.value.value))
    # Reuse only the frozen host adapter and 38 test assertions. Every production
    # handler below is freshly extracted from this hash-verified combined tree.
    header = header.replace('#include "source/hdr/win.h"', '#include "' + str(tree / "hdr/win.h") + '"')
    extra = r'''
#define DH d.b.h
struct WinPatchTable winPatchTable;
static int nul_dev;
struct cds { unsigned char bytes[88]; };
typedef struct { UBYTE m_type; UWORD m_psp, m_size; } mcb;
static mcb untested_mcb;
#define MK_PTR(type,seg,off) ((void)(seg),(void)(off),(type *)&untested_mcb)
#define hiword(x) ((UWORD)((x)>>16))
#define loword(x) ((UWORD)(x))
static void DosIdle_hlt(void) {}
static unsigned long dosmgr_frames;
#define EXPECT_FRAME(c,label) do { ++dosmgr_frames; if (!(c)) { fprintf(stderr,"FAIL %s frame %lu\n",label,dosmgr_frames); return 1; } } while(0)
'''
    handler = (tree / "kernel/inthndlr.c").read_text()
    handler = handler[handler.index("VOID ASMCFUNC int2F_12_handler"):]
    full_win = between(handler, '  else if (r.AH == 0x16) /* Window/Multitasking hooks */',
                       '  else if (r.AH == 0x46) /* MS Windows WinOLDAP switching */')
    full_win = full_win.replace("  else if", "  if", 1)
    internal_cases = "".join(between(handler, a, b) for a, b in (
        ("    case 0x16:", "    case 0x17:"), ("    case 0x20:", "    case 0x21:"),
        ("    case 0x31:", "    default:")))
    sft_functions = between((tree / "kernel/dosfns.c").read_text(), "int idx_to_sft_(", "sft FAR *get_sft(")
    clear_flags = "  r.FLAGS &= ~FLG_CARRY;  /* assume success, ensure carry clear */"
    if clear_flags not in handler:
        raise SystemExit("production entry FLAGS behavior changed")
    code = header + extra + sft_functions
    code += "\nstatic void run_win(regs *pr) {\n#define r (*pr)\n" + clear_flags + "\n" + full_win + "\n#undef r\n}\n"
    for name, enabled in (("run_internal", True), ("run_internal_no_windows", False)):
        if not enabled:
            code += "#undef WIN31SUPPORT\n"
        code += "static void " + name + "(regs *pr) {\n#define r (*pr)\nr.FLAGS &= ~FLG_CARRY;\nswitch(r.AL) {\n"
        code += internal_cases + "\n}\nreturn;\nerror_carry: r.FLAGS |= FLG_CARRY;\n#undef r\n}\n"
    combined_tests = r'''
  /* Actual outer AH/BX gates and complete production Windows case switch. */
  r.AX=0x1606; run_win(&r);
  memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=0x15; r.CX=0; r.FLAGS=0x8243;
  run_win(&r);
  CHECK(r.CX==0 && r.DX==FP_SEG(&nul_dev) && r.ES==FP_SEG(&winPatchTable) && r.BX==FP_OFF(&winPatchTable) && r.FLAGS==0x8242,
        "1607 idle query reports no Windows and actual host-adapted table/driver pointers");
  r.AX=0x1605; r.CX=0; r.ES=0x4567; r.BX=0x89ab; r.DI=0x040a; run_win(&r);
  r.AX=0x1607; r.BX=0x15; r.CX=0; run_win(&r);
  CHECK(r.CX==1 && r.ES==FP_SEG(&winPatchTable) && r.BX==FP_OFF(&winPatchTable), "1605 then1607 query reports actual active state");
  for (unsigned long mask=0;mask<65536ul;++mask) {
    memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=0x15; r.CX=1; r.DX=(UWORD)mask; r.FLAGS=0x8243; saved=r;
    run_win(&r); saved.AX=0xb97c; saved.BX=0; saved.DX=0xa2ab; saved.FLAGS=0x8242;
    EXPECT_FRAME(!memcmp(&r,&saved,sizeof r), "1607 CX1 requested mask is never echoed as applied");
  }
  CHECK(1,"1607 CX1 all65536 patch masks validated as unapplied");
  for (unsigned long selector=0;selector<65536ul;++selector) {
    memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=0x15; r.CX=3; r.DX=(UWORD)selector; r.FLAGS=0x8243; saved=r;
    run_win(&r); saved.FLAGS=0x8242;
    if(selector==1) { saved.AX=0xb97c; saved.CX=88; saved.DX=0xa2ab; } else saved.CX=0;
    EXPECT_FRAME(!memcmp(&r,&saved,sizeof r),"1607 CX3 uses exactDX selector and preserves unsupported frame");
  }
  CHECK(1,"1607 CX3 all65536 structure selectors validate onlyDX1");
  for (unsigned long mask=0;mask<65536ul;++mask) {
    memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=0x15; r.CX=4; r.DX=(UWORD)mask; r.FLAGS=0x8243; saved=r;
    run_win(&r); saved.CX=0; saved.DX=0; saved.FLAGS=0x8242;
    EXPECT_FRAME(!memcmp(&r,&saved,sizeof r),"1607 CX4 all requests return unsupported, no success signature");
  }
  CHECK(1,"1607 CX4 all65536 instancing masks reject honestly");
  for (unsigned long device=0;device<65536ul;++device) {
    if(device==0x15) continue;
    memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=(UWORD)device; r.CX=1; r.DX=0xffff; r.FLAGS=0x8243; saved=r;
    run_win(&r); saved.FLAGS=0x8242;
    EXPECT_FRAME(!memcmp(&r,&saved,sizeof r),"1607 nonDOSMGR BX device leaves register frame unchanged");
  }
  CHECK(1,"1607 all65535 otherBX devices preserve frame after productionCF clear");
  for (unsigned long function=0;function<65536ul;++function) {
    if(function<=5) continue;
    memset(&r,0x55,sizeof r); r.AX=0x1607; r.BX=0x15; r.CX=(UWORD)function; r.DX=0xffff; r.FLAGS=0x8243; saved=r;
    run_win(&r); saved.FLAGS=0x8242;
    EXPECT_FRAME(!memcmp(&r,&saved,sizeof r),"1607 unknownCX function preserves frame after productionCF clear");
  }
  CHECK(1,"1607 all65530 unknownCX functions preserve frame");
  r.AX=0x1507; r.BX=0x15; r.CX=1; r.DX=0xffff; r.FLAGS=0x8243; saved=r; run_win(&r); saved.FLAGS=0x8242;
  CHECK(!memcmp(&r,&saved,sizeof r),"Windows productionAH guard never dispatches unrelated1507");
  r.AX=0x1607; r.BX=0x15; r.CX=2; r.DX=0xbeef; r.FLAGS=0x8243; saved=r; run_win(&r); saved.CX=0; saved.FLAGS=0x8242;
  CHECK(!memcmp(&r,&saved,sizeof r),"1607 CX2 disable follows realDOS5/6 no-op reply");
  r.AX=0x1231; r.DX=1; run_internal(&r); r.AX=0x1607; r.BX=0x15; r.CX=0; run_win(&r);
  CHECK(r.CX==1 && winReportHidden==1,"1231 hides presence without changingDOSMGR instanced query");
  r.AX=0x1606; run_win(&r); r.AX=0x1607; r.BX=0x15; r.CX=0; run_win(&r);
  CHECK(r.CX==0 && !winActiveVersion && !winReportHidden,"1606 then1607 query clears actual active/presence state");
  printf("DOSMGR_REGISTER_FRAMES %lu PASS\n",dosmgr_frames);
'''
    test_main = test_main.replace('  printf("CHECKS %u PASS\\n",checks);', combined_tests + '\n  printf("CHECKS %u PASS\\n",checks);')
    code += test_main
    source, binary = out / "production-combined-fixture.c", out / "production-combined-fixture"
    source.write_text(code)
    commands = [["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing", str(source), "-o", str(binary)]]
    compiled = subprocess.run(commands[0], capture_output=True, text=True)
    (out / "compile.log").write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    tested = subprocess.run([str(binary)], capture_output=True, text=True)
    (out / "host-results.txt").write_text(tested.stdout + tested.stderr)
    tested.check_returncode()
    checks = [line[5:] for line in tested.stdout.splitlines() if line.startswith("PASS ")]
    frames = int(re.search(r"DOSMGR_REGISTER_FRAMES (\d+) PASS", tested.stdout)[1])
    # Real DOS compiler, real production headers, compile-time size assertion.
    native = out / "native-cds-layout.c"
    native.write_text('#include "portab.h"\n#include "cds.h"\ntypedef char cb43_actual_dos_cds_is_88[sizeof(struct cds)==88?1:-1];\nunsigned short cb43_actual_cds_bytes=sizeof(struct cds);\n')
    native_command = ["wcc", "-zq", "-bt=dos", "-ms", "-zp1", "-wx", "-we", "-i=" + str(tree / "hdr"), "-fo=" + str(out / "native-cds-layout.obj"), str(native)]
    native_result = subprocess.run(native_command, capture_output=True, text=True)
    (out / "native-cds-layout.log").write_text(native_result.stdout + native_result.stderr)
    native_result.check_returncode()
    commands.append(native_command)
    exe = (tree / "kernel/kernel.exe").read_bytes()
    hdr = struct.unpack_from("<14H", exe)
    image = exe[hdr[4] * 16:]
    flat = (tree / "kernel/kernel.sys").read_bytes()
    symbols = {}
    for line in (tree / "kernel/kernel.map").read_text().splitlines():
        match = re.match(r"([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\*?\s+(\S+)", line)
        if match: symbols[match[3]] = (int(match[1], 16), int(match[2], 16))
    ds, table = symbols["_winPatchTable"]
    words = struct.unpack_from("<7H", image, ds * 16 + table)
    table_checks = []
    def check(condition, label):
        if not condition: raise ValueError(label)
        table_checks.append(label)
    check(ds == symbols["_DATASTART"][0] == symbols["_nul_dev"][0], "query table/driver symbols share actual DOS data segment")
    check(words[0] == 6, "linked patch table retains actual DOS6 format version")
    check(words[1] == words[2] + 2 and words[2] + 4 <= symbols["_markEndInstanceData"][1], "saved DS/BX offsets are adjacent inside instanced region")
    check(words[3] == symbols["_InDOS"][1], "linked InDOS patch offset matches actual symbol")
    check(words[4] == symbols["_MachineId"][1], "linked MachineID offset matches actual symbol")
    check(words[5] == symbols["_CritPatch"][1] and struct.unpack_from("<H", image, ds * 16 + words[5])[0] == 0, "linked critical patch list is an actual zero-word terminator")
    check(words[6] == symbols["_uppermem_root"][1], "linked last-arena offset matches actual source symbol")
    check(table + 14 == symbols["_winReportHidden"][1] and table + 15 < symbols["_firstsftt"][1], "linked patch table ends before presence byte and fixed SFT")
    check(image[ds * 16 + table:ds * 16 + table + 14] == flat[ds * 16 + table:ds * 16 + table + 14], "flattened actual patch table preserves all offset words")
    receipt = {
        "schema": "shizukudos-cb43-combined-contract-fixture-v1", "VM_executed": False,
        "Windows98_boot_verified": False, "ShizukuDOS_replaces_MSDOS_verified": False,
        "production_inputs_sha256": EXPECTED, "template_sha256": sha(original_fixture),
        "fixture_source_sha256": sha(source), "host_binary_sha256": sha(binary),
        "host_checks": checks, "passed": len(checks), "failed": 0,
        "exhaustive_DOSMGR_register_frames": frames, "native_CDS_size_assertion": {"bytes": 88, "compiler_exit_code": native_result.returncode, "object_sha256": sha(out / "native-cds-layout.obj")},
        "linked_patch_table": {"passed": len(table_checks), "failed": 0, "checks": table_checks, "words": list(words), "data_segment": ds, "table_offset": table, "driver_offset": symbols["_nul_dev"][1], "kernel_exe_sha256": sha(tree / "kernel/kernel.exe"), "kernel_sys_sha256": sha(tree / "kernel/kernel.sys")},
        "commands": [[value.replace(str(out), "${OUTPUT}").replace(str(tree), "${KERNEL_TREE}") for value in command] for command in commands],
        "limits": ["Production Windows switch and AH/BX/FLAGS guards executed with host far-pointer adapter; not native DOS interrupts", "Host CDS88 layout is adapted; native Watcom compile-time assertion checks actual production header", "DOSMGR device-size CX5 and idle/other Windows cases are compiled, not exercised", "Actual linked table pointers/offset bytes do not prove Windows accepts or patches the FreeDOS layout", "No guest was run; no Windows 98, MS-DOS replacement or native modern application proof"],
    }
    (out / "combined-contract-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": len(checks), "register_frames": frames, "linked_table_checks": len(table_checks), "failed": 0, "VM_executed": False}))


if __name__ == "__main__":
    main()
