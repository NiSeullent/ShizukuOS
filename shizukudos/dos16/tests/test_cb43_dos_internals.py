#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Host regression of selected *production* FreeDOS DOS-internal handlers.

Supply an unmodified checkout at the pinned commit and an unused output folder.
This copies and patches that checkout without modifying it, extracts production
functions/case bodies, then compiles them with a host-only far-pointer adapter.
It does not emulate DOS, execute a VM, or demonstrate Windows boot compatibility.
"""
import argparse
import hashlib
import json
import pathlib
import subprocess

PIN = "5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3"
PREIMAGES = {
    "hdr/win.h": "7688c971830beb6274c490db7d97a04c7a19772e9cba1fae60e003c77b3a59f0",
    "kernel/kernel.asm": "d678196d67f88111ebf3b6b60edaa068a8feb64016073bb7b799de48160ed50f",
    "kernel/inthndlr.c": "0793e3bb94c558b6fdeb335f9e15577486b4b6ae53e987c89c095909fb363727",
    "kernel/dosfns.c": "9be568d1aef728738aea0d906c55beafc198b7625a036e269fbc1ce11b2cc816",
}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def between(text, start, end):
    a = text.index(start)
    return text[a:text.index(end, a + len(start))]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upstream", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()
    upstream, out = args.upstream.resolve(), args.output.resolve()
    assert out != upstream and upstream not in out.parents
    out.mkdir(parents=True, exist_ok=False)
    tree = out / "source"
    tree.mkdir()
    manifest = []
    for name, expected in PREIMAGES.items():
        raw = (upstream / name).read_bytes()
        if sha(raw) != expected:
            raise SystemExit(f"preimage mismatch: {name}")
        target = tree / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        manifest.append({"path": name, "preimage_sha256": expected})
    patch = pathlib.Path(__file__).resolve().parents[1] / "patches/0003-cb43-win98-dos-internals.patch"
    command = ["patch", "--batch", "--fuzz=0", "-p1", "-i", str(patch)]
    applied = subprocess.run(command, cwd=tree, capture_output=True, text=True, check=True)
    (out / "apply.log").write_text(applied.stdout + applied.stderr)
    for item in manifest:
        item["postimage_sha256"] = sha((tree / item["path"]).read_bytes())
    handler = (tree / "kernel/inthndlr.c").read_text()
    handler = handler[handler.index("VOID ASMCFUNC int2F_12_handler"):]
    win_cases = "".join(between(handler, a, b) for a, b in (
        ("      case 0x0:", "      case 0x0A:"),
        ("      case 0x05:", "      case 0x07:"),
    ))
    internal_cases = "".join(between(handler, a, b) for a, b in (
        ("    case 0x16:", "    case 0x17:"),
        ("    case 0x20:", "    case 0x21:"),
        ("    case 0x31:", "    default:"),
    ))
    dosfns = (tree / "kernel/dosfns.c").read_text()
    sft_functions = between(dosfns, "int idx_to_sft_(", "sft FAR *get_sft(")
    header = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#define FAR
#define ASM
#define WIN31SUPPORT 1
#define DebugPrintf(x) ((void)0)
#define __GNUC_DISABLED_WIN_SEG_ONLY 1
typedef uint16_t UWORD;
typedef uint8_t UBYTE;
typedef uint32_t ULONG;
/* Host layout is adapted explicitly; it is not a segmented-memory emulator. */
#pragma pack(push, 1)
#include "source/hdr/win.h"
#pragma pack(pop)
struct WinStartupInfo winStartupInfo;
UWORD winInstanced, winseg1, winseg2, winseg3;
static UWORD winActiveVersion;
UBYTE winReportHidden, markEndInstanceData;
struct lol { int unused; } DATASTART;
typedef struct { UWORD sft_count, marker; } sft;
typedef struct sfttbl {
  struct sfttbl *sftt_next;
  UWORD sftt_count;
  sft sftt_table[128];
} sfttbl;
sfttbl *sfthead;
sft *lpCurSft;
typedef struct { UWORD ps_maxfiles; UBYTE *ps_filetab; } psp;
psp process;
UWORD cu_psp = 0x3344;
#define FP_SEG(p) ((UWORD)(((uintptr_t)(p) >> 16) & 0xffff))
#define FP_OFF(p) ((UWORD)((uintptr_t)(p) & 0xffff))
#define MK_FP(seg,off) ((void)((off)), (void)((seg)), (void *)&process)
#define DE_INVLDHNDL (-6)
#define FLG_CARRY 1
typedef union { UWORD x; struct { UBYTE l, h; } b; } word;
typedef struct { UWORD es, ds, di, si, bp; word a,b,c,d; UWORD flags; } regs;
#define AX a.x
#define AH a.b.h
#define AL a.b.l
#define BX b.x
#define CX c.x
#define DX d.x
#define DL d.b.l
#define DI di
#define ES es
#define FLAGS flags
static unsigned checks;
#define CHECK(c,label) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL %s\n",label); return 1; } puts("PASS " label); } while (0)
'''
    # GNU-specific segment relocations are retained and supplied by the adapter.
    code = header + sft_functions + "\nstatic void run_win(regs *pr) {\n#define r (*pr)\nr.FLAGS &= ~FLG_CARRY;\nswitch(r.AL) {\n" + win_cases + "\n}\n#undef r\n}\n"
    code += "static void run_internal(regs *pr) {\n#define r (*pr)\nr.FLAGS &= ~FLG_CARRY;\nswitch(r.AL) {\n" + internal_cases + "\n}\nreturn;\nerror_carry: r.FLAGS |= FLG_CARRY;\n#undef r\n}\n"
    code += "#undef WIN31SUPPORT\nstatic void run_internal_no_windows(regs *pr) {\n#define r (*pr)\nr.FLAGS &= ~FLG_CARRY;\nswitch(r.AL) {\n" + internal_cases + "\n}\nreturn;\nerror_carry: r.FLAGS |= FLG_CARRY;\n#undef r\n}\n"
    code += r'''
int main(void) {
  sfttbl a={0}, empty={0}, b={0};
  UBYTE jft[6]={0,1,2,3,0xff,6};
  regs r, saved;
  a.sftt_count=5; empty.sftt_count=0; b.sftt_count=3;
  a.sftt_next=&empty; empty.sftt_next=&b; b.sftt_next=(sfttbl *)-1;
  sfthead=&a; process.ps_maxfiles=6; process.ps_filetab=jft;
  CHECK(idx_to_sft_(0)==0 && lpCurSft==&a.sftt_table[0], "SFT first entry");
  CHECK(idx_to_sft_(4)==4 && lpCurSft==&a.sftt_table[4], "SFT first block boundary");
  CHECK(idx_to_sft_(5)==0 && lpCurSft==&b.sftt_table[0], "SFT traversal skips empty block");
  CHECK(idx_to_sft_(7)==2 && lpCurSft==&b.sftt_table[2], "SFT final chain entry");
  CHECK(idx_to_sft_(8)==-1 && lpCurSft==(sft *)-1, "SFT chain end rejects index");
  CHECK(idx_to_sft_(-1)==-1 && lpCurSft==(sft *)-1, "SFT negative index rejects");
  CHECK(idx_to_sft_(65535)==-1, "SFT invalid unsigned index rejects");
  b.sftt_table[1].sft_count=0;
  CHECK(idx_to_sft(6)==(sft *)-1, "closed SFT rejects actual file lookup");
  b.sftt_table[1].sft_count=1;
  CHECK(idx_to_sft(6)==&b.sftt_table[1], "opened SFT resolves actual file lookup");
  CHECK(get_sft_idx(5)==6, "JFT handle resolves system file number");
  CHECK(get_sft_idx(4)==-6, "closed JFT byte rejects handle");
  CHECK(get_sft_idx(6)==-6 && get_sft_idx(65535)==-6, "out of range JFT rejects handle");
  memset(&r,0x55,sizeof r); r.AX=0x1216; r.BX=6; r.FLAGS=0x0201;
  run_internal(&r);
  CHECK(r.BX==1 && r.ES==FP_SEG(&b.sftt_table[1]) && r.DI==FP_OFF(&b.sftt_table[1]) && r.FLAGS==0x0200, "1216 real chain pointer and relative index");
  r.AX=0x1216; r.BX=65535; r.ES=0x1234; r.DI=0x5678; r.FLAGS=0x0200;
  run_internal(&r);
  CHECK((r.FLAGS&1) && r.ES==0x1234 && r.DI==0x5678, "1216 invalid SFN preserves pointer");
  r.AX=0x1220; r.BX=5; r.FLAGS=0x0201; run_internal(&r);
  CHECK(!(r.FLAGS&1) && r.ES==FP_SEG(&jft[5]) && r.DI==FP_OFF(&jft[5]), "1220 returns JFT pointer not SFT pointer");
  r.AX=0x1220; r.BX=4; run_internal(&r);
  CHECK(!(r.FLAGS&1) && jft[4]==0xff, "1220 closed in-range slot remains a readable JFT byte");
  r.AX=0x1220; r.BX=6; r.ES=0x1234; r.DI=0x5678; run_internal(&r);
  CHECK((r.FLAGS&1) && r.AL==6 && r.AH==0x12 && r.ES==0x1234 && r.DI==0x5678, "1220 invalid handle uses AL=6 and preserves AH/pointer");
  memset(&winStartupInfo,0,sizeof winStartupInfo); winInstanced=0; winReportHidden=0;
  r.AX=0x1600; run_win(&r); CHECK(r.AX==0x1600, "1600 idle never invents Windows");
  r.AX=0x1231; r.DX=0x8101; r.BX=0xaaaa; r.FLAGS=0x0241; run_internal(&r);
  CHECK(r.AX==0 && r.FLAGS==0x0240 && winReportHidden==1 && r.BX==0xaaaa && r.DX==0x8101, "1231 hide uses DL only and preserves other flags/registers");
  r.AX=0x1231; r.DX=0xab02; r.BX=1; run_internal(&r);
  CHECK(r.AX==0 && !winReportHidden && !winInstanced, "1231 report does not create an instance");
  r.AX=0x1600; run_win(&r); CHECK(r.AX==0x1600, "1600 remains idle after report-enable");
  winReportHidden=1; r.AX=0x1231; r.DX=0xff00; r.FLAGS=0x0240; run_internal(&r);
  CHECK(r.AX==1 && r.FLAGS==0x0241 && winReportHidden==1, "1231 one-shot loader honestly unsupported");
  r.AX=0x1231; r.DX=0x0003; run_internal(&r);
  CHECK(r.AX==1 && (r.FLAGS&1) && winReportHidden==1, "1231 selector 3 rejects safely");
  r.AX=0x1231; r.DX=0xffff; run_internal(&r);
  CHECK(r.AX==1 && (r.FLAGS&1) && winReportHidden==1, "1231 selector 255 rejects safely");
  winReportHidden=0; r.AX=0x1605; r.CX=0xffff; r.ES=0x4567; r.BX=0x89ab; r.DI=0x040a; r.FLAGS=0x0200; saved=r;
  run_win(&r);
  CHECK(!winInstanced && !memcmp(&r,&saved,sizeof r), "1605 prior veto preserves registers and idle state");
  r.AX=0x1605; r.CX=0; r.ES=0x4567; r.BX=0x89ab; r.DI=0x040a; run_win(&r);
  CHECK(winStartupInfo.next==0x456789ab && r.ES==FP_SEG(&winStartupInfo) && r.BX==FP_OFF(&winStartupInfo), "1605 chains actual prior startup record");
  CHECK(winInstanced==1 && winStartupInfo.winver==0x0004 && winActiveVersion==0x040a && !winStartupInfo.optInstanceTable, "1605 caller supplied version with null optional data");
  r.AX=0x1605; r.CX=0; r.ES=FP_SEG(&winStartupInfo); r.BX=FP_OFF(&winStartupInfo); run_win(&r);
  CHECK(winStartupInfo.next==0x456789ab, "1605 repeat never forms self-referential chain");
  r.AX=0x1600; run_win(&r); CHECK(r.AX==0x0a04, "1600 reports caller supplied version only");
  r.AX=0x1231; r.DX=1; run_internal(&r); r.AX=0x1600; run_win(&r);
  CHECK(r.AX==0x1600 && winInstanced==1, "1231 hides reporting without destroying active state");
  r.AX=0x1231; r.DX=2; run_internal(&r); r.AX=0x1600; run_win(&r);
  CHECK(r.AX==0x0a04, "1231 restores genuine active-state reporting");
  r.AX=0x1231; r.DX=1; run_internal(&r); r.AX=0x1606; run_win(&r);
  CHECK(!winInstanced && !winReportHidden && !winActiveVersion, "1606 clears active and reporting state");
  r.AX=0x1600; run_win(&r); CHECK(r.AX==0x1600, "1600 idle after exit");
  CHECK(offsetof(struct WinStartupInfo,next)==2 && offsetof(struct WinStartupInfo,instanceTable)==14 && offsetof(struct WinStartupInfo,optInstanceTable)==18 && sizeof(struct WinStartupInfo)==22, "startup record C layout matches 4.0 offsets");
  r.AX=0x1605; r.CX=0; r.ES=0; r.BX=0; r.DI=0x030a; run_win(&r);
  CHECK(winStartupInfo.winver==0x0003 && winActiveVersion==0x030a, "1605 3.0 record major byte first, actual 3.10 version separate");
  r.AX=0x1600; run_win(&r);
  CHECK(r.AX==0x0a03, "1600 actual Windows version distinct from supported record version");
  r.AX=0x1606; run_win(&r);
  r.AX=0x1231; r.DX=1; r.FLAGS=0x0200; run_internal_no_windows(&r);
  CHECK(r.AX==1 && r.FLAGS==0x0201, "1231 no-Windows-support profile rejects hide");
  r.AX=0x1231; r.DX=2; run_internal_no_windows(&r);
  CHECK(r.AX==1 && (r.FLAGS&1), "1231 no-Windows-support profile rejects report");
  printf("CHECKS %u PASS\n",checks);
  return 0;
}
'''
    source = out / "production-fixture.c"
    source.write_text(code)
    binary = out / "production-fixture"
    compile_cmd = [args.cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing", str(source), "-o", str(binary)]
    compiled = subprocess.run(compile_cmd, cwd=out, capture_output=True, text=True)
    (out / "compile.log").write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    tested = subprocess.run([str(binary)], cwd=out, capture_output=True, text=True)
    (out / "host-results.txt").write_text(tested.stdout + tested.stderr)
    tested.check_returncode()
    checks = [line[5:] for line in tested.stdout.splitlines() if line.startswith("PASS ")]
    receipt = {
        "schema": "shizukudos-cb43-dos-internals-host-v1",
        "upstream_commit": PIN, "patch_sha256": sha(patch.read_bytes()),
        "preimages": manifest, "fixture_source_sha256": sha(source.read_bytes()),
        "host_binary_sha256": sha(binary.read_bytes()), "host_checks": checks,
        "passed": len(checks), "failed": 0,
        "limits": ["Selected production C bodies with host far-pointer adaptation", "No native DOS execution", "No Windows 98 boot or modern application claim", "1230 and 1231/DL=0 remain unsupported"],
    }
    (out / "host-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": len(checks), "failed": 0, "receipt": str(out / "host-result.json")}))


if __name__ == "__main__":
    main()
