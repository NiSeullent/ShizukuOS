#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Execute actual private SeaBIOS functions; no VM or guest disk access."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

PARENT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


EXTRA = r'''
static void parity(unsigned cap, unsigned count, int write, int error, int reported, unsigned failcall) {
    cases++; reset(cap); struct drive_s drive={512};
    struct disk_op_s op={user+16,&drive,write ? CMD_WRITE : CMD_READ,(u16)count,base_lba};
    fail_at=failcall; completion=reported; io_rc=error;
    int got=process_op_32_v86bounce(&op);
    u8 saved_user[65536], saved_media[65536];
    memcpy(saved_user,user+16,65536); memcpy(saved_media,media+16,65536);
    unsigned saved_calls=calls, saved_copied=copied_bytes, saved_count=op.count;
    require(op.buf_fl==user+16 && op.lba==base_lba,"instrumented state restored");
    require(!(shz_storage_stats.sequence&1),"instrumented request committed");
    reset(cap); observe_functions=0;
    op=(struct disk_op_s){user+16,&drive,write ? CMD_WRITE : CMD_READ,(u16)count,base_lba};
    fail_at=failcall; completion=reported; io_rc=error;
    int expected=control_process_op_32_v86bounce(&op);
    require(got==expected && saved_count==op.count && saved_calls==calls && saved_copied==copied_bytes,
            "counter instrumentation preserves return/count/dispatch/copy");
    require(!memcmp(saved_user,user+16,65536) && !memcmp(saved_media,media+16,65536),
            "counter instrumentation preserves every caller/media byte");
    require(op.buf_fl==user+16 && op.lba==base_lba,"control state restored");
    require(shz_storage_stats.sequence==0 && shz_storage_stats.requests==0,"control has no counters");
    canaries();
}
static int snapshot_valid(u32 before, const struct shz_storage_statistics *s, u32 after) {
    return before==after && !(before&1) && s->sequence==before
        && !memcmp(s->magic,"SHZSTAT1",8) && s->major==1 && s->minor==0 && s->bytes==224
        && !(s->flags&2);
}
static void additional_controls(void) {
    cases++; require(sizeof shz_storage_stats==224,"actual struct size224");
    require(offsetof(struct shz_storage_statistics,sequence)==16
        && offsetof(struct shz_storage_statistics,requested_blocks)==56
        && offsetof(struct shz_storage_statistics,completed_bytes)==88
        && offsetof(struct shz_storage_statistics,last_lba)==152
        && offsetof(struct shz_storage_statistics,count_histogram)==160
        && offsetof(struct shz_storage_statistics,completed_write_bytes)==216,"actual ABI field offsets");
    unsigned sizes[]={1,4,5,31,32,33,128};
    for(unsigned k=0;k<2;k++) for(unsigned i=0;i<7;i++) for(int w=0;w<2;w++)
        parity(k?16384:2048,sizes[i],w,0,-1,0);
    for(unsigned k=0;k<2;k++) for(int w=0;w<2;w++) {
        parity(k?16384:2048,64,w,9,-1,1);
        parity(k?16384:2048,64,w,9,1,2);
        parity(k?16384:2048,64,w,9,40,1);
        parity(k?16384:2048,64,w,0,1,1);
    }
    cases++; reset(16384); struct disk_op_s zero={user+16,NULL,CMD_READ,0,base_lba};
    require(process_op_32_v86bounce(&zero)==0 && calls==0 && zero.drive_fl==NULL,"zero count retains no-drive-dereference early return");
    require(shz_storage_stats.requests==1 && shz_storage_stats.zero_count_requests==1
        && shz_storage_stats.last_blocksize==0 && shz_storage_stats.sequence==2,"zero request records unknown blocksize without I/O");
    cases++; reset(16384); struct drive_s drive={512};
    struct disk_op_s one={user+16,&drive,CMD_READ,1,base_lba};
    shz_storage_stats.requests=UINT32_MAX; shz_storage_stats.read_requests=UINT32_MAX;
    shz_storage_stats.chunks=UINT32_MAX; shz_storage_stats.completed_chunks=UINT32_MAX;
    shz_storage_stats.count_histogram[1]=UINT32_MAX;
    shz_storage_stats.requested_blocks=UINT64_MAX; shz_storage_stats.completed_blocks=UINT64_MAX;
    shz_storage_stats.requested_bytes=UINT64_MAX-511; shz_storage_stats.completed_bytes=UINT64_MAX-511;
    shz_storage_stats.requested_read_bytes=UINT64_MAX; shz_storage_stats.completed_read_bytes=UINT64_MAX;
    require(process_op_32_v86bounce(&one)==0 && one.count==1,"saturation never changes transfer");
    require(shz_storage_stats.flags==1 && shz_storage_stats.sequence==2,"counter saturation marks committed lower bound");
    require(shz_storage_stats.requests==UINT32_MAX && shz_storage_stats.read_requests==UINT32_MAX
        && shz_storage_stats.chunks==UINT32_MAX && shz_storage_stats.completed_chunks==UINT32_MAX
        && shz_storage_stats.count_histogram[1]==UINT32_MAX,"all exercised32-bit counters saturate");
    require(shz_storage_stats.requested_blocks==UINT64_MAX && shz_storage_stats.completed_blocks==UINT64_MAX
        && shz_storage_stats.requested_bytes==UINT64_MAX && shz_storage_stats.completed_bytes==UINT64_MAX
        && shz_storage_stats.requested_read_bytes==UINT64_MAX && shz_storage_stats.completed_read_bytes==UINT64_MAX,
        "all exercised64-bit counters saturate");
    cases++; reset(2048); shz_storage_stats.sequence=UINT32_MAX-1;
    one.count=1; require(process_op_32_v86bounce(&one)==0 && shz_storage_stats.sequence==0,"sequence wraps separately from saturating counters");
    struct shz_storage_statistics snap=shz_storage_stats;
    require(snapshot_valid(0,&snap,0),"equal even snapshot accepted");
    require(!snapshot_valid(1,&snap,1) && !snapshot_valid(0,&snap,2),"odd or changed snapshot rejected");
    snap.sequence=2; require(!snapshot_valid(0,&snap,0),"body sequence must match outer reads");
    snap=shz_storage_stats; snap.magic[0]='X'; require(!snapshot_valid(0,&snap,0),"wrong magic rejected");
    snap=shz_storage_stats; snap.bytes=223; require(!snapshot_valid(0,&snap,0),"wrong ABI size rejected");
    cases++; reset(2048); shz_storage_stats.sequence=1; observe_functions=0;
    one.count=1; require(process_op_32_v86bounce(&one)==0 && one.count==1,"unexpected nested observation does not alter I/O");
    require(shz_storage_stats.sequence==1 && shz_storage_stats.flags==2 && shz_storage_stats.requests==0,
            "unexpected reentry invalidates comparison without committing another writer");
    snap=shz_storage_stats; snap.sequence=0;
    require(!snapshot_valid(0,&snap,0),"reentry record rejected even after an outer commit");
    cases++; reset(2048); drive.blksize=0; one.count=1;
    require(process_op_32_v86bounce(&one)==DISK_RET_EPARAM && one.count==0 && calls==0,"zero blocksize still rejected before dispatch");
    require(shz_storage_stats.error_requests==1 && shz_storage_stats.rejected_requests==1
        && shz_storage_stats.requested_blocks==1 && !shz_storage_stats.requested_bytes
        && shz_storage_stats.sequence==2,"invalid zero blocksize has exact committed rejection counters");
}
'''


def run_tests(tree, control, baseline, out):
    out.mkdir()
    spec = importlib.util.spec_from_file_location("held_storage_controls", PARENT / "test_storage.py")
    old = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(old)
    source = tree / "src/block.c"
    text = source.read_text()
    allocation = old.function(text, "int create_bounce_buf(void)")
    transfer = old.function(text, "static int\nprocess_op_32_v86bounce(")
    uninstrumented = old.function(control.read_text(), "static int\nprocess_op_32_v86bounce(").replace(
        "process_op_32_v86bounce(", "control_process_op_32_v86bounce(", 1)
    previous = old.function(baseline.read_text(), "static int\nprocess_op_32_v86bounce(").replace(
        "process_op_32_v86bounce(", "baseline_process_op_32_v86bounce(", 1)
    harness = old.HARNESS.replace("#include <stdarg.h>", "#include <stdarg.h>\n#include <stddef.h>")
    harness = harness.replace("static u32 bounce_buf_size;", r'''static u32 bounce_buf_size;
#define VARFSEG
#define __aligned(n) __attribute__((aligned(n)))
#define GLOBAL_SEGREG 0
#define get_global_offset() 0
#define SET_VAR(seg, var, val) do { (var)=(val); } while(0)
#include "shzstorage_statistics.h"
static struct shz_storage_statistics pristine;
static int observe_functions;
''')
    harness = harness.replace("    require(calls < 200,", "    if(observe_functions) {\n        require(shz_storage_stats.sequence&1, \"reader rejects active odd transaction\");\n        require(shz_storage_stats.last_chunks==calls+1, \"dispatch counter precedes each actual call\");\n    }\n    require(calls < 200,")
    harness = harness.replace("/* ACTUAL_FUNCTIONS */", allocation + "\n" + transfer + "\n" + uninstrumented + "\n" + previous)
    harness = harness.replace("static void reset(unsigned capacity) {", "static void reset(unsigned capacity) {\n    shz_storage_stats=pristine; observe_functions=1;")
    harness = harness.replace("    canaries();\n}\nstatic void fault", r'''
    require(shz_storage_stats.sequence==2 && shz_storage_stats.requests==1,"one request commits exactly once");
    require(shz_storage_stats.last_requested_blocks==count && shz_storage_stats.last_blocksize==bs
        && shz_storage_stats.last_lba==base_lba && shz_storage_stats.actual_capacity==cap,"exact original request metadata");
    require(shz_storage_stats.requested_blocks==count && shz_storage_stats.completed_blocks==count
        && shz_storage_stats.requested_bytes==count*bs && shz_storage_stats.completed_bytes==count*bs,
        "request/certified completion counters exact");
    require(shz_storage_stats.chunks==expected && shz_storage_stats.completed_chunks==expected
        && !shz_storage_stats.error_chunks && !shz_storage_stats.partial_chunks,"full chunks exact");
    require(shz_storage_stats.read_requests==(u32)!write && shz_storage_stats.write_requests==(u32)write,
        "READ/WRITE request counters exact");
    require(shz_storage_stats.requested_read_bytes==(write?0:count*bs)
        && shz_storage_stats.requested_write_bytes==(write?count*bs:0)
        && shz_storage_stats.completed_read_bytes==(write?0:count*bs)
        && shz_storage_stats.completed_write_bytes==(write?count*bs:0),"direction-specific byte counters exact");
    canaries();
}
static void fault''')
    harness = harness.replace('    require(calls == fail_call, "no dispatch after first error"); canaries();', r'''
    require(calls == fail_call, "no dispatch after first error");
    require(shz_storage_stats.sequence==2 && shz_storage_stats.chunks==fail_call
        && shz_storage_stats.error_requests==1 && shz_storage_stats.error_chunks==1,"error transaction and attempts exact");
    require(shz_storage_stats.completed_blocks==expected_done && shz_storage_stats.completed_bytes==expected_done*512
        && shz_storage_stats.last_completed_blocks==expected_done,"error completion counters certify only retained bytes");
    require(shz_storage_stats.partial_requests==(u32)(expected_done>0 && expected_done<64),"partial request counter exact");
    require(shz_storage_stats.oversized_completions==(u32)(reported>32),"invalid oversized count recorded once");
    canaries();''')
    harness = harness.replace("int main(void) {", EXTRA + "\nint main(void) {\n    pristine=shz_storage_stats;")
    harness = harness.replace("    require(baseline_process_op_32_v86bounce(&old)==9", "    observe_functions=0;\n    require(baseline_process_op_32_v86bounce(&old)==9")
    harness = harness.replace("bounce_buf_size==16384 && alloc_calls==1 && alloc_sizes[0]==16384",
                              "bounce_buf_size==SHZ_STORAGE_PROFILE_CAPACITY && alloc_calls==1 && alloc_sizes[0]==SHZ_STORAGE_PROFILE_CAPACITY")
    harness = harness.replace("bounce_buf_size==2048 && alloc_calls==2 && alloc_sizes[1]==2048",
                              "bounce_buf_size==2048 && alloc_calls==(SHZ_STORAGE_PROFILE_CAPACITY==16384?2u:1u) && alloc_sizes[alloc_calls-1]==2048")
    harness = harness.replace('    printf("STORAGE_HOST_PASS', '    additional_controls();\n    printf("STATISTICS_HOST_PASS')
    hpath = out / "actual-functions-harness.c"
    hpath.write_text(harness)
    result = {"schema": 1, "host_only": True, "native_execution": False,
              "source_sha256": sha(source), "control_source_sha256": sha(control),
              "baseline_source_sha256": sha(baseline), "header_sha256": sha(tree / "src/shzstorage_statistics.h"),
              "actual_function_text_sha256": hashlib.sha256((allocation + transfer).encode()).hexdigest(),
              "harness_sha256": sha(hpath), "runs": []}
    env = dict(os.environ, LC_ALL="C", ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    for mode, extra in [("normal", []), ("sanitized", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        exe = out / mode
        command = ["clang" if mode == "sanitized" else "gcc", "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror",
                   *extra, "-iquote", str(tree / "src"), str(hpath), "-o", str(exe)]
        compilation = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env)
        clog = out / (mode + "-compile.log")
        clog.write_text(compilation.stdout + compilation.stderr)
        if compilation.returncode:
            raise RuntimeError(f"Actual-function controls failed compile: {clog}")
        p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60, env=env)
        rlog = out / (mode + "-run.log")
        rlog.write_text(p.stdout + p.stderr)
        if p.returncode or not p.stdout.startswith("STATISTICS_HOST_PASS "):
            raise RuntimeError(f"Actual-function controls failed: {rlog}")
        result["runs"].append({"mode": mode, "compile_argv": command, "compile_exit": 0, "exit": 0,
                               "report": p.stdout.strip(), "compile_log_sha256": sha(clog),
                               "run_log_sha256": sha(rlog), "binary_sha256": sha(exe)})
    (out / "host-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
