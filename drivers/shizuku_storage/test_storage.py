#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Compile the actual copied SeaBIOS allocation/bounce functions against bounded I/O controls."""
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def function(text, marker):
    start = text.index(marker)
    pos = text.index("{", start) + 1
    depth = 1
    while depth:
        depth += (text[pos] == "{") - (text[pos] == "}")
        pos += 1
    return text[start:pos]


HARNESS = r'''
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
struct drive_s { u16 blksize; };
struct disk_op_s { void *buf_fl; struct drive_s *drive_fl; u8 command; u16 count; u64 lba; };
#define CDROM_SECTOR_SIZE 2048
#define CMD_READ 2
#define CMD_WRITE 3
#define DISK_RET_EPARAM 1
#define ASSERT16() ((void)0)
#define GET_GLOBAL(x) (x)
#define GET_FLATPTR(x) (x)
#define GET_SEG(x) 0
#define MAKE_FLATPTR(seg, p) (p)
#define call32(fn, p, err) io_call(p)
static u8 *bounce_buf_fl;
static u32 bounce_buf_size;
static _Alignas(16) u8 area[16384 + 32], user[65536 + 32], media[65536 + 32];
static u64 base_lba;
static unsigned checks, cases, calls, chunks[200], copied_bytes;
static u64 lbas[200];
static int fail_at, completion, io_rc, fail_large, fail_small;
static unsigned alloc_calls, alloc_sizes[3], warned;
static void require(int condition, const char *label) {
    checks++;
    if (!condition) { fprintf(stderr, "FAIL %s check=%u\n", label, checks); exit(1); }
}
static void *malloc_low(u32 size) {
    require(alloc_calls < 3, "allocation call bounded"); alloc_sizes[alloc_calls++] = size;
    if ((size == 16384 && fail_large) || (size == 2048 && fail_small)) return NULL;
    require(size == 16384 || size == 2048, "actual allocation request"); return area + 16;
}
static void warn_noalloc(void) { warned++; }
static void bios_dprintf(int level, const char *format, ...) { (void)level; (void)format; }
#define dprintf bios_dprintf
static void memcpy_fl(void *dst, const void *src, u32 bytes) {
    uintptr_t d = (uintptr_t)dst, s = (uintptr_t)src;
    uintptr_t a = (uintptr_t)(area + 16), u = (uintptr_t)(user + 16);
    require(bytes <= bounce_buf_size, "copy within allocated capacity");
    require((d >= a && d + bytes <= a + bounce_buf_size && s >= u && s + bytes <= u + 65536)
         || (s >= a && s + bytes <= a + bounce_buf_size && d >= u && d + bytes <= u + 65536), "segment copy uses admitted buffers");
    copied_bytes += bytes; memcpy(dst, src, bytes);
}
static int io_call(struct disk_op_s *op) {
    require(calls < 200, "dispatch bound");
    require(op->buf_fl == bounce_buf_fl && op->count, "DMA only reserved bounce");
    u32 requested = op->count, bytes = requested * op->drive_fl->blksize;
    require(bytes <= bounce_buf_size, "DMA actual capacity bound");
    require(op->lba >= base_lba && op->lba - base_lba <= 128, "LBA progression bounded");
    u32 offset = (u32)(op->lba - base_lba) * op->drive_fl->blksize;
    require(offset + bytes <= 65536, "media transfer range");
    chunks[calls] = requested; lbas[calls] = op->lba; calls++;
    int special = fail_at > 0 && (int)calls == fail_at;
    u32 written = special && completion >= 0 && completion < (int)requested
                ? (u32)completion : requested;
    if (op->command == CMD_READ) memcpy(op->buf_fl, media + 16 + offset, written * op->drive_fl->blksize);
    else memcpy(media + 16 + offset, op->buf_fl, written * op->drive_fl->blksize);
    if (special && completion >= 0) op->count = (u16)completion;
    return special ? io_rc : 0;
}
/* ACTUAL_FUNCTIONS */
static void reset(unsigned capacity) {
    memset(area, 0x5c, sizeof area); memset(user, 0xa5, sizeof user); memset(media, 0x33, sizeof media);
    for (unsigned i = 0; i < 65536; i++) media[16+i] = (u8)((i * 53 + (i >> 8)) & 255);
    bounce_buf_fl = area + 16; bounce_buf_size = capacity;
    base_lba = UINT64_C(0x100000063); calls = copied_bytes = alloc_calls = warned = 0;
    fail_at = fail_large = fail_small = io_rc = 0; completion = -1;
}
static void canaries(void) {
    for (unsigned i=0;i<16;i++) {
        require(area[i] == 0x5c && area[16384+16+i] == 0x5c, "bounce canary unchanged");
        require(user[i] == 0xa5 && user[65536+16+i] == 0xa5, "caller canary unchanged");
    }
}
static void transfer(unsigned count, unsigned bs, unsigned cap, int write) {
    cases++;
    reset(cap); struct drive_s drive = {(u16)bs};
    struct disk_op_s op = {user+16, &drive, write ? CMD_WRITE : CMD_READ, (u16)count, base_lba};
    if(write) for(unsigned i=0;i<count*bs;i++) user[16+i] = (u8)(i*17+7);
    int rc = process_op_32_v86bounce(&op);
    require(rc == 0 && op.count == count, "full transfer succeeds");
    require(op.buf_fl == user+16 && op.lba == base_lba, "original pointer and 64-bit LBA restored");
    unsigned maximum=cap/bs, expected=(count+maximum-1)/maximum;
    require(calls == expected, "chunk count expected");
    unsigned done=0;
    for(unsigned i=0;i<calls;i++) {
        unsigned n=count-done; if(n>maximum)n=maximum;
        require(chunks[i] == n && lbas[i] == base_lba+done, "chunk count and LBA exact"); done += n;
    }
    require(!memcmp(user+16, media+16, count*bs), "all transferred bytes exact");
    if(!write) for(unsigned i=count*bs;i<65536;i++) require(user[16+i] == 0xa5, "read leaves tail untouched");
    canaries();
}
static void fault(int rc, int reported, unsigned fail_call, unsigned expected_done) {
    cases++;
    reset(16384); struct drive_s drive={512};
    struct disk_op_s op={user+16,&drive,CMD_READ,64,base_lba};
    fail_at=(int)fail_call; completion=reported; io_rc=rc;
    int got=process_op_32_v86bounce(&op);
    require(got != 0 && op.count == expected_done, "error reports only certified completed sectors");
    require(op.buf_fl == user+16 && op.lba == base_lba, "error restores original state");
    require(!memcmp(user+16,media+16,expected_done*512), "partial read bytes correspond to count");
    for(unsigned i=expected_done*512;i<65536;i++) require(user[16+i] == 0xa5, "error leaves incomplete caller bytes unchanged");
    require(calls == fail_call, "no dispatch after first error"); canaries();
}
int main(void) {
    unsigned sizes[]={1,4,5,31,32,33,64,128};
    for(unsigned i=0;i<sizeof sizes/sizeof sizes[0];i++) {
        transfer(sizes[i],512,16384,0); transfer(sizes[i],512,16384,1);
        transfer(sizes[i],512,2048,0); transfer(sizes[i],512,2048,1);
    }
    unsigned cd[]={1,4,5,8,9,31,32};
    for(unsigned i=0;i<sizeof cd/sizeof cd[0];i++) { transfer(cd[i],2048,16384,0); transfer(cd[i],2048,2048,0); }
    fault(9,-1,1,0); fault(9,-1,2,32); // unchanged stale count must not claim completion
    fault(9,0,1,0); fault(9,3,1,3); fault(9,3,2,35);
    fault(9,33,1,0); fault(9,33,2,32); // oversized count rejected before copy
    fault(0,3,1,3); // short success rejected, explicit smaller count retained
    cases++; reset(16384); struct drive_s drive={512};
    struct disk_op_s old={user+16,&drive,CMD_READ,64,base_lba};
    fail_at=1; io_rc=9; completion=-1;
    require(baseline_process_op_32_v86bounce(&old)==9 && old.count==4, "actual baseline reproduces inflated error count");
    require(user[16] == 0xa5, "baseline inflated count has no corresponding caller copy");
    cases++; reset(0); bounce_buf_fl=NULL;
    require(create_bounce_buf()==0 && bounce_buf_size==16384 && alloc_calls==1 && alloc_sizes[0]==16384, "large allocation and actual capacity");
    cases++; require(create_bounce_buf()==0 && alloc_calls==1, "existing buffer allocation retained");
    cases++; reset(0); bounce_buf_fl=NULL; fail_large=1;
    require(create_bounce_buf()==0 && bounce_buf_size==2048 && alloc_calls==2 && alloc_sizes[1]==2048, "fallback exact two KiB capacity");
    cases++; reset(0); bounce_buf_fl=NULL; fail_large=fail_small=1;
    require(create_bounce_buf()==-1 && !bounce_buf_fl && !bounce_buf_size && warned==1, "both allocation failures close DMA path");
    cases++; struct disk_op_s missing={user+16,&drive,CMD_READ,1,base_lba};
    require(process_op_32_v86bounce(&missing)==DISK_RET_EPARAM && missing.count==0 && calls==0, "missing buffer cannot fall through to caller DMA");
    unsigned invalid_caps[]={0,511,2049,32768};
    for(unsigned i=0;i<sizeof invalid_caps/sizeof invalid_caps[0];i++) {
        cases++;
        reset(invalid_caps[i]); struct disk_op_s bad={user+16,&drive,CMD_READ,1,base_lba};
        require(process_op_32_v86bounce(&bad)==1 && bad.count==0 && calls==0, "invalid capacity refuses before I/O");
    }
    for(unsigned bs=0;bs<=32768;bs+=32768) {
        cases++;
        reset(16384); struct drive_s invalid={(u16)bs}; struct disk_op_s bad={user+16,&invalid,CMD_READ,1,base_lba};
        require(process_op_32_v86bounce(&bad)==1 && bad.count==0 && calls==0, "zero or oversize sector refuses");
    }
    cases++; reset(16384); struct disk_op_s oversized={user+16,&drive,CMD_READ,129,base_lba};
    require(process_op_32_v86bounce(&oversized)==1 && oversized.count==0 && calls==0, "64 KiB request bound preserved");
    cases++; reset(0); bounce_buf_fl=NULL; struct disk_op_s empty={user+16,&drive,CMD_READ,0,base_lba};
    require(process_op_32_v86bounce(&empty)==0 && calls==0 && empty.lba==base_lba, "empty request does no DMA");
    printf("STORAGE_HOST_PASS checks=%u cases=%u baseline_failed_count=4 candidate_failed_count=0\n",checks,cases);
    return 0;
}
'''


def run_tests(source, baseline, out):
    out.mkdir()
    text = source.read_text()
    old = baseline.read_text()
    allocation = function(text, "int create_bounce_buf(void)")
    transfer = function(text, "static int\nprocess_op_32_v86bounce(")
    previous = function(old, "static int\nprocess_op_32_v86bounce(").replace(
        "process_op_32_v86bounce(", "baseline_process_op_32_v86bounce(", 1)
    harness = out / "actual-functions-harness.c"
    harness.write_text(HARNESS.replace("/* ACTUAL_FUNCTIONS */", allocation + "\n" + transfer + "\n" + previous))
    result = {"schema": 1, "host_only": True, "native_execution": False,
              "source_sha256": sha(source), "baseline_source_sha256": sha(baseline),
              "actual_function_text_sha256": hashlib.sha256((allocation + transfer).encode()).hexdigest(),
              "harness_sha256": sha(harness), "runs": []}
    env = dict(os.environ, LC_ALL="C", ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    for mode, extra in [("normal", []), ("sanitized", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        exe = out / mode
        compiler = "clang" if mode == "sanitized" else "gcc"
        command = [compiler, "-std=gnu11", "-O1", "-Wall", "-Wextra", "-Werror", *extra, str(harness), "-o", str(exe)]
        compilation = subprocess.run(command, capture_output=True, text=True, timeout=120, env=env)
        log = out / (mode + "-compile.log")
        log.write_text(compilation.stdout + compilation.stderr)
        if compilation.returncode:
            raise RuntimeError(f"Host control compile failed: {log}")
        p = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60, env=env)
        runlog = out / (mode + "-run.log")
        runlog.write_text(p.stdout + p.stderr)
        if p.returncode or not p.stdout.startswith("STORAGE_HOST_PASS "):
            raise RuntimeError(f"Host controls failed: {runlog}")
        result["runs"].append({"mode": mode, "compile_argv": command, "compile_exit": compilation.returncode,
                               "exit": p.returncode, "report": p.stdout.strip(),
                               "compile_log_sha256": sha(log), "run_log_sha256": sha(runlog),
                               "binary_sha256": sha(exe)})
    (out / "host-result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
