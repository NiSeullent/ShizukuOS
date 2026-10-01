#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic real-SRW-source release/reacquire-before-park regression.

Only host simulation of the primitive parking boundary; it is not native or
guest execution evidence. Uses the actual production SRW section unchanged.
"""
from __future__ import annotations
import datetime
import hashlib
import json
import pathlib
import resource
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
SOURCE = ROOT / "shizukudos/win64/ntdll/sync.c"
PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
typedef uintptr_t ULONG_PTR;
typedef void VOID;
typedef int BOOLEAN;
typedef struct { void *Ptr; } RTL_SRWLOCK;
#define SHZ_EXPORT
#define NTAPI
static int park(const void *, int (*)(const void *), const void *, const void *);
static void unpark(const void *, int);
static int queued, woke, park_calls, force_reacquire, bucket_locked;
static RTL_SRWLOCK *target;
'''
SUFFIX = r'''
static void unpark(const void *key, int maximum)
{
    assert(key == target && maximum == 64);
    assert(!bucket_locked);
    if (queued) { queued = 0; ++woke; }
}
static int park(const void *key, int (*validate)(const void *), const void *ctx, const void *timeout)
{
    assert(key == target && ctx == target && !timeout);
    assert(++park_calls == 1);
    if (force_reacquire) {
        /* Real production release sees WAIT and wakes nobody: the waiter
         * has not acquired the parking bucket or linked its stack node. */
        RtlReleaseSRWLockExclusive(target);
        assert(!queued && !woke);
        assert(RtlTryAcquireSRWLockExclusive(target));
        assert((uintptr_t)target->Ptr == SRW_EXCL);
    }
    bucket_locked = 1;
    if (!validate(ctx)) { bucket_locked = 0; return 1; }
    /* Production callback must mark the CURRENT owner while under this
     * bucket lock. The old one-line predicate leaves word=1 and fails here. */
    assert((uintptr_t)target->Ptr == (SRW_EXCL | SRW_WAIT));
    queued = 1;
    bucket_locked = 0;
    RtlReleaseSRWLockExclusive(target);
    assert(!queued && woke == 1);
    return 0;
}
static void scenario(int shared, int reacquire)
{
    RTL_SRWLOCK lock;
    target = &lock; queued = woke = park_calls = bucket_locked = 0;
    force_reacquire = reacquire;
    RtlInitializeSRWLock(&lock);
    assert(RtlTryAcquireSRWLockExclusive(&lock));
    lock.Ptr = (void *)(uintptr_t)(SRW_EXCL | SRW_WAIT);
    if (shared) {
        RtlAcquireSRWLockShared(&lock);
        assert((uintptr_t)lock.Ptr == SRW_ONE);
        RtlReleaseSRWLockShared(&lock);
    } else {
        RtlAcquireSRWLockExclusive(&lock);
        assert((uintptr_t)lock.Ptr == SRW_EXCL);
        RtlReleaseSRWLockExclusive(&lock);
    }
    assert(!lock.Ptr && park_calls == 1 && woke == 1);
}
int main(void)
{
    RTL_SRWLOCK lock;
    scenario(0, 1); scenario(1, 1);
    target = &lock;
    RtlInitializeSRWLock(&lock);
    assert(!validate_srw_excl(&lock) && !validate_srw_busy(&lock));
    lock.Ptr = (void *)(uintptr_t)SRW_WAIT;
    assert(!validate_srw_excl(&lock) && !validate_srw_busy(&lock));
    lock.Ptr = (void *)(uintptr_t)SRW_ONE;
    assert(!validate_srw_excl(&lock));
    assert(validate_srw_busy(&lock) && (uintptr_t)lock.Ptr == (SRW_ONE | SRW_WAIT));
    lock.Ptr = (void *)(uintptr_t)SRW_EXCL;
    assert(validate_srw_excl(&lock) && (uintptr_t)lock.Ptr == (SRW_EXCL | SRW_WAIT));
    scenario(0, 0); scenario(1, 0);
    puts("PASS: real SRW predicates + exclusive/shared release/reacquire-before-park, wake and completion");
    return 0;
}
'''


def main():
    source = SOURCE.read_text()
    start = source.index("#define SRW_EXCL")
    end = source.index("/* ---------------------------------------------------------------- condition variables */", start)
    section = source[start:end]
    cc = shutil.which("cc") or shutil.which("gcc")
    if not cc:
        raise SystemExit("BLOCKED: host C compiler absent; no install attempted")
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S")
    out = ROOT / "build/srw-race-validation" / stamp
    out.mkdir(parents=True)
    fixture = out / "actual-srw-race.c"
    fixture.write_text(PREFIX + section + SUFFIX)
    command = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-strict-aliasing", str(fixture), "-o", str(out / "actual-srw-race")]
    subprocess.run(command, check=True, timeout=30)
    result = subprocess.run([str(out / "actual-srw-race")], capture_output=True, text=True, timeout=10)
    # Demonstrate the exact historical bug fails under the same schedule.
    old = section[:section.index("/* park()")] + '''static int validate_srw_excl(const void *p) { return (*(const volatile ULONG_PTR *)p & SRW_EXCL) != 0; }
static int validate_srw_busy(const void *p) { return (*(const volatile ULONG_PTR *)p & ~(ULONG_PTR)SRW_WAIT) != 0; }
''' + section[section.index("SHZ_EXPORT VOID NTAPI RtlInitializeSRWLock"):]
    negative = out / "historical-srw-race.c"
    negative.write_text(PREFIX + old + SUFFIX)
    subprocess.run([*command[:-3], str(negative), "-o", str(out / "historical-srw-race")], check=True, timeout=30)
    failed = subprocess.run([str(out / "historical-srw-race")], capture_output=True, text=True, timeout=10,
                            preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
    receipt = {"status": "PASS" if result.returncode == 0 and failed.returncode != 0 else "FAIL",
               "scope": "host boundary fixture using unchanged actual SRW source; guest execution pending",
               "source_sha256": hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
               "actual_section_sha256": hashlib.sha256(section.encode()).hexdigest(),
               "command": command, "actual_exit": result.returncode, "actual_stdout": result.stdout,
               "historical_exit": failed.returncode, "historical_stderr": failed.stderr,
               "fixture_sha256": hashlib.sha256(fixture.read_bytes()).hexdigest()}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2)); print("EVIDENCE", out)
    raise SystemExit(0 if receipt["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
