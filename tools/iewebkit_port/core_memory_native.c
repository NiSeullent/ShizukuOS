/* Native probe of the shared actual WTF Win9x memory backend.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * This does not execute JavaScript, render documents or certify the engine.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "src/core_MemoryWin9x.h"

static int valid_digest(const char* value)
{
    size_t i;
    if (strlen(value) != 64)
        return 0;
    for (i = 0; i < 64; ++i) {
        if (!((value[i] >= '0' && value[i] <= '9') || (value[i] >= 'a' && value[i] <= 'f')))
            return 0;
    }
    return 1;
}

static int read_provenance(const char* path, char hashes[4][65])
{
    FILE* file = fopen(path, "rb");
    char line[68];
    unsigned i;
    int valid = file != NULL;
    if (!file)
        return 0;
    for (i = 0; i < 4 && valid; ++i) {
        valid = fgets(line, sizeof(line), file) != NULL;
        if (!valid)
            break;
        line[strcspn(line, "\r\n")] = 0;
        valid = valid_digest(line);
        if (valid)
            memcpy(hashes[i], line, 65);
    }
    valid = valid && fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return valid;
}

int main(int argc, char** argv)
{
    const char* path = argc > 1 ? argv[1] : "C:\\GOPLAB\\MEM9X.LOG";
    FILE* log = fopen(path, "wb");
    DWORD version = GetVersion();
    IEWKWin9xMemoryStatus status, policy;
    size_t before = 0, during = 0, after = 0;
    const size_t requested = 2UL * 1024 * 1024;
    SYSTEM_INFO system = { 0 };
    volatile unsigned char* block = NULL;
    size_t offset;
    int exitCode = 0, statusValid, beforeValid = 0, duringValid = 0, afterValid = 0;
    int freed = 0, policyValid = 0;
    DWORD allocationError = 0, freeError = 0;
    char hashes[4][65];
    if (!log)
        return 2;
    fprintf(log, "scope=Actual-WTF-shared-Win9x-memory-backend\r\n");
    fprintf(log, "accounting=committed-private-virtual-bytes-not-resident-working-set\r\n");
    if (argc != 4 || !strlen(argv[2]) || strlen(argv[2]) > 80
        || strspn(argv[2], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(argv[2])
        || !read_provenance(argv[3], hashes)) {
        fprintf(log, "exit=10\r\n");
        fclose(log);
        return 10;
    }
    fprintf(log, "nonce=%s\r\nexpected.source.sha256=%s\r\nexpected.header.sha256=%s\r\nexpected.binary.sha256=%s\r\nexpected.receipt.sha256=%s\r\n",
        argv[2], hashes[0], hashes[1], hashes[2], hashes[3]);
    fprintf(log, "os.major=%lu\r\nos.minor=%lu\r\nos.win9x=%u\r\n",
        version & 255, (version >> 8) & 255, (unsigned)(version >> 31));
    if (!(version & 0x80000000UL) || (version & 255) != 4 || ((version >> 8) & 255) != 10) {
        fprintf(log, "exit=3\r\n");
        fclose(log);
        return 3;
    }
    statusValid = iewkWin9xQueryMemoryStatus(&status);
    fprintf(log, "status.valid=%u\r\n", (unsigned)statusValid);
    if (!statusValid) {
        exitCode = 4;
        goto finish;
    }
    fprintf(log, "physical.total=%lu\r\nphysical.available=%lu\r\nvirtual.total=%lu\r\nvirtual.available=%lu\r\nmemory.load=%lu\r\n",
        (unsigned long)status.totalPhysical, (unsigned long)status.availablePhysical,
        (unsigned long)status.totalVirtual, (unsigned long)status.availableVirtual, status.memoryLoad);
    fprintf(log, "pressure.current=%u\r\nwarning.divisor=%u\r\ncritical.divisor=%u\r\n",
        (unsigned)iewkWin9xMemoryPressureLevel(&status), IEWK_MEMORY_WARNING_DIVISOR, IEWK_MEMORY_CRITICAL_DIVISOR);
    /* Exercise the exact shared policy without forcing the guest into a
     * dangerous low-memory state. Allocation below tests real OS accounting.
     */
    policy = status;
    policy.availablePhysical = policy.totalPhysical;
    policy.availableVirtual = policy.totalVirtual;
    policyValid = iewkWin9xMemoryPressureLevel(&policy) == IEWK_MEMORY_NORMAL;
    policy.availablePhysical = policy.totalPhysical / IEWK_MEMORY_WARNING_DIVISOR;
    policyValid = policyValid && iewkWin9xMemoryPressureLevel(&policy) == IEWK_MEMORY_WARNING;
    policy.availablePhysical = policy.totalPhysical / IEWK_MEMORY_CRITICAL_DIVISOR;
    policyValid = policyValid && iewkWin9xMemoryPressureLevel(&policy) == IEWK_MEMORY_CRITICAL;
    policy.availablePhysical = policy.totalPhysical;
    policy.availableVirtual = policy.totalVirtual / IEWK_MEMORY_WARNING_DIVISOR;
    policyValid = policyValid && iewkWin9xMemoryPressureLevel(&policy) == IEWK_MEMORY_WARNING;
    policy.availableVirtual = policy.totalVirtual / IEWK_MEMORY_CRITICAL_DIVISOR;
    policyValid = policyValid && iewkWin9xMemoryPressureLevel(&policy) == IEWK_MEMORY_CRITICAL;
    fprintf(log, "pressure.policy.boundaries=%u\r\n", (unsigned)policyValid);
    if (!policyValid) {
        exitCode = 5;
        goto finish;
    }
    GetSystemInfo(&system);
    fprintf(log, "scan.minimum=%lu\r\nscan.os.maximum=%lu\r\nscan.exclusive-limit=%lu\r\n",
        (unsigned long)(uintptr_t)system.lpMinimumApplicationAddress,
        (unsigned long)(uintptr_t)system.lpMaximumApplicationAddress,
        (unsigned long)(((uint64_t)(uintptr_t)system.lpMaximumApplicationAddress + 1 < IEWK_MEMORY_PRIVATE_ADDRESS_LIMIT)
            ? (uint64_t)(uintptr_t)system.lpMaximumApplicationAddress + 1 : IEWK_MEMORY_PRIVATE_ADDRESS_LIMIT));
    beforeValid = iewkWin9xCommittedPrivateBytes(&before);
    if (!beforeValid || !system.dwPageSize || requested % system.dwPageSize) {
        exitCode = 6;
        goto finish;
    }
    /* Avoid stdio calls between these measurements: they can grow CRT heaps
     * and obscure the probe's own committed-region allocation/release delta.
     */
    SetLastError(0);
    block = (volatile unsigned char*)VirtualAlloc(NULL, requested, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    allocationError = GetLastError();
    if (block) {
        for (offset = 0; offset < requested; offset += system.dwPageSize)
            block[offset] = (unsigned char)(offset / system.dwPageSize);
        block[requested - 1] = 0x5a;
        duringValid = iewkWin9xCommittedPrivateBytes(&during);
        SetLastError(0);
        freed = VirtualFree((LPVOID)block, 0, MEM_RELEASE);
        freeError = GetLastError();
        if (freed)
            block = NULL;
        afterValid = iewkWin9xCommittedPrivateBytes(&after);
    }
    fprintf(log, "allocation.requested=%lu\r\nallocation.error=%lu\r\nfree.succeeded=%u\r\nfree.error=%lu\r\n",
        (unsigned long)requested, allocationError, (unsigned)freed, freeError);
    fprintf(log, "committed.before.valid=%u\r\ncommitted.before=%lu\r\ncommitted.during.valid=%u\r\ncommitted.during=%lu\r\ncommitted.after.valid=%u\r\ncommitted.after=%lu\r\n",
        (unsigned)beforeValid, (unsigned long)before, (unsigned)duringValid, (unsigned long)during,
        (unsigned)afterValid, (unsigned long)after);
    fprintf(log, "delta.allocate=%lu\r\ndelta.release=%lu\r\nrecovery.at-or-below-before=%u\r\n",
        (unsigned long)(during >= before ? during - before : 0),
        (unsigned long)(during >= after ? during - after : 0), (unsigned)(afterValid && after <= before));
    if (!duringValid || during < before || during - before < requested)
        exitCode = 7;
    else if (!freed || !afterValid || after > during || during - after < requested)
        exitCode = 8;
finish:
    if (block && !VirtualFree((LPVOID)block, 0, MEM_RELEASE))
        exitCode = 9;
    fprintf(log, "exit=%d\r\n", exitCode);
    fclose(log);
    return exitCode;
}
