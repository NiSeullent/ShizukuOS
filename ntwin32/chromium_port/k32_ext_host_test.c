/* SPDX-License-Identifier: GPL-2.0-only
 * Host controls for the batch-3 chrome_elf KERNEL32 cores in k32_compat.c:
 * VEH list ordering/removal-during-dispatch/concurrency, bounded frame walk,
 * logical processor layout, computer-name formats, mapped-image registry and
 * the api_contract accounting of all 40 Win98-missing chrome_elf names. */
#include "k32_compat.h"
#include "api_contract.h"
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int checks, failures;
static void check(int ok, const char *what) { checks++; if (!ok) { failures++; printf("FAIL %s\n", what); } }
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
void k32p_lock(void) { pthread_mutex_lock(&queue_mutex); }
void k32p_unlock(void) { pthread_mutex_unlock(&queue_mutex); }
void *k32p_thread_event(void) { return NULL; }
int k32p_wait(void *event, uint32_t ms) { (void)event; (void)ms; return -1; }
void k32p_signal(void *event) { (void)event; }
void k32p_yield(void) { sched_yield(); }
uint32_t k32p_ticks(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000); }

static char order[16]; static int pos; static void *self_handle;
static long h_a(void *p) { (void)p; order[pos++] = 'a'; return 0; }
static long h_b(void *p) { (void)p; order[pos++] = 'b'; return 0; }
static long h_c(void *p) { (void)p; order[pos++] = 'c'; return -1; }
static long h_self_remove(void *p) { (void)p; order[pos++] = 's'; check(k32_veh_remove(self_handle) == 1, "veh remove self during dispatch"); return 0; }
static long invoke(void *h, void *p) { return ((long (*)(void *))h)(p); }
static volatile long hits;
static long h_count(void *p) { (void)p; __atomic_add_fetch(&hits, 1, __ATOMIC_RELAXED); return 0; }
static void *veh_worker(void *arg)
{
    int i; (void)arg;
    for (i = 0; i < 2000; i++) {
        void *h = k32_veh_add(i & 1, (void *)h_count);
        if (h) { k32_veh_dispatch(NULL, invoke); k32_veh_remove(h); }
    }
    return NULL;
}

static const char *const missing40[] = {
 "AcquireSRWLockExclusive","AddVectoredExceptionHandler","DecodePointer","EncodePointer","FlsAlloc","FlsFree",
 "FlsGetValue","FlsSetValue","GetComputerNameExW","GetFileSizeEx","GetLogicalProcessorInformation","GetModuleHandleExW",
 "GetNativeSystemInfo","GetProcessId","GetProductInfo","GetThreadId","GlobalMemoryStatusEx","InitOnceExecuteOnce",
 "InitializeCriticalSectionEx","InitializeSListHead","InterlockedFlushSList","IsWow64Process","K32EnumProcessModules",
 "K32GetMappedFileNameW","K32GetModuleFileNameExA","K32GetModuleInformation","K32QueryWorkingSetEx","QueryThreadCycleTime",
 "ReleaseSRWLockExclusive","RemoveVectoredExceptionHandler","RtlCaptureStackBackTrace","SetFilePointerEx",
 "SetProcessMitigationPolicy","SetThreadInformation","SleepConditionVariableSRW","TryAcquireSRWLockExclusive",
 "VerSetConditionMask","VerifyVersionInfoW","WakeAllConditionVariable","WerRegisterRuntimeExceptionModule",0};

int main(int argc, char **argv)
{
    void *a, *b, *c, *handles[K32_VEH_MAX + 1]; unsigned i, n; pthread_t t[4];
    /* VEH: order (first inserts at head), stop on CONTINUE_EXECUTION, removal. */
    a = k32_veh_add(0, (void *)h_a); b = k32_veh_add(1, (void *)h_b);
    pos = 0; check(k32_veh_dispatch(NULL, invoke) == 0 && pos == 2 && order[0] == 'b' && order[1] == 'a', "veh head/tail order");
    c = k32_veh_add(1, (void *)h_c);
    pos = 0; check(k32_veh_dispatch(NULL, invoke) == -1 && pos == 1 && order[0] == 'c', "veh continue-execution stops chain");
    check(k32_veh_remove(c) == 1 && k32_veh_remove(c) == 0, "veh remove once");
    check(k32_veh_remove((char *)a + 1) == 0 && k32_veh_remove(&pos) == 0 && k32_veh_remove(NULL) == 0, "veh foreign handle rejected");
    self_handle = k32_veh_add(1, (void *)h_self_remove);
    pos = 0; k32_veh_dispatch(NULL, invoke);
    check(pos == 3 && order[0] == 's' && order[1] == 'b' && order[2] == 'a', "veh self-removal keeps chain intact");
    pos = 0; k32_veh_dispatch(NULL, invoke); check(pos == 2, "veh removed handler not called again");
    check(k32_veh_remove(a) && k32_veh_remove(b) && k32_veh_count() == 0, "veh drained");
    for (i = 0; i <= K32_VEH_MAX; i++) handles[i] = k32_veh_add(0, (void *)h_a);
    check(handles[K32_VEH_MAX - 1] && !handles[K32_VEH_MAX], "veh capacity bounded, overflow fails");
    for (i = 0; i < K32_VEH_MAX; i++) k32_veh_remove(handles[i]);
    check(k32_veh_add(0, NULL) == NULL && k32_veh_count() == 0, "veh null handler rejected");
    for (i = 0; i < 4; i++) pthread_create(&t[i], NULL, veh_worker, NULL);
    for (i = 0; i < 4; i++) pthread_join(t[i], NULL);
    check(k32_veh_count() == 0 && hits >= 8000, "veh 4-thread add/dispatch/remove");

    /* Frame walk on a synthetic stack: {fp,ret} chain, skip, bounds, loop. */
    { uintptr_t stack[32]; void *out[8]; uint32_t hash = 0; uintptr_t lo = (uintptr_t)stack, hi = (uintptr_t)(stack + 32);
      memset(stack, 0, sizeof(stack));
      stack[0] = (uintptr_t)&stack[4]; stack[1] = 0x1111;
      stack[4] = (uintptr_t)&stack[10]; stack[5] = 0x2222;
      stack[10] = (uintptr_t)&stack[20]; stack[11] = 0x3333;
      stack[20] = (uintptr_t)&stack[2]; stack[21] = 0x4444;   /* non-increasing: stop after */
      n = k32_walk_frames((uintptr_t)stack, lo, hi, 0, 8, out, &hash);
      check(n == 4 && out[0] == (void *)0x1111 && out[3] == (void *)0x4444 && hash == 0x1111 + 0x2222 + 0x3333 + 0x4444, "walk chain + hash");
      n = k32_walk_frames((uintptr_t)stack, lo, hi, 2, 1, out, &hash);
      check(n == 1 && out[0] == (void *)0x3333 && hash == 0x3333, "walk skip/count");
      stack[10] = hi + 64;  /* out of range */
      n = k32_walk_frames((uintptr_t)stack, lo, hi, 0, 8, out, NULL);
      check(n == 3, "walk stops at out-of-range frame");
      check(k32_walk_frames((uintptr_t)stack + 1, lo, hi, 0, 8, out, &hash) == 0 && hash == 0, "walk rejects misaligned");
      check(k32_walk_frames(hi - sizeof(uintptr_t), lo, hi, 0, 8, out, NULL) == 0, "walk rejects frame crossing top"); }

    /* Logical processor information: x86 24-byte layout. */
    { uint8_t buf[5 * K32_LPI_ENTRY]; uint32_t len = 0;
      check(k32_logical_processor_info(1, NULL, &len) == K32_LPI_SHORT && len == 3 * K32_LPI_ENTRY, "lpi size query");
      len = sizeof(buf);
      check(k32_logical_processor_info(1, buf, &len) == K32_LPI_OK && len == 72 && buf[0] == 1 && buf[4] == 0 &&
            buf[24] == 1 && buf[28] == 3 && buf[48] == 1 && buf[52] == 1, "lpi uniprocessor core/package/numa");
      len = 48; check(k32_logical_processor_info(3, buf, &len) == K32_LPI_SHORT && len == 96, "lpi short buffer");
      check(k32_logical_processor_info(0, buf, &len) == K32_LPI_BADARG, "lpi empty mask rejected"); }

    /* Computer name formats. */
    { char out[64]; unsigned need = 0;
      check(k32_compose_computer_name(0, "SHIZUKU", "shz", "lan", out, sizeof(out), &need) == 7 && !strcmp(out, "SHIZUKU"), "name netbios");
      check(k32_compose_computer_name(3, "SHIZUKU", "shz", "lan", out, sizeof(out), &need) == 7 && !strcmp(out, "shz.lan"), "name fqdn");
      check(k32_compose_computer_name(7, "SHIZUKU", "", "", out, sizeof(out), &need) == 7 && !strcmp(out, "SHIZUKU"), "name physical fqdn fallback");
      check(k32_compose_computer_name(2, "SHIZUKU", "shz", "", out, sizeof(out), &need) == 0 && !out[0], "name empty domain");
      check(k32_compose_computer_name(1, "SHIZUKU", "host", "", out, 4, &need) == -2 && need == 5, "name too small reports need");
      check(k32_compose_computer_name(8, "SHIZUKU", "", "", out, sizeof(out), &need) == -1, "name bad format"); }

    /* Mapped-image registry. */
    { uintptr_t base = 0; uint32_t size = 0; char path[16];
      check(k32_image_register(0x10000000u, 0x200000u, "C:\\APPLAB\\chrome_elf.dll"), "image register");
      check(!k32_image_register(0x10100000u, 0x1000u, "C:\\x.dll"), "image overlap rejected");
      check(!k32_image_register(0x20000000u, 0, "C:\\x.dll") && !k32_image_register(0xfffff000u, 0x2000u, "C:\\x.dll"), "image bad range rejected");
      check(k32_image_find(0x101fffffu, &base, &size, NULL, 0) == 1 && base == 0x10000000u && size == 0x200000u, "image find inside");
      check(k32_image_find(0x10200000u, &base, NULL, NULL, 0) == 0, "image end exclusive");
      check(k32_image_find(0x10000010u, NULL, NULL, path, sizeof(path)) == -1 && strlen(path) == 15, "image path truncation reported");
      check(k32_image_by_name("CHROME_ELF.DLL", &base) && base == 0x10000000u && !k32_image_by_name("chrome.dll", NULL), "image by leaf name");
      check(k32_image_list(NULL, 0) == 1 && k32_image_unregister(0x10000000u) && !k32_image_find(0x10000010u, NULL, NULL, NULL, 0), "image unregister"); }

    /* Contract accounting: every Win98-missing chrome_elf KERNEL32 name has
     * exactly one route; unsupported ones are marked explicitly. */
    if (argc > 1) {
        FILE *f = fopen(argv[1], "rb"); static uint8_t img[1276928]; size_t got = 0; ac_target target; ac_route r;
        unsigned routed = 0, unsupported = 0;
        if (f) { got = fread(img, 1, sizeof(img), f); fclose(f); }
        check(got == sizeof(img) && ac_init(&target, img, got) && target.role == AC_ROLE_CHROME_ELF, "pinned chrome_elf identity");
        for (i = 0; missing40[i]; i++) {
            int ok = ac_lookup(&target, "KERNEL32.dll", missing40[i], 0, &r);
            if (!ok || strcmp(r.provider, "M98K32CE.DLL") || strcmp(r.symbol, missing40[i])) printf("FAIL unrouted %s\n", missing40[i]);
            else if (r.kind == AC_KERNEL32_UNSUPPORTED) unsupported++; else routed++;
        }
        check(routed == 34 && unsupported == 6, "40 missing chrome_elf KERNEL32 names accounted (34 routed, 6 explicit unsupported)");
        check(!ac_lookup(&target, "KERNEL32.dll", "CreateFileW", 0, &r) && !ac_lookup(&target, "KERNEL32.dll", "getprocessid", 0, &r) &&
              !ac_lookup(&target, "KERNEL32.dll", "GetProcessId", 7, &r), "no blanket/case/ordinal routes");
        img[4096] ^= 1; check(!ac_init(&target, img, got), "mutated chrome_elf rejected");
    }
    if (failures) { printf("FAIL %d/%d checks\n", failures, checks); return 1; }
    printf("PASS %d checks; k32 batch3 host cores; native_executed=false; application_executed=false\n", checks);
    return 0;
}
