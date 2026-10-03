/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for k32_compat.c (pthread platform binding) and for the
 * chrome_elf contract in api_contract.c. Optional argv[1]: path to the pinned
 * Chromium 157 chrome_elf.dll; without it the identity checks are skipped and
 * reported as such (never counted as passes).
 */
#include "k32_compat.h"
#include "api_contract.h"
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int checks, failures;
static void check(int ok, const char *what) { checks++; if (!ok) { failures++; printf("FAIL %s\n", what); } }

/* ---- pthread platform -------------------------------------------------- */
typedef struct ev { pthread_mutex_t m; pthread_cond_t c; int set; } ev;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread ev *thread_event;
static int deny_events;
void k32p_lock(void) { pthread_mutex_lock(&queue_mutex); }
void k32p_unlock(void) { pthread_mutex_unlock(&queue_mutex); }
static ev *all_events[256]; static unsigned event_count;
void *k32p_thread_event(void)
{
    if (deny_events) return NULL;
    if (!thread_event) {
        thread_event = calloc(1, sizeof(ev));
        pthread_mutex_init(&thread_event->m, 0);
        pthread_cond_init(&thread_event->c, 0);
        pthread_mutex_lock(&queue_mutex);
        if (event_count < 256) all_events[event_count++] = thread_event;
        pthread_mutex_unlock(&queue_mutex);
    }
    return thread_event;
}
int k32p_wait(void *event, uint32_t ms)
{
    ev *e = event; int r = 0;
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    t.tv_sec += ms / 1000; t.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (t.tv_nsec >= 1000000000L) { t.tv_sec++; t.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&e->m);
    while (!e->set && r == 0) r = ms == K32_INFINITE ? pthread_cond_wait(&e->c, &e->m) : pthread_cond_timedwait(&e->c, &e->m, &t);
    if (e->set) { e->set = 0; r = 0; }
    pthread_mutex_unlock(&e->m);
    return r == 0 ? 0 : r == ETIMEDOUT ? 1 : -1;
}
void k32p_signal(void *event) { ev *e = event; pthread_mutex_lock(&e->m); e->set = 1; pthread_cond_signal(&e->c); pthread_mutex_unlock(&e->m); }
void k32p_yield(void) { sched_yield(); }
uint32_t k32p_ticks(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return (uint32_t)(t.tv_sec * 1000 + t.tv_nsec / 1000000); }

/* ---- SRW stress --------------------------------------------------------- */
static volatile uint32_t srw;
static long counter, shadow;
static volatile int readers_inside, writer_inside, violation;
static void *srw_worker(void *arg)
{
    long id = (long)arg; int i;
    for (i = 0; i < 20000; i++) {
        if ((i + id) % 4 == 0) {
            k32_srw_acquire(&srw, 0);
            __sync_fetch_and_add(&readers_inside, 1);
            if (writer_inside || counter != shadow) violation = 1;
            __sync_fetch_and_sub(&readers_inside, 1);
            k32_srw_release(&srw, 0);
        } else {
            k32_srw_acquire(&srw, 1);
            if (writer_inside || readers_inside) violation = 1;
            writer_inside = 1; counter++; if (i % 64 == 0) sched_yield(); shadow++; writer_inside = 0;
            k32_srw_release(&srw, 1);
        }
    }
    return 0;
}

/* ---- condition variable producer/consumer ------------------------------- */
static volatile uint32_t cv_lock, cv;
static int items, consumed;
static void rel(void *l, int shared) { k32_srw_release(l, !shared); }
static void acq(void *l, int shared) { k32_srw_acquire(l, !shared); }
static void *consumer(void *arg)
{
    (void)arg;
    for (;;) {
        k32_srw_acquire(&cv_lock, 1);
        while (!items && consumed < 4000) (void)k32_cv_sleep(&cv, (void *)&cv_lock, 0, K32_INFINITE, rel, acq);
        if (consumed >= 4000) { k32_srw_release(&cv_lock, 1); k32_cv_wake(&cv, 1); return 0; }
        items--; consumed++;
        k32_srw_release(&cv_lock, 1);
    }
}

int main(int argc, char **argv)
{
    pthread_t t[8]; long i; int r;
    /* uncontended semantics */
    check(k32_srw_try_acquire(&srw, 1) && srw == K32_SRW_EXCLUSIVE, "try exclusive on free lock");
    check(!k32_srw_try_acquire(&srw, 1) && !k32_srw_try_acquire(&srw, 0), "exclusive excludes both modes (non-recursive)");
    k32_srw_release(&srw, 1); check(srw == 0, "exclusive release clears word");
    check(k32_srw_try_acquire(&srw, 0) && k32_srw_try_acquire(&srw, 0) && srw == 2 * K32_SRW_SHARED, "two shared owners");
    check(!k32_srw_try_acquire(&srw, 1), "shared excludes exclusive");
    k32_srw_release(&srw, 0); k32_srw_release(&srw, 0); check(srw == 0, "shared releases clear word");
    /* contended correctness */
    for (i = 0; i < 8; i++) pthread_create(&t[i], 0, srw_worker, (void *)i);
    for (i = 0; i < 8; i++) pthread_join(t[i], 0);
    check(!violation && counter == shadow && counter == 8 * 15000, "8-thread SRW mutual exclusion and reader isolation");
    check(srw == 0 && k32_queue_depth() == 0, "SRW word and queue drained");
    /* polling fallback when no wait event can be created */
    deny_events = 1;
    k32_srw_acquire(&srw, 1); check(srw == K32_SRW_EXCLUSIVE, "fallback acquire without event");
    k32_srw_release(&srw, 1); deny_events = 0;
    /* condition variable timeout keeps lock and leaves no waiter */
    k32_srw_acquire(&cv_lock, 1);
    r = k32_cv_sleep(&cv, (void *)&cv_lock, 0, 30, rel, acq);
    check(r == 1 && cv_lock == K32_SRW_EXCLUSIVE && k32_queue_depth() == 0, "CV timeout reacquires lock, unlinks waiter");
    k32_srw_release(&cv_lock, 1);
    deny_events = 1;
    k32_srw_acquire(&cv_lock, 1);
    r = k32_cv_sleep(&cv, (void *)&cv_lock, 0, 30, rel, acq);
    check(r == 2 && cv_lock == K32_SRW_EXCLUSIVE, "CV without event fails truthfully while lock held");
    k32_srw_release(&cv_lock, 1); deny_events = 0;
    k32_cv_wake(&cv, 0); check(k32_queue_depth() == 0, "wake with no waiters is a no-op");
    /* producer / consumers */
    for (i = 0; i < 4; i++) pthread_create(&t[i], 0, consumer, 0);
    for (i = 0; i < 4000; i++) {
        k32_srw_acquire(&cv_lock, 1); items++; k32_srw_release(&cv_lock, 1);
        if (i & 1) k32_cv_wake(&cv, 0); else k32_cv_wake(&cv, 1);
    }
    for (;;) { k32_srw_acquire(&cv_lock, 1); r = consumed >= 4000; k32_srw_release(&cv_lock, 1); if (r) break; k32_cv_wake(&cv, 1); sched_yield(); }
    k32_cv_wake(&cv, 1);
    for (i = 0; i < 4; i++) pthread_join(t[i], 0);
    check(consumed == 4000 && items == 0 && k32_queue_depth() == 0, "CV producer/consumer: no lost wakeups, queue drained");

    /* VerSetConditionMask / VerifyVersionInfo against actual Win98 SE values */
    {
        k32_osver w98 = {4, 10, 2222, 1, 0, 0, 0, 0}, want;
        uint64_t m = 0;
        m = k32_ver_set_condition_mask(m, K32_VER_MAJOR, K32_VER_GREATER_EQUAL);
        m = k32_ver_set_condition_mask(m, K32_VER_MINOR, K32_VER_GREATER_EQUAL);
        m = k32_ver_set_condition_mask(m, K32_VER_SPMAJOR, K32_VER_GREATER_EQUAL);
        check(m == ((3ull << 3) | 3ull | (3ull << 15)), "condition mask bit layout");
        check(k32_ver_set_condition_mask(7, 0, 3) == 7 && k32_ver_set_condition_mask(7, 2, 0) == 7, "zero type/condition leaves mask");
        memset(&want, 0, sizeof want); want.major = 10;
        check(k32_verify_version(&w98, &want, K32_VER_MAJOR | K32_VER_MINOR | K32_VER_SPMAJOR, m) == K32_VERIFY_MISMATCH, "IsWindows10OrGreater false on Win98");
        want.major = 4; want.minor = 10;
        check(k32_verify_version(&w98, &want, K32_VER_MAJOR | K32_VER_MINOR | K32_VER_SPMAJOR, m) == K32_VERIFY_OK, "4.10 >= 4.10 SP0");
        want.major = 4; want.minor = 0;
        check(k32_verify_version(&w98, &want, K32_VER_MAJOR | K32_VER_MINOR, m) == K32_VERIFY_OK, "4.10 >= 4.0 hierarchical");
        want.major = 3; want.minor = 50; m = k32_ver_set_condition_mask(0, K32_VER_MAJOR, K32_VER_GREATER);
        m = k32_ver_set_condition_mask(m, K32_VER_MINOR, K32_VER_GREATER);
        check(k32_verify_version(&w98, &want, K32_VER_MAJOR | K32_VER_MINOR, m) == K32_VERIFY_OK, "major decides when greater");
        want.platform = 2; m = k32_ver_set_condition_mask(0, K32_VER_PLATFORM, K32_VER_EQUAL);
        check(k32_verify_version(&w98, &want, K32_VER_PLATFORM, m) == K32_VERIFY_MISMATCH, "platform is not NT");
        want.suite = 0x100; m = k32_ver_set_condition_mask(0, K32_VER_SUITE, K32_VER_AND);
        check(k32_verify_version(&w98, &want, K32_VER_SUITE, m) == K32_VERIFY_MISMATCH, "suite AND absent");
        m = k32_ver_set_condition_mask(0, K32_VER_SUITE, K32_VER_LESS);
        check(k32_verify_version(&w98, &want, K32_VER_SUITE, m) == K32_VERIFY_BADARG, "suite numeric condition invalid");
        check(k32_verify_version(&w98, &want, 0, m) == K32_VERIFY_BADARG && k32_verify_version(&w98, &want, K32_VER_MAJOR, 0) == K32_VERIFY_BADARG, "empty type/condition invalid");
        want.build = 2222; m = k32_ver_set_condition_mask(0, K32_VER_BUILD, K32_VER_LESS_EQUAL);
        check(k32_verify_version(&w98, &want, K32_VER_BUILD, m) == K32_VERIFY_OK, "build <= 2222");
    }
    /* pointer encoding */
    {
        uint32_t c, v;
        for (c = 1; c < 0xffffffffu - 0x10001u; c += 0x10001u) {
            v = 0x00401000u ^ c * 7u;
            if (k32_decode(k32_encode(v, c), c) != v) break;
        }
        check(c >= 0xffffffffu - 0x10001u, "decode inverts encode across cookies");
        check(k32_encode(0x00401000u, 0x5a5a1234u) != 0x00401000u, "encoded pointer differs");
    }
    /* chrome_elf contract */
    {
        ac_target target; ac_route route; FILE *f; uint8_t *bytes; long n;
        if (argc < 2) printf("SKIP chrome_elf identity checks (no pinned file argument)\n");
        else if (!(f = fopen(argv[1], "rb"))) { printf("FAIL cannot open %s\n", argv[1]); failures++; }
        else {
            fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
            bytes = malloc((size_t)n);
            check(bytes && fread(bytes, 1, (size_t)n, f) == (size_t)n, "read pinned chrome_elf");
            fclose(f);
            check(ac_init(&target, bytes, (size_t)n) && target.role == AC_ROLE_CHROME_ELF, "exact chrome_elf 157 identity accepted");
            check(ac_lookup(&target, "ntdll.dll", "NtOpenKeyEx", 0, &route) && route.kind == AC_PRIVATE_NT_REGISTRY && !strcmp(route.provider, "M98NTREG.DLL"), "ntdll NtOpenKeyEx -> M98NTREG");
            check(ac_lookup(&target, "ntdll.dll", "RtlFormatCurrentUserKeyPath", 0, &route) && !strcmp(route.symbol, "RtlFormatCurrentUserKeyPath"), "ntdll Rtl route");
            check(!ac_lookup(&target, "ntdll.dll", "NtCreateFile", 0, &route) && !route.kind, "no blanket ntdll redirection");
            check(!ac_lookup(&target, "ntdll.dll", "ntopenkeyex", 0, &route), "symbol case exact");
            check(ac_lookup(&target, "KERNEL32.dll", "AcquireSRWLockExclusive", 0, &route) && route.kind == AC_PRIVATE_KERNEL32 && !strcmp(route.provider, "M98K32CE.DLL"), "KERNEL32 SRW -> M98K32CE");
            check(ac_lookup(&target, "kernel32.dll", "VerifyVersionInfoW", 0, &route), "KERNEL32 VerifyVersionInfoW route");
            check(!ac_lookup(&target, "KERNEL32.dll", "CreateFileW", 0, &route), "native KERNEL32 names not redirected");
            check(!ac_lookup(&target, "KERNEL32.dll", "IsProcessInJob", 0, &route) && !ac_lookup(&target, "KERNEL32.dll", "GetTickCount64", 0, &route), "names chrome_elf does not import stay unresolved");
            check(ac_lookup(&target, "KERNEL32.dll", "AddVectoredExceptionHandler", 0, &route) && route.kind == AC_PRIVATE_KERNEL32, "batch3 VEH routed to real backend");
            check(ac_lookup(&target, "KERNEL32.dll", "QueryThreadCycleTime", 0, &route) && route.kind == AC_KERNEL32_UNSUPPORTED, "batch3 explicit unsupported kind");
            check(!ac_lookup(&target, "API-MS-WIN-CORE-SYNCH-L1-2-0.DLL", "WaitOnAddress", 0, &route), "chrome.exe routes not granted to chrome_elf");
            check(!ac_lookup(&target, "C:\\X\\ntdll.dll", "NtClose", 0, &route), "path module names rejected");
            check(!ac_lookup(&target, "ntdll.dll", "NtClose", 3, &route), "ordinal alias rejected");
            bytes[4096] ^= 1;
            check(!ac_init(&target, bytes, (size_t)n) && !target.magic, "modified chrome_elf rejected");
            check(!ac_lookup(&target, "ntdll.dll", "NtClose", 0, &route), "failed identity has no route");
            free(bytes);
        }
    }
    for (i = 0; i < (long)event_count; i++) { pthread_mutex_destroy(&all_events[i]->m); pthread_cond_destroy(&all_events[i]->c); free(all_events[i]); }
    printf("%s %d checks, %d failures\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures != 0;
}
