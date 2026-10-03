/* SPDX-License-Identifier: GPL-2.0-only
 * Real parallel callers execute the production admission boundary. VMM and
 * hypercalls remain host fixtures; no Windows scheduling claim is made. */
#include "../bridge.h"
#include "../../../shizukudos/abi/shz_ipc.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", (unsigned)__LINE__, #x); exit(1); } } while (0)
static uint8_t channel[SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
static uint32_t paused, resume_owner, first_probe, callbacks;
static _Thread_local struct ntwv_w64_open output;
static uint32_t owner_result;
static uint32_t lifecycle_ready, lifecycle_go, shutdown_result, entry_result;

static uintptr_t enter(void *unused) { (void)unused; return 0; }
static void leave(void *unused, uintptr_t saved) { (void)unused; (void)saved; }
static uint32_t check(uint32_t page, uint32_t count, uint32_t flags)
{ (void)page; (void)flags; __atomic_fetch_add(&callbacks, 1, __ATOMIC_RELAXED); return count; }
static uint32_t lock(uint32_t page, uint32_t count, uint32_t flags)
{ (void)count; (void)flags; return page == 0x500 ? 0xc1000000u : 0xc2000000u; }
static uint32_t unlock(uint32_t page, uint32_t count, uint32_t flags)
{ (void)page; (void)count; (void)flags; return 1; }
static uint32_t ptes(uint32_t page, uint32_t count, uint32_t *out, uint32_t flags)
{
    uint32_t i;
    const uint32_t base = page == 0x500 || page == 0xc1000 ? 0x100000u : 0x200000u;
    (void)flags;
    for (i = 0; i < count; ++i) out[i] = base + i * 4096u + 7;
    return 1;
}
static void write_alias(uint32_t alias, const void *source, uint32_t bytes)
{ if (alias == 0xc1000000u) { CHECK(bytes == sizeof output); memcpy(&output, source, bytes); } }
static void read_alias(void *destination, uint32_t alias, uint32_t bytes)
{ (void)destination; (void)alias; (void)bytes; CHECK(0); }
static int present(void)
{
    uint32_t expected = 0;
    if (__atomic_compare_exchange_n(&first_probe, &expected, 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
        __atomic_store_n(&paused, 1, __ATOMIC_RELEASE);
        while (!__atomic_load_n(&resume_owner, __ATOMIC_ACQUIRE)) { }
    }
    return 1;
}
static int32_t hcall(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx, uint32_t *ecx)
{
    (void)b;
    if (op == SHZ_HC_ABI_VERSION) { *ebx = (1u << 16) | 1u; return SHZ_OK; }
    if (op == SHZ_HC_CHANNEL_INFO && a == 2) { *ebx = 0xe0200000u; *ecx = SHZ_DOM_KERNEL64; return SHZ_OK; }
    return SHZ_E_NOENT;
}
static void *map_phys(uint32_t phys, uint32_t bytes)
{ CHECK(phys == 0xe0200000u && bytes == sizeof channel); return channel; }
static const struct ntwv_pages pages = { check, lock, unlock, ptes, enter, leave, write_alias, read_alias };
static const struct ntwv_hv hv = { present, hcall, map_phys, 0 };
static const struct ntwv_dioc request = { .code = NTWV_IOCTL_W64_OPEN,
    .output = 0x00500000, .output_bytes = 64, .returned = 0x00600000 };
static void *owner(void *unused)
{ (void)unused; owner_result = ntwv_dioc_ex(&request, &pages, &hv); return 0; }

static void lifecycle_start(void)
{
    __atomic_fetch_add(&lifecycle_ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&lifecycle_go, __ATOMIC_ACQUIRE)) { }
}
static void *shutdown_caller(void *unused)
{ (void)unused; lifecycle_start(); shutdown_result = (uint32_t)ntwv_shutdown(); return 0; }
static void *entry_caller(void *unused)
{ (void)unused; lifecycle_start(); entry_result = ntwv_dioc_ex(&request, &pages, &hv); return 0; }

static void shutdown_versus_entry(void)
{
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    unsigned round;
    /* Initialization stays externally serialized. Only shutdown and W64 entry
     * overlap, with no ordering edge between their lifecycle accesses. */
    for (round = 0; round < 128; ++round) {
        pthread_t shutdown_thread, entry_thread;
        ntwv_w64_reset();
        CHECK(ntwv_initialize(&locks));
        lifecycle_ready = lifecycle_go = shutdown_result = entry_result = 0;
        CHECK(!pthread_create(&shutdown_thread, 0, shutdown_caller, 0));
        CHECK(!pthread_create(&entry_thread, 0, entry_caller, 0));
        while (__atomic_load_n(&lifecycle_ready, __ATOMIC_ACQUIRE) != 2) { }
        __atomic_store_n(&lifecycle_go, 1, __ATOMIC_RELEASE);
        CHECK(!pthread_join(shutdown_thread, 0));
        CHECK(!pthread_join(entry_thread, 0));
        CHECK(entry_result == 0 || entry_result == NTWV_ERROR_BUSY || entry_result == NTWV_ERROR_NOT_READY);
        if (!shutdown_result)
            CHECK(ntwv_shutdown());             /* now externally serialized after both joins */
        CHECK(ntwv_dioc_ex(&request, &pages, &hv) == NTWV_ERROR_NOT_READY);
    }
    ntwv_w64_reset();
    puts("PASS: VxD shutdown-versus-entry 128 externally initialized rounds; final entry is NOT_READY");
}

int main(void)
{
    const struct ntw_lock_ops locks = { enter, leave, 0 };
    pthread_t thread;
    uint32_t before, result;
    CHECK(shz_channel_init(channel, sizeof channel, 2, SHZ_DOM_KERNEL64, SHZ_DOM_WIN98, 32, 1) == SHZ_OK);
    CHECK(ntwv_initialize(&locks));
    CHECK(!pthread_create(&thread, 0, owner, 0));
    while (!__atomic_load_n(&paused, __ATOMIC_ACQUIRE)) { }
    CHECK(!ntwv_shutdown());                   /* the paused admitted owner cannot be shut down */
    before = __atomic_load_n(&callbacks, __ATOMIC_RELAXED);
    result = ntwv_dioc_ex(&request, &pages, &hv);
    /* Always release and join the owner, including the failing baseline. */
    __atomic_store_n(&resume_owner, 1, __ATOMIC_RELEASE);
    CHECK(!pthread_join(thread, 0));
    CHECK(result == NTWV_ERROR_BUSY);
    CHECK(__atomic_load_n(&callbacks, __ATOMIC_RELAXED) == before);
    CHECK(owner_result == 0);
    CHECK(ntwv_dioc_ex(&request, &pages, &hv) == 0 && output.generation == 1);
    ntwv_w64_reset();
    CHECK(ntwv_shutdown());
    puts("PASS: VxD parallel admission rejects overlap before page callbacks; owner resumes and later calls succeed");
    shutdown_versus_entry();
    return 0;
}
