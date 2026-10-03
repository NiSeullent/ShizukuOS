/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the production IPC constructor and real EPT mapper in a bounded host
 * pool. No privileged instruction, VM or Windows guest is executed.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "domain.h"
#include "shz_ipc.h"
#include "ept.c"

domain_t g_dom[SHZ_MAX_DOMAINS];
static unsigned checks, allocated, publications, logs;
static int fail_at = -1;
static unsigned char pages[80][4096] __attribute__((aligned(4096)));
static unsigned char backing[SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE] __attribute__((aligned(4096)));
static unsigned char worker_ram[2][0x10000] __attribute__((aligned(4096)));
#define CHECK(v) do { ++checks; if (!(v)) { fprintf(stderr, "FAIL %u: %s\n", __LINE__, #v); exit(2); } } while (0)

void *pool_alloc_pages(unsigned n)
{
    CHECK(n == 1 && allocated < 80);
    if ((int)allocated == fail_at) return NULL;
    memset(pages[allocated], 0, 4096);
    return pages[allocated++];
}

void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *buffer, unsigned size, const char *format, ...)
{
    (void)format; ++logs;
    if (size) buffer[0] = 0;
}

/* Existing Windows-owner publication policy has its own tests. Record that the
 * constructor reaches it only after successful channel mapping. */
static int win98_foundation_publish(shz_info_t *info)
{
    (void)info; ++publications; return 0;
}
#include "ipc_constructor.inc"

static uint64_t leaf(const ept_t *e, uint64_t gpa)
{
    uint64_t *table = e->pml4;
    if (!table) return 0;
    for (int shift = 39; shift >= 21; shift -= 9) {
        const uint64_t entry = table[(gpa >> shift) & 511];
        if (!(entry & EPT_RWX)) return 0;
        CHECK(!(entry & LARGE));
        table = (uint64_t *)(uintptr_t)(entry & ADDR_MASK);
    }
    return table[(gpa >> 12) & 511];
}

static void setup(shz_info_t *info, int win98)
{
    memset(info, 0, sizeof *info);
    memset(g_dom, 0, sizeof g_dom);
    memset(worker_ram, 0, sizeof worker_ram);
    memset(backing, 0, sizeof backing);
    allocated = publications = logs = 0; fail_at = -1;
    info->ipc_base = (uint64_t)(uintptr_t)backing;
    info->ipc_size = sizeof backing;
    const unsigned ids[] = { SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64, SHZ_DOM_DOS16, SHZ_DOM_WIN98 };
    for (unsigned i = 0; i < 4; ++i) {
        domain_t *d = &g_dom[ids[i]];
        d->id = ids[i]; d->state = SHZ_DS_RUNNABLE; d->generation = 1;
        d->name = "host-fixture";
        d->kind = i == 0 ? DK_KERNEL32 : i == 1 ? DK_KERNEL64 : i == 2 ? DK_DOS16 : DK_WIN98;
        if (i < 2) {
            d->ram_base = (uint64_t)(uintptr_t)worker_ram[i];
            d->ram_size = sizeof worker_ram[i];
        }
        if (i == 3 && !win98) { d->state = 0; continue; }
        CHECK(ept_init(&d->ept) == 0);
        if (i != 2) {
            /* Private code keeps execution permission. IPC must not inherit it. */
            CHECK(ept_map(&d->ept, 0x100000, 0x10000000 + i * 0x100000, 4096,
                          EPT_R | EPT_X | EPT_WB, 1) == 0);
        }
    }
}

static void verify_peer(unsigned id, unsigned channel, unsigned peer)
{
    domain_t *d = &g_dom[id];
    const uint64_t gpa = SHZ_IPC_GPA_BASE + (uint64_t)channel * SHZ_IPC_REGION_SIZE;
    const uint64_t hpa = (uint64_t)(uintptr_t)backing + (uint64_t)channel * SHZ_IPC_REGION_SIZE;
    CHECK(d->chan[channel].mapped && d->chan[channel].peer == peer && d->chan[channel].hpa == hpa);
    for (uint64_t offset = 0; offset < SHZ_IPC_REGION_SIZE; offset += 4096) {
        const uint64_t entry = leaf(&d->ept, gpa + offset);
        CHECK(entry == ((hpa + offset) | EPT_R | EPT_W | EPT_WB));
        CHECK(!(entry & EPT_X));
    }
}

int main(void)
{
    shz_info_t info;
    setup(&info, 1);
    CHECK(ipc_channels_create(&info) == 0 && publications == 1 && !logs);
    verify_peer(SHZ_DOM_KERNEL32, 0, SHZ_DOM_KERNEL64);
    verify_peer(SHZ_DOM_KERNEL64, 0, SHZ_DOM_KERNEL32);
    verify_peer(SHZ_DOM_KERNEL32, 1, SHZ_DOM_DOS16);
    verify_peer(SHZ_DOM_KERNEL64, 2, SHZ_DOM_WIN98);
    verify_peer(SHZ_DOM_WIN98, 2, SHZ_DOM_KERNEL64);
    CHECK(!g_dom[SHZ_DOM_DOS16].chan[1].mapped && !g_dom[SHZ_DOM_DOS16].ept.mapped_bytes);
    CHECK(!leaf(&g_dom[SHZ_DOM_KERNEL32].ept, SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE));
    CHECK(!leaf(&g_dom[SHZ_DOM_WIN98].ept, SHZ_IPC_GPA_BASE));
    CHECK(leaf(&g_dom[SHZ_DOM_KERNEL64].ept, 0x100000) == (0x10100000 | EPT_R | EPT_X | EPT_WB));
    shz_bootinfo_t *a = (shz_bootinfo_t *)(worker_ram[0] + SHZ_BOOTINFO_GPA);
    shz_bootinfo_t *b = (shz_bootinfo_t *)(worker_ram[1] + SHZ_BOOTINFO_GPA);
    CHECK(a->channel_count == 2 && b->channel_count == 2);
    shz_channel_hdr_t *channel = (shz_channel_hdr_t *)(backing + 2 * SHZ_IPC_REGION_SIZE);
    CHECK(channel->channel_id == 2 && channel->domain_a == SHZ_DOM_KERNEL64 && channel->domain_b == SHZ_DOM_WIN98);

    setup(&info, 0);
    CHECK(ipc_channels_create(&info) == 0 && publications == 1);
    CHECK(!g_dom[SHZ_DOM_KERNEL64].chan[2].mapped && !leaf(&g_dom[SHZ_DOM_KERNEL64].ept, SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE));
    verify_peer(SHZ_DOM_KERNEL32, 0, SHZ_DOM_KERNEL64);

    setup(&info, 1); info.ipc_size = sizeof backing - 1;
    CHECK(ipc_channels_create(&info) == 0 && !publications);
    info.loader_flags = 1;
    CHECK(ipc_channels_create(&info) == -1 && !publications && logs == 1);
    CHECK(!g_dom[SHZ_DOM_KERNEL32].chan[0].mapped);

    setup(&info, 1); fail_at = (int)allocated;
    CHECK(ipc_channels_create(&info) == -1 && !publications && logs == 1);
    CHECK(!g_dom[SHZ_DOM_KERNEL32].chan[0].mapped);
    printf("PASS %u production IPC/EPT leaf, peer isolation and failure checks; no VMX/Windows execution\n", checks);
    return 0;
}
