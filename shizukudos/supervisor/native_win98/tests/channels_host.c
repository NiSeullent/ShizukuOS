/* SPDX-License-Identifier: GPL-2.0-only
 * Actual channel constructor and hypercall dispatcher; only VMCS instructions
 * are modeled. No guest code, VMM, VMX or Windows executes in this fixture.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/cpu.h"
#include "../../src/domain.h"
#include "../../src/devices.h"
#include "../../../kernel64/boot_channel_peer.h"

static unsigned checks, map_calls, advance_calls;
static uint64_t rip = 0x1234;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(2); } } while (0)

static uint64_t host_vmread(uint64_t field)
{
    CHECK(field == VMCS_GUEST_RIP || field == VMCS_EXIT_INSTR_LEN);
    return field == VMCS_GUEST_RIP ? rip : 3;
}
static int host_vmwrite(uint64_t field, uint64_t value)
{
    CHECK(field == VMCS_GUEST_RIP && value == rip + 3);
    rip = value;
    ++advance_calls;
    return 0;
}
static uint64_t host_rdtsc(void) { return 1000000; }
#define vmread host_vmread
#define vmwrite host_vmwrite
#define rdtsc host_rdtsc
#include "../../src/domain.c"
#include "../../src/kdom.c"
#undef vmread
#undef vmwrite
#undef rdtsc

void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *out, unsigned length, const char *format, ...)
{ (void)format; if (length) out[0] = 0; }
uint8_t dev_cmos_read(uint8_t reg) { (void)reg; return 0; }
int ept_map(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t bytes, uint64_t flags, int pages)
{
    CHECK(e == &g_dom[SHZ_DOM_KERNEL64].ept || e == &g_dom[SHZ_DOM_WIN98].ept);
    CHECK(gpa == SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE);
    CHECK(hpa == g_info->ipc_base + 2ull * SHZ_IPC_REGION_SIZE);
    CHECK(bytes == SHZ_IPC_REGION_SIZE && flags == (EPT_RWX | EPT_WB) && pages == 1);
    ++map_calls;
    return 0;
}

static void query(domain_t *d, uint64_t channel, int64_t expected)
{
    const unsigned before = advance_calls;
    d->vc.gpr[GPR_RAX] = SHZ_HC_CHANNEL_INFO;
    d->vc.gpr[GPR_RBX] = channel;
    CHECK(hcall_vmcall(d) == 0);
    CHECK((int64_t)d->vc.gpr[GPR_RAX] == expected && advance_calls == before + 1);
    if (expected == SHZ_OK) {
        CHECK(d->vc.gpr[GPR_RBX] == SHZ_IPC_GPA_BASE + channel * SHZ_IPC_REGION_SIZE);
        CHECK(d->vc.gpr[GPR_RCX] == d->chan[channel].peer);
    }
}

int main(void)
{
    shz_info_t info = {0};
    uint8_t *ipc = calloc(SHZ_MAX_CHANNELS, SHZ_IPC_REGION_SIZE);
    uint8_t *win = malloc(65536), *saved = malloc(65536), *k64 = calloc(1, 65536);
    CHECK(ipc && win && saved && k64);
    for (unsigned i = 0; i < 65536; ++i) win[i] = (uint8_t)(i * 37 + 0xa5);
    memcpy(saved, win, 65536);
    info.ipc_base = (uintptr_t)ipc;
    info.ipc_size = SHZ_MAX_CHANNELS * SHZ_IPC_REGION_SIZE;
    g_info = &info;
    g_tsc_hz = 1000000000;
    domain_t *w = &g_dom[SHZ_DOM_WIN98], *k = &g_dom[SHZ_DOM_KERNEL64];
    w->id = SHZ_DOM_WIN98; w->kind = DK_WIN98; w->state = SHZ_DS_RUNNABLE;
    w->name = "WIN98"; w->ram_base = (uintptr_t)win; w->ram_size = 65536;
    k->id = SHZ_DOM_KERNEL64; k->kind = DK_KERNEL64; k->state = SHZ_DS_RUNNABLE;
    k->name = "K64"; k->ram_base = (uintptr_t)k64; k->ram_size = 65536;
    shz_bootinfo_t *bi = (shz_bootinfo_t *)(k64 + SHZ_BOOTINFO_GPA);
    bi->size = sizeof *bi;
    CHECK(ipc_channels_create(&info) == 0 && map_calls == 2);
    /* Complete Windows low memory, especially 0x7000, survives actual mapping. */
    CHECK(memcmp(win, saved, 65536) == 0);
    CHECK(w->chan[2].mapped && w->chan[2].peer == SHZ_DOM_KERNEL64);
    CHECK(k->chan[2].mapped && k->chan[2].peer == SHZ_DOM_WIN98);
    CHECK(!w->chan[0].mapped && !w->chan[1].mapped && !w->chan[3].mapped);
    CHECK(bi->channel_count == 1 && bi->channel[0].channel_id == 2);
    CHECK(bi->channel[0].peer_domain == SHZ_DOM_WIN98);
    CHECK(k64_boot_has_kernel32_peer(bi) == 0);
    query(w, 2, SHZ_OK);
    query(k, 2, SHZ_OK);
    query(w, 0, SHZ_E_NOENT);
    query(w, SHZ_MAX_CHANNELS, SHZ_E_NOENT);
    query(w, UINT64_MAX, SHZ_E_NOENT);
    CHECK(memcmp(win, saved, 65536) == 0);
    const uint64_t gpa = SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE;
    CHECK(dom_gpa_ptr(w, gpa, SHZ_IPC_REGION_SIZE) == ipc + 2u * SHZ_IPC_REGION_SIZE);
    CHECK(dom_gpa_ptr(w, gpa + SHZ_IPC_REGION_SIZE, 1) == NULL);
    CHECK(dom_gpa_ptr(w, UINT64_MAX, 1) == NULL);

    bi->channel[0].peer_domain = SHZ_DOM_KERNEL32;
    CHECK(k64_boot_has_kernel32_peer(bi) == 1);
    bi->channel[0].peer_domain = SHZ_DOM_WIN98;
    bi->channel_count = 2; bi->channel[1].peer_domain = SHZ_DOM_KERNEL32;
    CHECK(k64_boot_has_kernel32_peer(bi) == 1);
    bi->size = __builtin_offsetof(shz_bootinfo_t, channel) + sizeof bi->channel[0];
    CHECK(k64_boot_has_kernel32_peer(bi) == -1);
    bi->size = sizeof *bi; bi->channel_count = SHZ_MAX_CHANNELS + 1;
    CHECK(k64_boot_has_kernel32_peer(bi) == -1);
    bi->channel_count = 0;
    CHECK(k64_boot_has_kernel32_peer(bi) == 0);
    bi->size = __builtin_offsetof(shz_bootinfo_t, channel_count);
    CHECK(k64_boot_has_kernel32_peer(bi) == -1);
    CHECK(k64_boot_has_kernel32_peer(NULL) == -1);

    memset(g_dom, 0, sizeof g_dom); map_calls = 0;
    CHECK(ipc_channels_create(&info) == 0 && map_calls == 0);
    free(ipc); free(win); free(saved); free(k64);
    printf("PASS %u actual channel/CHANNEL_INFO/low-memory/peer checks (VMCS instructions modeled, no VM)\n", checks);
    return 0;
}
