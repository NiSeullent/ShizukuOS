/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Supervisor policy publisher; domain/mapping state is modeled.
 * This checks admission and atomic handoff, not VMX or Windows execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../supervisor/src/kdom.c"

domain_t g_dom[SHZ_MAX_DOMAINS];
static unsigned checks;
static uint8_t *ram[3];
static shz_info_t info;
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); exit(1); } } while (0)
void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *out, unsigned length, const char *format, ...)
{ (void)format; if (length) out[0] = 'E'; }
int ept_map(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t bytes, uint64_t flags, int pages)
{ (void)e; (void)gpa; (void)hpa; (void)bytes; (void)flags; (void)pages; abort(); }

static shz_bootinfo_t *worker(unsigned id)
{ return (shz_bootinfo_t *)(uintptr_t)(g_dom[id].ram_base + SHZ_BOOTINFO_GPA); }
static void fixture(void)
{
    const unsigned ids[] = {SHZ_DOM_WIN98, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64};
    const dom_kind_t kinds[] = {DK_WIN98, DK_KERNEL32, DK_KERNEL64};
    memset(&info, 0, sizeof info); memset(g_dom, 0, sizeof g_dom);
    info.loader_flags = SHZ_LOADER_NATIVE_WIN98;
    for (unsigned i = 0; i < 3; ++i) {
        memset(ram[i], i == 0 ? 0xa5 : 0, 65536);
        domain_t *d = &g_dom[ids[i]];
        d->id = ids[i]; d->kind = kinds[i]; d->generation = 7;
        d->state = SHZ_DS_RUNNABLE; d->ram_base = (uintptr_t)ram[i]; d->ram_size = 65536;
        if (i) {
            shz_bootinfo_t *b = worker(ids[i]);
            b->magic = SHZ_BOOTINFO_MAGIC; b->abi_major = SHZ_ABI_MAJOR; b->abi_minor = SHZ_ABI_MINOR;
            b->size = sizeof *b; b->domain_id = ids[i]; b->generation = 7;
            b->channel_count = i;
            for (unsigned c = 0; c < i; ++c) {
                unsigned channel = c ? 2 : 0;
                unsigned peer = c ? SHZ_DOM_WIN98 : (i == 1 ? SHZ_DOM_KERNEL64 : SHZ_DOM_KERNEL32);
                b->channel[c].channel_id = channel; b->channel[c].peer_domain = peer;
                b->channel[c].gpa = SHZ_IPC_GPA_BASE + (uint64_t)channel * SHZ_IPC_REGION_SIZE;
                b->channel[c].size = SHZ_IPC_REGION_SIZE;
                d->chan[channel].mapped = 1; d->chan[channel].peer = peer;
            }
        }
    }
    g_dom[SHZ_DOM_WIN98].chan[2].mapped = 1;
    g_dom[SHZ_DOM_WIN98].chan[2].peer = SHZ_DOM_KERNEL64;
}
static void refusal(void)
{
    shz_bootinfo_t before32 = *worker(SHZ_DOM_KERNEL32), before64 = *worker(SHZ_DOM_KERNEL64);
    CHECK(win98_foundation_publish(&info) == -1);
    CHECK(memcmp(&before32, worker(SHZ_DOM_KERNEL32), sizeof before32) == 0);
    CHECK(memcmp(&before64, worker(SHZ_DOM_KERNEL64), sizeof before64) == 0);
}
int main(void)
{
    for (unsigned i = 0; i < 3; ++i) { ram[i] = malloc(65536); CHECK(ram[i]); }
    fixture();
    CHECK(win98_foundation_publish(&info) == 0);
    CHECK(shz_win98_foundation_policy(worker(SHZ_DOM_KERNEL32)) == 1);
    CHECK(shz_win98_foundation_policy(worker(SHZ_DOM_KERNEL64)) == 1);
    for (unsigned i = 0; i < 65536; ++i) CHECK(ram[0][i] == 0xa5);
    fixture(); info.loader_flags = 0;
    CHECK(win98_foundation_publish(&info) == 0);
    CHECK(worker(SHZ_DOM_KERNEL32)->cmdline_size == 0 && worker(SHZ_DOM_KERNEL64)->cmdline_size == 0);
    fixture(); info.loader_flags = SHZ_LOADER_NATIVE_WIN98 | 2; refusal();
    const unsigned ids[] = {SHZ_DOM_WIN98, SHZ_DOM_KERNEL32, SHZ_DOM_KERNEL64};
    const unsigned bad_states[] = {SHZ_DS_UNUSED, SHZ_DS_EXITED, SHZ_DS_FAILED, 99};
    for (unsigned i = 0; i < 3; ++i) {
        for (unsigned s = 0; s < sizeof bad_states / sizeof bad_states[0]; ++s) {
            fixture(); g_dom[ids[i]].state = bad_states[s]; refusal();
        }
        fixture(); g_dom[ids[i]].state = SHZ_DS_WAITING;
        CHECK(win98_foundation_publish(&info) == 0);
        fixture(); g_dom[ids[i]].generation = 0; refusal();
        fixture(); g_dom[ids[i]].id = SHZ_DOM_NONE; refusal();
        fixture(); g_dom[ids[i]].kind = DK_DOS16; refusal();
    }
    for (unsigned i = 1; i < 3; ++i) {
        fixture(); worker(ids[i])->generation++; refusal();
        fixture(); worker(ids[i])->domain_id = SHZ_DOM_WIN98; refusal();
        fixture(); worker(ids[i])->size--; refusal();
        fixture(); worker(ids[i])->channel[0].size--; refusal();
        fixture(); worker(ids[i])->flags = SHZ_BIF_UEFI_DIRECT; refusal();
        fixture(); g_dom[ids[i]].ram_size = SHZ_BOOTINFO_GPA; refusal();
    }
    fixture(); g_dom[SHZ_DOM_WIN98].chan[2].mapped = 0; refusal();
    fixture(); g_dom[SHZ_DOM_KERNEL64].chan[2].peer = SHZ_DOM_DOS16; refusal();
    fixture(); g_dom[SHZ_DOM_KERNEL32].chan[0].mapped = 0; refusal();
    fixture(); worker(SHZ_DOM_KERNEL64)->channel[1] = worker(SHZ_DOM_KERNEL64)->channel[0]; refusal();
    fixture(); CHECK(ipc_channels_create(&info) == -1); /* native flag cannot bypass missing backing */
    for (unsigned i = 0; i < 3; ++i) free(ram[i]);
    printf("PASS %u actual Supervisor publisher checks; domain/mapping boundary modeled; no VM\n", checks);
    return 0;
}
