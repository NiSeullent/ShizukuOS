/* SPDX-License-Identifier: GPL-2.0-only
 * Run the production host page mapper with privileged boundaries substituted.
 * Catches fixed/default-PAT assumptions, large aperture leaves, adjacent mapping
 * changes and mutation before validation. No host MSR/CR/device access occurs.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SHZ_CPU_H
#define MSR_IA32_PAT 0x277
struct __attribute__((packed)) dtr { uint16_t limit; uint64_t base; };
static unsigned checks, pat_reads, cr3_writes, pat_writes;
static uint64_t inherited_pat, active_cr3;
#define CHECK(v) do { ++checks; if (!(v)) { \
    fprintf(stderr, "FAIL %s:%u: %s\n", __func__, __LINE__, #v); exit(2); \
} } while (0)

uint64_t rdmsr(uint32_t msr)
{ CHECK(msr == MSR_IA32_PAT); ++pat_reads; return inherited_pat; }
void wrmsr(uint32_t msr, uint64_t value)
{ (void)msr; (void)value; ++pat_writes; CHECK(0 && "global PAT must remain unchanged"); }
uint64_t read_cr2(void) { return 0; }
uint64_t read_cr3(void) { return active_cr3; }
uint64_t read_cr4(void) { return 0; }
void write_cr3(uint64_t value);
void write_cr4(uint64_t value) { (void)value; CHECK(0 && "fixture never enters platform_init"); }
void cli(void) { CHECK(0 && "fixture never enters host failure loop"); }
void hlt(void) { CHECK(0 && "fixture never executes HLT"); }

#include "../../src/platform.c"

const uint64_t isr_table[256] = {0};
void load_descriptor_tables(struct dtr *gdtr, struct dtr *idtr, uint16_t tr)
{ (void)gdtr; (void)idtr; (void)tr; CHECK(0 && "no host descriptor loading"); }
void kprintf(const char *format, ...) { (void)format; }
void log_capture(char *out, unsigned capacity, const char *format, ...)
{ (void)out; (void)capacity; (void)format; }

/* The proposed production function remains absent for the initial RED. */
int platform_vga_uc(uint64_t lfb_base, uint64_t lfb_bytes);

#define LFB_BASE UINT64_C(0xe0000000)
#define LFB_BYTES UINT64_C(0x01000000)
#define HOST_ADDRESS_MASK UINT64_C(0x000ffffffffff000)
static uint64_t before_pml4[512], before_pdpt[512], before_pd[MAX_GIB][512];
struct mapping { uint64_t physical, entry, page_bytes; unsigned pat_index; };
static struct mapping before_low[512];

static struct mapping mapping_at(uint64_t address)
{
    uint64_t *table = pml4;
    struct mapping result = {0};
    for (int shift = 39; shift >= 12; shift -= 9) {
        uint64_t entry = table[(address >> shift) & 511];
        CHECK(entry & UINT64_C(1));
        if (shift == 12 || ((shift == 30 || shift == 21) && (entry & UINT64_C(0x80)))) {
            const uint64_t page_bytes = UINT64_C(1) << shift;
            const uint64_t base_mask = HOST_ADDRESS_MASK & ~(page_bytes - 1);
            result.physical = (entry & base_mask) | (address & (page_bytes - 1));
            result.entry = entry;
            result.page_bytes = page_bytes;
            result.pat_index = (unsigned)((entry >> 3) & 3) |
                               (unsigned)(((entry >> (shift == 12 ? 7 : 12)) & 1) << 2);
            return result;
        }
        CHECK(shift > 12 && !(entry & UINT64_C(0x80)));
        table = (uint64_t *)(uintptr_t)(entry & HOST_ADDRESS_MASK);
    }
    CHECK(0 && "present identity mapping must have a leaf");
    return result;
}

static void exact_uc(uint64_t address)
{
    struct mapping mapped = mapping_at(address);
    CHECK(mapped.physical == address);
    CHECK(mapped.page_bytes == 4096);
    CHECK((mapped.entry & UINT64_C(3)) == UINT64_C(3));
    CHECK(((inherited_pat >> (mapped.pat_index * 8)) & 255) == 0);
}

static void verify_assigned(void)
{
    for (uint64_t address = UINT64_C(0xa0000); address < UINT64_C(0xc0000); address += 4096)
        exact_uc(address);
    exact_uc(UINT64_C(0xa0000)); exact_uc(UINT64_C(0xbffff));
    for (uint64_t address = LFB_BASE; address < LFB_BASE + LFB_BYTES; address += 4096)
        exact_uc(address);
    exact_uc(LFB_BASE + LFB_BYTES - 1);
}

void write_cr3(uint64_t value)
{
    CHECK(value == (uint64_t)(uintptr_t)pml4 && value == active_cr3);
    CHECK(pat_reads > 0 && pat_writes == 0);
    /* A flush may occur only after both complete mappings are ready. */
    verify_assigned(); ++cr3_writes;
}

static void snapshot_tables(void)
{
    memcpy(before_pml4, pml4, sizeof pml4);
    memcpy(before_pdpt, pdpt, sizeof pdpt);
    memcpy(before_pd, pd, sizeof pd);
}

static void unchanged_tables(void)
{
    CHECK(!memcmp(before_pml4, pml4, sizeof pml4));
    CHECK(!memcmp(before_pdpt, pdpt, sizeof pdpt));
    CHECK(!memcmp(before_pd, pd, sizeof pd));
}

static void seed(uint64_t pat)
{
    /* Complete physical-memory descriptors at the offsets build_paging uses.
     * Both windows are deliberately marked RAM to expose cached baseline leaves;
     * this mapper fixture does not claim actual VGA BAR/RAM admission. */
    struct { uint32_t type, padding; uint64_t physical, virtual_address, pages, attributes; }
        map[2] = {{7, 0, 0, 0, 512, 0}, {7, 0, LFB_BASE, 0, LFB_BYTES / 4096, 0}};
    shz_info_t info;
    memset(&info, 0, sizeof info);
    memset(window_is_ram, 0, sizeof window_is_ram);
    info.memmap_base = (uintptr_t)map; info.memmap_bytes = sizeof map;
    info.memmap_desc_size = sizeof map[0];
    inherited_pat = pat; pat_reads = cr3_writes = pat_writes = 0;
    CHECK(build_paging(&info) == 4);
    active_cr3 = (uint64_t)(uintptr_t)pml4;
    snapshot_tables();
    for (unsigned page = 0; page < 512; ++page)
        before_low[page] = mapping_at((uint64_t)page * 4096);
}

static void preserve_neighbors(void)
{
    CHECK(!memcmp(before_pml4, pml4, sizeof pml4));
    CHECK(!memcmp(before_pdpt, pdpt, sizeof pdpt));
    unsigned changed_directories = 0;
    for (unsigned gig = 0; gig < MAX_GIB; ++gig)
        for (unsigned slot = 0; slot < 512; ++slot) {
            uint64_t base = ((uint64_t)gig << 30) | ((uint64_t)slot << 21);
            if (base == 0 || (base >= LFB_BASE && base < LFB_BASE + LFB_BYTES)) {
                CHECK((pd[gig][slot] & UINT64_C(3)) == UINT64_C(3));
                CHECK(!(pd[gig][slot] & UINT64_C(0x80)));
                ++changed_directories;
            } else CHECK(pd[gig][slot] == before_pd[gig][slot]);
        }
    CHECK(changed_directories == 9);
    for (unsigned page = 0; page < 512; ++page) {
        uint64_t address = (uint64_t)page * 4096;
        if (address >= UINT64_C(0xa0000) && address < UINT64_C(0xc0000)) continue;
        struct mapping after = mapping_at(address);
        CHECK(after.physical == before_low[page].physical);
        CHECK(after.pat_index == before_low[page].pat_index);
        CHECK((after.entry & UINT64_C(3)) == (before_low[page].entry & UINT64_C(3)));
    }
    CHECK(mapping_at(LFB_BASE - 4096).physical == LFB_BASE - 4096);
    CHECK(mapping_at(LFB_BASE + LFB_BYTES).physical == LFB_BASE + LFB_BYTES);
}

static void each_inherited_uc_slot(void)
{
    for (unsigned uc_slot = 0; uc_slot < 8; ++uc_slot) {
        uint64_t pat = UINT64_C(0x0606060606060606);
        pat &= ~(UINT64_C(255) << (uc_slot * 8));
        seed(pat);
        CHECK(platform_vga_uc(LFB_BASE, LFB_BYTES) == 0);
        CHECK(inherited_pat == pat && pat_writes == 0 && pat_reads > 0 && cr3_writes > 0);
        verify_assigned(); preserve_neighbors();
        snapshot_tables();
        CHECK(platform_vga_uc(LFB_BASE, LFB_BYTES) == 0);
        unchanged_tables(); verify_assigned(); preserve_neighbors();
        unsigned old_flushes = cr3_writes;
        CHECK(platform_vga_uc(UINT64_C(0xd0000000), LFB_BYTES) == -1);
        CHECK(cr3_writes == old_flushes && inherited_pat == pat && pat_writes == 0);
        unchanged_tables(); verify_assigned(); preserve_neighbors();
    }
}

static void invalid_admission_never_mutates(void)
{
    static const struct { uint64_t base, bytes; } bad[] = {
        {0, LFB_BYTES}, {1, LFB_BYTES}, {UINT64_C(0x07000000), LFB_BYTES},
        {LFB_BASE + 4096, LFB_BYTES}, {UINT64_C(0x100000000), LFB_BYTES},
        {UINT64_C(0xffffffffff000000), LFB_BYTES}, {LFB_BASE, 0},
        {LFB_BASE, LFB_BYTES - 4096}, {LFB_BASE, LFB_BYTES * 2}
    };
    for (unsigned index = 0; index < sizeof bad / sizeof bad[0]; ++index) {
        seed(UINT64_C(0x0007040600070406));
        CHECK(platform_vga_uc(bad[index].base, bad[index].bytes) == -1);
        CHECK(cr3_writes == 0 && pat_writes == 0);
        unchanged_tables();
    }
    /* UC-minus (7) is not UC (0), and must not silently substitute for it. */
    seed(UINT64_C(0x0706060504040101));
    CHECK(platform_vga_uc(LFB_BASE, LFB_BYTES) == -1);
    CHECK(pat_reads > 0 && cr3_writes == 0 && pat_writes == 0);
    unchanged_tables();
}

int main(void)
{
    invalid_admission_never_mutates(); each_inherited_uc_slot();
    printf("PASS %u production VGA host-PTE PAT/extent/neighbor/flush checks; privileged boundaries mocked, no VM\n", checks);
    return 0;
}
