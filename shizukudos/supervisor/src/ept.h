/* SPDX-License-Identifier: GPL-2.0-only
 * Per-domain extended page tables built from pool pages. Mappings are guest-physical
 * -> host-physical with explicit permissions and memory type, at 4 KiB or 2 MiB
 * granularity. A domain can therefore hold private RAM plus shared IPC windows and
 * still fault (EPT violation) on anything else.
 */
#ifndef SHZ_EPT_H
#define SHZ_EPT_H
#include <stdint.h>

#define EPT_R 1ull
#define EPT_W 2ull
#define EPT_X 4ull
#define EPT_RWX 7ull
#define EPT_WB (6ull << 3)
#define EPT_UC 0ull
#define EPT_WC (1ull << 3)                      /* EPT memory type 1: write-combining (guest PAT still applies) */

typedef struct {
    uint64_t *pml4;
    uint64_t pml4_pa;
    uint64_t mapped_bytes;
} ept_t;

int ept_init(ept_t *e);
/* Maps [gpa, gpa+size) to [hpa, ...). Uses 2 MiB leaves where both addresses and the
 * remaining size are 2 MiB aligned unless force_4k. Returns 0 or -1 (no memory/overlap). */
int ept_map(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t size, uint64_t perms_and_type, int force_4k);
/* Changes the host page behind one 4 KiB guest page (splits a 2 MiB leaf if needed). */
int ept_remap_page(ept_t *e, uint64_t gpa, uint64_t hpa, uint64_t perms_and_type);
uint64_t ept_pointer(const ept_t *e);            /* EPTP value: PML4 | walk length | WB */
void ept_invalidate(void);
#endif
