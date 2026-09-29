/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: block devices through the Kernel64 installer syscalls (ntdll stubs generated from kernel64/ntsys.h
 * SYSCALL_LIST_SETUP). See blkio.h.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include "blkio.h"
#include "../../kernel64/setup_abi.h"

LONG NTAPI NtShzSetupBlkQuery(ULONG_PTR index, void *info, ULONG_PTR size);
LONG NTAPI NtShzSetupBlkRead(ULONG_PTR index, ULONG_PTR lba, ULONG_PTR count, void *buf);
LONG NTAPI NtShzSetupBlkWrite(ULONG_PTR index, ULONG_PTR lba, ULONG_PTR count, const void *buf);
LONG NTAPI NtShzSetupBlkFlush(ULONG_PTR index);
LONG NTAPI NtShzSetupPower(ULONG_PTR action);

#define MAX_DEVS 32
static shz_setup_blk_info_t devs[MAX_DEVS];
static unsigned ndevs;

_Static_assert(BLKIO_MAX_SECTORS <= SHZ_SETUP_MAX_SECTORS, "per-call limit");

int blkio_init(void)
{
    ndevs = 0;
    while (ndevs < MAX_DEVS) {
        LONG st = NtShzSetupBlkQuery(ndevs, &devs[ndevs], sizeof devs[ndevs]);
        if (st == (LONG)0x8000001A) break;                          /* STATUS_NO_MORE_ENTRIES */
        if (st) return -1;
        ++ndevs;
    }
    return 0;
}

unsigned blkio_count(void *ctx) { (void)ctx; return ndevs; }

int blkio_info(void *ctx, unsigned i, plat_disk_t *o)
{
    unsigned k;
    (void)ctx;
    if (i >= ndevs) return -1;
    memset(o, 0, sizeof *o);
    for (k = 0; k < sizeof o->name - 1 && devs[i].name[k]; ++k) o->name[k] = devs[i].name[k];
    for (k = 0; k < sizeof o->serial - 1 && devs[i].serial[k]; ++k) o->serial[k] = devs[i].serial[k];
    o->sectors = devs[i].sectors;
    o->sector_size = devs[i].sector_size;
    o->flags = (devs[i].flags & SHZ_SETUP_BLK_PARTITION ? PLAT_DISK_PARTITION : 0) |
               (devs[i].flags & SHZ_SETUP_BLK_READONLY ? PLAT_DISK_READONLY : 0) |
               (devs[i].flags & SHZ_SETUP_BLK_REMOVABLE ? PLAT_DISK_REMOVABLE : 0);
    return 0;
}

int blkio_read(void *ctx, unsigned i, uint64_t lba, uint32_t n, void *buf)
{
    (void)ctx;
    return i < ndevs && !NtShzSetupBlkRead(devs[i].index, lba, n, buf) ? 0 : -1;
}

int blkio_write(void *ctx, unsigned i, uint64_t lba, uint32_t n, const void *buf)
{
    (void)ctx;
    return i < ndevs && !NtShzSetupBlkWrite(devs[i].index, lba, n, buf) ? 0 : -1;
}

int blkio_flush(void *ctx, unsigned i)
{
    (void)ctx;
    return i < ndevs && !NtShzSetupBlkFlush(devs[i].index) ? 0 : -1;
}

void blkio_power(int action) { NtShzSetupPower((ULONG_PTR)action); }
