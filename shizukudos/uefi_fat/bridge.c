/* SPDX-License-Identifier: GPL-2.0-only
 * Original read-only FAT/AHCI bridge. One owned device, synchronous callbacks.
 */
#include "bridge.h"
int sdfat_fat_now(void *user, uint64_t *out)
{
    struct sdfat_binding *b = user;
    int result;
    if (!b || !b->proof || !b->ticks || !out) return -1;
    result = sdfat_clock_sample(&b->clock, b->ticks(b->ticks_user), out);
    b->proof->clock_last_tsc = b->clock.last_tsc;
    b->proof->clock_fault = b->clock.fault;
    b->proof->clock_stagnant = b->clock.stagnant;
    return result;
}
uint64_t sdfat_ahci_now(void *user)
{
    struct sdfat_binding *b = user;
    uint64_t value;
    if (!b) return 0;
    value = b->clock.last_us;
    (void)sdfat_fat_now(b, &value);
    /* The immutable AHCI API has no clock-error return channel. Hold the last
     * valid reading: its finite poll limits and the external watchdog bound a
     * broken clock. Never fabricate time or report a clock-faulted read PASS. */
    return value;
}
int sdfat_read_sector(void *user, uint64_t lba, uint8_t out[512],
                      uint32_t remaining_us)
{
    struct sdfat_binding *b = user;
    uint64_t before, after;
    int result;
    if (!b || !b->disk || !b->proof || !out) return -1;
    if (remaining_us < SDFAT_READ_RESERVE_US ||
        sdfat_fat_now(b, &before) != 0) {
        ++b->proof->read_refusals;
        return -1;
    }
    ++b->proof->sector_reads;
    b->proof->last_lba_low = (uint32_t)lba;
    b->proof->last_lba_high = (uint32_t)(lba >> 32);
    result = ahci_read_sector(b->disk, lba, out, NTWF_SECTOR_BYTES);
    b->proof->read_result = (uint32_t)result;
    if (sdfat_fat_now(b, &after) != 0) return -1;
    if (after < before || after - before >= remaining_us) {
        ++b->proof->read_overruns;
        return -1;
    }
    return result == AHCI_OK ? 0 : -1;
}
