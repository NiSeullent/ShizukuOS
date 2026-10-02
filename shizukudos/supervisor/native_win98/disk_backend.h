/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_DISK_BACKEND_H
#define SHZ_WIN98_DISK_BACKEND_H
#include <stdint.h>
#define W98_DISK_BACKEND_OPTIN 0x50525354u
/* Supervisor-owned sector operations. Success means the entire operation
 * completed; failure may have modified physical storage. There is no rollback.
 * All callbacks and their context remain owned/alive for the ATA lifetime.
 * flush is mandatory and must implement a device persistence barrier. */
typedef struct {
    uint64_t bytes;
    void *opaque;
    int (*read_sector)(void *, uint32_t, uint8_t *);
    int (*write_sector)(void *, uint32_t, const uint8_t *);
    int (*flush)(void *);
} w98_disk_backend_t;
#endif
