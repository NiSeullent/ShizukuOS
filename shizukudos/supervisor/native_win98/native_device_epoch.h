/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_NATIVE_DEVICE_EPOCH_H
#define SHZ_WIN98_NATIVE_DEVICE_EPOCH_H
#include <stdint.h>
#define W98_EPOCH_MAGIC 0x31454457u /* WDE1, little endian */
#define W98_EPOCH_VERSION 1u
#define W98_EPOCH_CHALLENGE 1u
#define W98_EPOCH_REPORT 2u
#define W98_EPOCH_GRANT 3u
#define W98_EPOCH_CHALLENGE_BYTES 48u
#define W98_EPOCH_REPORT_BYTES 256u
#define W98_EPOCH_GRANT_BYTES 272u
#define W98_EPOCH_MAX_IO_CALLS 4096u
#define W98_EPOCH_VGA 1u
#define W98_EPOCH_STORAGE 2u
#define W98_EPOCH_NEW 0u
#define W98_EPOCH_EXCHANGING 1u
#define W98_EPOCH_ADMITTED 2u
#define W98_EPOCH_FAILED 3u
/* BAR DWORD expectations are prospective values, not device authority. Sizes,
 * overlap, backing node/cache and actual owned process/peer are outer checks. */
typedef struct {
    uint16_t bdf,role,vendor,device;
    uint32_t class_code;
    uint16_t command_required,command_forbidden;
    uint32_t raw_bar[6];
} w98_epoch_device_t;
typedef struct {
    uint32_t count;
    uint8_t nonce[32],config_sha256[2][32],rom_sha256[32];
    w98_epoch_device_t device[2];
} w98_epoch_expect_t;
/* All callbacks are bounded, nonblocking and exclusively owned. Transport
 * returns consumed/delivered bytes (0 means no progress), or -1. No write to
 * PCI, VGA, MMIO, a reset register or DMA is expressible through this API. */
typedef struct {
    void *opaque;
    int (*pci_read)(void *,uint16_t,unsigned,uint32_t *);
    int (*receive)(void *,uint8_t *,unsigned);
    int (*send)(void *,const uint8_t *,unsigned);
    uint64_t (*now)(void *);
    void (*pause)(void *);
} w98_epoch_io_t;
typedef struct {
    uint32_t state,io_calls;
    uint8_t protocol_admitted,nonce_consumed;
    uint64_t deadline,last_now;
    w98_epoch_expect_t expected;
    w98_epoch_io_t io;
    uint8_t report[W98_EPOCH_REPORT_BYTES];
} w98_epoch_gate_t;
/* Caller owns a zero-initialized object for exactly one attempt; never clear
 * or reuse it within that process/resource epoch. deadline is the original
 * absolute deadline in now()'s monotonic units, never a duration to extend.
 * The expected nonce MUST come from a fresh actual owned host attempt. Passing
 * fixtures, an old nonce or a syntactically valid grant confers no physical
 * permission. Return0 establishes only this protocol's checks; future wiring
 * must separately prove the actual process/QMP/channel/resource provenance. */
int w98_native_epoch_gate(w98_epoch_gate_t *,const w98_epoch_expect_t *,
                          const w98_epoch_io_t *,uint64_t deadline);
#endif
