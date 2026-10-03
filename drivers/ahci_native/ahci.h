/* SPDX-License-Identifier: GPL-2.0-only -- independent AHCI core: read, and opt-in write + cache flush. */
#ifndef NTW_AHCI_NATIVE_H
#define NTW_AHCI_NATIVE_H
#include <stddef.h>
#include <stdint.h>

#define AHCI_DMA_BYTES 4096u
#define AHCI_SECTOR_BYTES 512u
#define AHCI_MAX_SECTORS 4u /* remaining 2 KiB of the existing 4 KiB DMA arena */
#define AHCI_AUTO_PORT 32u
#define AHCI_POLL_LIMIT 1000000u
enum ahci_result {
    AHCI_OK = 0, AHCI_INVALID = -1, AHCI_UNSUPPORTED = -2,
    AHCI_IO = -3, AHCI_TIMEOUT = -4, AHCI_NO_MEMORY = -5,
    AHCI_NO_DEVICE = -6, AHCI_DEVICE_ERROR = -7, AHCI_BUSY = -8,
    AHCI_QUARANTINED = -9, AHCI_BAD_IDENTIFY = -10, AHCI_CLOCK = -11
};
enum ahci_state {
    AHCI_EMPTY = 0, AHCI_STARTING, AHCI_READY, AHCI_CLOSED, AHCI_RETAINED
};
struct ahci_dma { void *cpu; uint64_t bus; size_t bytes; };
struct ahci_ops {
    void *context;
    /* MMIO offsets are relative to ABAR. Failures may occur after a write. */
    int (*read32)(void *, uint32_t offset, uint32_t *value);
    int (*write32)(void *, uint32_t offset, uint32_t value);
    /* Allocate stable contiguous DMA memory, honouring max_bus inclusively.
     * Success transfers ownership, even if the returned block is malformed.
     * Failure transfers nothing. Do not use a virtual address as a bus address. */
    int (*allocate)(void *, size_t bytes, size_t alignment, uint64_t max_bus,
                    struct ahci_dma *block);
    void (*release)(void *, struct ahci_dma *block);
    /* DMA-coherent allocation is required. sync provides compiler/CPU ordering
     * and any platform synchronization: to_device=1, to_cpu=0. */
    int (*sync)(void *, const struct ahci_dma *, size_t offset, size_t bytes,
                int to_device);
    uint64_t (*now_us)(void *); /* monotonic elapsed wall time, not loop count */
    void (*relax)(void *);     /* bounded; no driver reentry */
};
struct ahci_config {
    uint32_t pci_class;       /* exactly 0x010601: storage/SATA/AHCI */
    uint32_t pci_command;     /* caller already enabled memory + bus mastering */
    uint32_t abar_bytes;      /* size of exclusively mapped MMIO BAR */
    uint32_t port;            /* 0..31 or AHCI_AUTO_PORT */
    uint32_t command_timeout_us; /* 1..30,000,000; engine stop gets 500 ms */
    uint32_t exclusive;       /* must be 1: whole HBA belongs to this caller */
    uint32_t allow_write;     /* 0: read-only (writes/flushes AHCI_UNSUPPORTED); 1: WRITE DMA EXT + FLUSH CACHE EXT */
};
#define AHCI_FEATURE_FLUSH_EXT 1u   /* IDENTIFY word 83 bit 13: FLUSH CACHE EXT supported */
#define AHCI_FEATURE_WRITE_CACHE 2u /* IDENTIFY word 85 bit 5: volatile write cache enabled */
struct ahci_identity {
    uint64_t sectors;
    uint32_t sector_bytes;
    uint32_t features;        /* AHCI_FEATURE_* */
    char model[41];
    char serial[21];         /* actual ATA IDENTIFY words10..19, empty if unavailable */
};
/* Zero initialize. No copying, concurrent calls, IRQ reentry or direct field
 * modification while live. Storage/callbacks must outlive retained DMA. */
struct ahci_device {
    struct ahci_ops ops;
    struct ahci_dma dma;
    struct ahci_identity identity;
    uint32_t state, cap, ports, version, port, port_base, abar_bytes;
    uint32_t timeout_us, dma_owned, dma_published, ownership_acquired, writable;
    uint32_t last_is, last_tfd, last_serr;
    int last_error;
    /* First deadline failure retained across safe port shutdown. Diagnostics
     * only: 1 elapsed deadline, 2 frozen-clock poll guard, 3 reversed clock. */
    uint64_t last_wait_elapsed_us;
    uint32_t last_wait_polls, last_wait_reason;
};

/* Takes over the HBA after firmware is finished with it. Stops all implemented
 * ports; leaves nonselected ports stopped. Does not restore firmware state. */
int ahci_open(struct ahci_device *, const struct ahci_ops *, const struct ahci_config *);
/* Only one 512-byte sector is supported. Output changes only after completion. */
int ahci_read_sector(struct ahci_device *, uint64_t lba, void *output, size_t bytes);
/* One command, 1..4 consecutive sectors within the identified capacity. Output
 * is changed only after successful completion and exact PRDBC validation. */
int ahci_read_sectors(struct ahci_device *, uint64_t lba, unsigned count,
                      void *output, size_t bytes);
/* Exactly one 512-byte sector (bytes must be 512). Needs allow_write=1 at open, else AHCI_UNSUPPORTED with no
 * device access. Success means the device reported completion; data may sit in a volatile write cache until
 * ahci_flush(). A failed write leaves the sector's content undefined (as on any interrupted ATA write). */
int ahci_write_sector(struct ahci_device *, uint64_t lba, const void *input, size_t bytes);
/* One WRITE DMA EXT, 1..4 consecutive sectors; bytes must equal count * 512.
 * Interrupted writes can leave any sector in this command partially written. */
int ahci_write_sectors(struct ahci_device *, uint64_t lba, unsigned count,
                       const void *input, size_t bytes);
/* FLUSH CACHE EXT: returns after the device reports its write cache written to media. AHCI_UNSUPPORTED without
 * allow_write or when IDENTIFY does not advertise the command (no device access in either case). */
int ahci_flush(struct ahci_device *);
/* On AHCI_QUARANTINED, DMA remains owned: retain context and call close again
 * after external recovery. Never release/reset the allocation behind this API. */
int ahci_close(struct ahci_device *);
/* Pure parser; useful before device policy is expanded. Output unchanged on failure. */
int ahci_parse_identify(const uint8_t data[512], struct ahci_identity *);
#endif
