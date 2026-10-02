/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_COMMON_DEVICE_H
#define SHZ_COMMON_DEVICE_H
#include <stddef.h>
#include <stdint.h>

enum shz_result {
    SHZ_OK = 0, SHZ_INVALID = -1, SHZ_UNSUPPORTED = -2, SHZ_IO = -3,
    SHZ_TIMEOUT = -4, SHZ_REVOKED = -5, SHZ_BUSY = -6,
    SHZ_QUARANTINED = -7, SHZ_STALE = -8, SHZ_MALFORMED = -9,
    SHZ_CLOCK = -10, SHZ_NO_EVENT = -11, SHZ_CAPACITY = -12,
    SHZ_NOT_FOUND = -13
};
enum shz_device_state {
    SHZ_DEVICE_EMPTY, SHZ_DEVICE_STARTING, SHZ_DEVICE_RUNNING,
    SHZ_DEVICE_STOPPING, SHZ_DEVICE_SUSPENDED, SHZ_DEVICE_CLOSED,
    SHZ_DEVICE_QUARANTINED
};
#define SHZ_DEVICE_SLOTS 16u
struct shz_device_ops {
    void *context;
    /* Trusted resource manager verifies this immutable owner and generation.
     * All callbacks are bounded, serialized and non-reentrant. They never
     * accept an untrusted process pointer as ownership evidence. */
    int (*validate)(void *, uint64_t owner, uint64_t generation);
    int (*start)(void *); /* May leave published DMA on ANY error. */
    int (*close)(void *); /* OK only after real controller stop / DMA drain. */
    void (*release)(void *); /* Optional platform context release after close. */
};
struct shz_ticket { uint64_t generation, sequence; uint32_t slot; };
struct shz_device {
    struct shz_device_ops ops;
    uint64_t owner, generation, next_sequence;
    uint64_t slots[SHZ_DEVICE_SLOTS];
    uint32_t state, pending, target_suspend, release_done;
    int last_error;
};
/* Zero initialize; never copy/reset while live or quarantined. Serialized by
 * the real PnP/IRQ owner. Callbacks and backing MUST outlive quarantine. */
int shz_device_bind(struct shz_device *, const struct shz_device_ops *,
                    uint64_t owner, uint64_t generation);
int shz_device_start(struct shz_device *);
int shz_device_admit(struct shz_device *, struct shz_ticket *);
int shz_device_complete(struct shz_device *, const struct shz_ticket *);
/* Closes admission immediately. BUSY needs in-flight completion and retry.
 * Quarantine permits close retry only; no rebind/start/release is allowed. */
int shz_device_stop(struct shz_device *, int suspend);
int shz_device_resume(struct shz_device *);
#endif
