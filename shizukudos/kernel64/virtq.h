/* SPDX-License-Identifier: GPL-2.0-only
 * Split virtqueue ring model (Virtio 1.2, OASIS, section 2.7 "Split Virtqueues"), written from the specification.
 *
 * This file is deliberately free of kernel dependencies (only <stdint.h>/<stddef.h>): the same code runs inside Kernel64
 * (virtio_pci.c hands it the ring memory and physical addresses) and inside the host unit test
 * (kernel64/host/test_virtq.c) against a simulated device. The caller owns the ring memory:
 *   descriptor table  16 * size bytes, 16-byte aligned
 *   available ring    6 + 2 * size (+2 for used_event) bytes, 2-byte aligned
 *   used ring         6 + 8 * size (+2 for avail_event) bytes, 4-byte aligned
 * Physical addresses are opaque 64-bit numbers here (the host test uses host pointers). Neither VIRTIO_F_RING_INDIRECT_DESC
 * nor VIRTIO_F_RING_EVENT_IDX is used: buffers are direct descriptor chains and interrupt/notification suppression is the
 * plain flags variant. One chain = a caller token ("cookie") that comes back from virtq_get_used() when the device
 * returns the chain. Not thread safe by itself: the transport serialises calls (interrupts off in the kernel).
 */
#ifndef K64_VIRTQ_H
#define K64_VIRTQ_H
#include <stdint.h>
#include <stddef.h>

#define VIRTQ_DESC_F_NEXT 1u
#define VIRTQ_DESC_F_WRITE 2u
#define VIRTQ_DESC_F_INDIRECT 4u
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1u
#define VIRTQ_USED_F_NO_NOTIFY 1u
#define VIRTQ_MAX_SIZE 32768u

typedef struct { uint64_t addr; uint32_t len; uint16_t flags; uint16_t next; } virtq_desc_t;
typedef struct { uint16_t flags; uint16_t idx; uint16_t ring[]; } virtq_avail_t;
typedef struct { uint32_t id; uint32_t len; } virtq_used_elem_t;
typedef struct { uint16_t flags; uint16_t idx; virtq_used_elem_t ring[]; } virtq_used_t;

typedef struct { uint64_t pa; uint32_t len; } virtq_sg_t;         /* one buffer of a chain (device-readable or -writable) */

typedef struct {
    uint16_t size;                          /* entries (power of two per the spec; any size works here) */
    uint16_t index;                         /* queue index at the device */
    virtq_desc_t *desc;
    virtq_avail_t *avail;
    virtq_used_t *used;
    uint64_t desc_pa, avail_pa, used_pa;    /* what the transport programs into the device */
    uint16_t free_head, num_free;
    uint16_t last_used_idx;                 /* next used->ring slot the driver has not consumed */
    uint16_t avail_pending;                 /* chains added since the last virtq_kick_prepare() */
    void **cookie;                          /* [size]: caller token of the chain headed by that descriptor */
    uint16_t *chain_len;                    /* [size]: descriptors in the chain headed there */
    uint64_t n_added, n_completed, n_kicks, n_kicks_suppressed;
} virtq_t;

static inline size_t virtq_desc_bytes(unsigned size) { return (size_t)size * sizeof(virtq_desc_t); }
static inline size_t virtq_avail_bytes(unsigned size) { return 6 + 2 * (size_t)size + 2; }
static inline size_t virtq_used_bytes(unsigned size) { return 6 + 8 * (size_t)size + 2; }

/* Memory ordering between the driver and the device (another host thread under QEMU, the DMA engine on real hardware). */
#define VIRTQ_MB() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define VIRTQ_RMB() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define VIRTQ_WMB() __atomic_thread_fence(__ATOMIC_RELEASE)

/* Initialises the ring over caller-provided, zeroed memory. Returns -1 for a bad size or a NULL area. */
int virtq_init(virtq_t *q, uint16_t index, uint16_t size, void *desc, uint64_t desc_pa, void *avail, uint64_t avail_pa,
               void *used, uint64_t used_pa, void **cookies, uint16_t *chain_len);
/* Adds one chain: `n_out` device-readable buffers followed by `n_in` device-writable ones (that order is what the
 * spec requires). Returns the head descriptor index, or -1 when fewer than n_out+n_in descriptors are free or the
 * chain is empty. The chain is exposed to the device in the available ring immediately (idx not yet published). */
int virtq_add(virtq_t *q, const virtq_sg_t *out, unsigned n_out, const virtq_sg_t *in, unsigned n_in, void *cookie);
/* Publishes every chain added since the last call (avail->idx). Returns 1 when the device wants a notification
 * (used->flags has no VIRTQ_USED_F_NO_NOTIFY), 0 when the notification can be skipped or nothing was added. */
int virtq_kick_prepare(virtq_t *q);
int virtq_has_used(const virtq_t *q);
/* Takes the next completed chain: returns its cookie and the number of bytes the device wrote into it (NULL when the
 * used ring has nothing new). Its descriptors go back to the free list. */
void *virtq_get_used(virtq_t *q, uint32_t *written);
void virtq_suppress_interrupts(virtq_t *q, int suppress);
static inline unsigned virtq_num_free(const virtq_t *q) { return q->num_free; }
#endif
