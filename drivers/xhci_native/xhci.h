/* SPDX-License-Identifier: GPL-2.0-only -- independently authored. */
#ifndef SHIZUKU_XHCI_NATIVE_H
#define SHIZUKU_XHCI_NATIVE_H
#include <stddef.h>
#include <stdint.h>

#define XHCI_DMA_BYTES 4096u
#define XHCI_COMMAND_OFFSET 2048u
#define XHCI_COMMAND_TRBS 16u
#define XHCI_EVENT_OFFSET 2304u
#define XHCI_EVENT_TRBS 64u
#define XHCI_ERST_OFFSET 3328u
#define XHCI_POLL_LIMIT 1000000u

enum xhci_result {
    XHCI_OK=0, XHCI_INVALID=-1, XHCI_UNSUPPORTED=-2, XHCI_IO=-3,
    XHCI_TIMEOUT=-4, XHCI_NO_MEMORY=-5, XHCI_CONTROLLER_ERROR=-6,
    XHCI_BAD_EVENT=-7, XHCI_COMPLETION_ERROR=-8, XHCI_QUARANTINED=-9,
    XHCI_CLOCK=-10, XHCI_EVENT_LIMIT=-11
};
enum xhci_state { XHCI_EMPTY=0, XHCI_STARTING, XHCI_READY, XHCI_CLOSED, XHCI_RETAINED };
struct xhci_dma { void *cpu; uint64_t bus; size_t bytes; };
/* Trusted serialized kernel callbacks: no user pointers or implicit DMA mapping.
 * MMIO write failure may happen after the write took effect. Allocation success
 * transfers ownership even if malformed; failure transfers no allocation.
 * DMA is coherent, disjoint, stable and contiguous; sync also orders CPU/MMIO.
 * release is infallible. now_us is monotonic; relax is bounded/non-reentrant. */
struct xhci_ops {
    void *context;
    int (*read32)(void *,uint32_t,uint32_t *);
    int (*write32)(void *,uint32_t,uint32_t);
    int (*allocate)(void *,size_t,size_t,uint64_t,struct xhci_dma *);
    void (*release)(void *,struct xhci_dma *);
    int (*sync)(void *,const struct xhci_dma *,size_t,size_t,int);
    uint64_t (*now_us)(void *);
    void (*relax)(void *);
    int (*write8)(void *,uint32_t,uint8_t); /* optional unless legacy handoff exists */
};
struct xhci_config {
    uint32_t pci_class;       /* 0x0c0330 */
    uint32_t pci_command;     /* memory decoding + bus mastering already enabled */
    uint32_t mmio_bytes;      /* verified mapped BAR aperture */
    uint32_t timeout_us;      /* 1..30000000 per reset/command */
    uint32_t exclusive;       /* must be 1: exclusive ownership of entire xHC */
};
/* Zero initialize; never copy a live device. Retained DMA must remain allocated
 * until a later xhci_close confirms halt/reset. No concurrent/IRQ invocation. */
struct xhci_device {
    struct xhci_ops ops;
    struct xhci_dma dma;
    uint64_t last_completion_pointer;
    uint32_t state,mmio_bytes,timeout_us,version,op_base,runtime_base,doorbell_base;
    uint32_t hccparams1,max_slots,max_ports,max_interrupters,scratchpads;
    uint32_t legacy_base,legacy_owned;
    uint32_t dma_owned,dma_published,command_index,command_cycle,event_index,event_cycle;
    uint32_t last_status,last_completion_code,commands_completed,port_events;
    int last_error;
};
int xhci_open(struct xhci_device *,const struct xhci_ops *,const struct xhci_config *);
int xhci_noop(struct xhci_device *);
int xhci_close(struct xhci_device *);
#endif
