/* SPDX-License-Identifier: GPL-2.0-only -- original xHCI USB HID interrupt-IN transport. */
#ifndef SHIZUKU_XHCI_HID_INTERRUPT_H
#define SHIZUKU_XHCI_HID_INTERRUPT_H
#include "xhci_usb.h"
#include "../shz_laptop/laptop.h"
/* Second controller session for one directly attached USB2 HID pointing device.
 * A caller first runs xhciu_probe_configuration (which closes its disposable
 * session), then re-opens the controller with xhci_open_one_slot and passes the
 * probe result here. This module resets the port again, re-reads and compares
 * the device descriptor and the whole configuration descriptor with the probe
 * result (a swapped or changed device is refused), sets the configuration,
 * reads and parses the HID report descriptor, issues Configure Endpoint and
 * keeps XHCIU_HID_DEPTH Normal TRBs queued on the interrupt-IN transfer ring.
 *
 * Ownership: the xhci_device stays exclusively owned by the handle until
 * xhciu_hid_close (which is xhci_close: controller halt+reset, DMA release;
 * a QUARANTINED result means the DMA lifetime continues). Everything is
 * serialized by the caller and runs in thread context only: xhciu_hid_poll
 * never blocks, it consumes events already posted to the event ring.
 * Not implemented, reported rather than guessed: hubs, SuperSpeed, endpoint
 * halt recovery (any non-success completion fails the handle), multiple
 * transactions per microframe, reports longer than 64 bytes, alternate
 * settings, SET_PROTOCOL/SET_IDLE (the device is port-reset into the default
 * report protocol). */
#define XHCIU_HID_ABI 1u
#define XHCIU_HID_DEPTH 8u
#define XHCIU_HID_RECOVERY_MAX 4u    /* halt recoveries per open session before the handle fails */
#define XHCIU_HID_REPORT_MAX 64u
#define XHCIU_HID_INT_RING 8704u      /* 16 TRBs, last is the Link TRB */
#define XHCIU_HID_BUFFERS 9216u       /* one 64-byte buffer per ring slot */
#define XHCIU_HID_CONTROL_BUFFER 10240u
#define XHCIU_HID_CONTROL_BYTES 2048u
enum xhciu_hid_status {
    XHCIU_HID_NO_POINTER=-200, XHCIU_HID_STALE=-201, XHCIU_HID_STATE=-202,
    XHCIU_HID_DESCRIPTOR=-203, XHCIU_HID_ENDPOINT=-204, XHCIU_HID_TRANSFER=-205,
    XHCIU_HID_SINK=-206
};
enum xhciu_hid_state { XHCIU_HID_CLOSED=0, XHCIU_HID_OPEN, XHCIU_HID_FAILED, XHCIU_HID_GONE };
/* Trusted sink; report returns 0 (accepted), >0 (this report refused, counted,
 * stream continues) or <0 (the consumer is revoked: the handle goes STALE). */
struct xhciu_hid_sink {
    void *context;
    int (*report)(void *,uint64_t generation,const struct shz_hid_layout *,
                  const uint8_t *,size_t);
};
struct xhciu_hid {
    struct xhci_device *x;
    struct xhciu_hid_sink sink;
    struct shz_hid_layout layout;
    uint64_t generation;
    uint32_t state,slot,port,speed,stride,iface,dci,mps,interval,config_value;
    uint32_t ep0_index,ep0_cycle,int_index,int_cycle,ep0_packet;
    uint32_t reports,refused,short_reports,port_events,polls;
    uint32_t last_code,recoveries;
    int last_error;
    uint8_t vendor_product[4];
};
/* x must be READY (xhci_open_one_slot) and exclusively owned. On any failure the
 * controller is closed (xhci_close) and the XHCI/XHCIU/XHCIU_HID error returned;
 * QUARANTINED is passed through. Output is unchanged until success. */
int xhciu_hid_open(struct xhciu_hid *,struct xhci_device *x,
                   const struct xhciu_configuration_descriptor *probed,
                   uint64_t generation,const struct xhciu_hid_sink *sink);
/* Consumes at most max_events posted events (1..256); *delivered counts reports
 * handed to the sink. Returns 0, or a negative error after which the handle is
 * FAILED/GONE and the caller should xhciu_hid_close. Never waits on hardware. */
int xhciu_hid_poll(struct xhciu_hid *,uint32_t max_events,uint32_t *delivered);
/* Caller-supplied generation must match the open generation (stale-handle check). */
int xhciu_hid_close(struct xhciu_hid *,uint64_t generation);
#endif
