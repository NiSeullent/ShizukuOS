/* SPDX-License-Identifier: GPL-2.0-only -- private shared original core helpers. */
#ifndef SHIZUKU_XHCI_INTERNAL_H
#define SHIZUKU_XHCI_INTERNAL_H
#include "xhci.h"
struct xhci_deadline { uint64_t start,last; uint32_t polls; };
struct xhci_event { uint32_t word[4]; };
uint32_t xhci_i_get32(const void *);
void xhci_i_put32(void *,uint32_t);
void xhci_i_put64(void *,uint64_t);
void xhci_i_zero(void *,size_t);
void xhci_i_copy(void *,const void *,size_t);
int xhci_i_read(struct xhci_device *,uint32_t,uint32_t *);
int xhci_i_write(struct xhci_device *,uint32_t,uint32_t);
int xhci_i_sync(struct xhci_device *,const struct xhci_dma *,size_t,size_t,int);
void xhci_i_begin(struct xhci_device *,struct xhci_deadline *);
int xhci_i_expired(struct xhci_device *,struct xhci_deadline *,uint32_t);
int xhci_i_health(struct xhci_device *);
int xhci_i_event(struct xhci_device *,struct xhci_deadline *,struct xhci_event *);
int xhci_i_ack(struct xhci_device *);
int xhci_i_command(struct xhci_device *,uint32_t,uint64_t,uint32_t,uint32_t *);
int xhci_i_fail(struct xhci_device *,int);
#endif
