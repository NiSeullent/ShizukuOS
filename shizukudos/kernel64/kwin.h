/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel file views (kwin.c): a read-only kernel mapping of a whole file, populated page by page on first touch.
 */
#ifndef K64_KWIN_H
#define K64_KWIN_H
#include "fs.h"

typedef struct kview {
    fsnode_t *node;
    uint64_t base;                  /* kernel virtual address of file offset 0 (KWIN slot) */
    uint64_t size, npages;
    uint64_t resident;              /* pages read so far */
    uint64_t io_errors;             /* pages that could not be read (mapped as zeros) */
    struct kview *next;
} kview_t;

kview_t *kview_get(fsnode_t *n);    /* the node's view, created on first use (NULL: directory, empty, no space) */
int kview_read(kview_t *v, uint64_t off, void *buf, uint64_t len);   /* copy through the view; -1 on I/O error */
int kwin_fault(uint64_t addr);      /* kernel #PF inside the KWIN slot: 1 when a view page was loaded */
uint64_t kwin_total_faults(void);
#endif
