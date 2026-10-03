/* SPDX-License-Identifier: GPL-2.0-only
 * Only privileged kernel boundaries replaced. Actual blk.h/registry/authority
 * bodies compile unchanged; pthread mutexes provide real host concurrency. */
#ifndef SHZ_BLK_AUTHORITY_HOST_SHIM_H
#define SHZ_BLK_AUTHORITY_HOST_SHIM_H
#define K64_H
#define K64_PCI_H
#define K64_PROC_INTERNAL_H
#include <stddef.h>
#include <stdint.h>
#include "../../abi/shz_abi.h"
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
typedef pthread_mutex_t kmutex_t;
void mutex_init(kmutex_t *);
void mutex_lock(kmutex_t *);
void mutex_unlock(kmutex_t *);
uint64_t irq_save(void);
void irq_restore(uint64_t);
void krandom_get(void *,size_t);
void kprintf(const char *,...);
void *kmalloc(size_t);
void *kzalloc(size_t);
uint64_t ticks_now(void);
uint64_t pmm_alloc(void);
void pmm_free(uint64_t);
#define PAGE_SIZE 4096u
void kfree(void *);
uint64_t kernel_pml4(void);
uint64_t p2v(uint64_t);
#define DIRECT_MAP 0xffff800000000000ull
#define PT_P 1ull
#endif
