/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_RESOURCE_NATIVE_BRIDGE_H
#define NTW_RESOURCE_NATIVE_BRIDGE_H
#include "../win32_adapter.h"
typedef struct nrb_registry {
 const struct nrb_registry *self;
 nra_adapter adapter;
 nr_resources resource[NRA_MODULES];
 const void *owner[NRA_MODULES],*base[NRA_MODULES];
 int initialized,bound;
} nrb_registry;
/* The real loader supplies stable module objects and actual mapped bases.
 * All operations occur under its lock after graph protection and before any
 * attach. Registration failure is unpublished; retained mappings outlive every
 * detach/resource call. Disposal precedes freeing files/maps/loader storage.
 * No allocator, synthetic module IDs, free/refcount emulation or ABA detection.
 */
int nrb_init(nrb_registry *,nra_read,nra_error,void *);
int nrb_add(nrb_registry *,const void *,const np_image *,const void *,int,const char **);
int nrb_remove(nrb_registry *,const void *);
int nrb_publish(nrb_registry *);
int nrb_dispose(nrb_registry *);
int nrb_owned(const nrb_registry *,const void *,const void *);
int nrb_verify_file(const char *,const void *,uint32_t);
#endif
