/* SPDX-License-Identifier: GPL-2.0-only
 * Host (Linux) stand-ins for the few OS-facing internals the portable UCRT core calls. The core objects are linked with
 * every symbol prefixed "u_" (objcopy --prefix-symbols), so these definitions carry the prefix and nothing of the
 * core can bind to glibc by accident. */
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct { int err; unsigned long doserr; unsigned rand_next; char pad[4096]; } host_ptd;
static __thread host_ptd ptd = { 0, 0, 1, { 0 } };
int host_invalid_parameter_calls;

int *u_crt_errno_ptr(void) { return &ptd.err; }
unsigned long *u_crt_doserrno_ptr(void) { return &ptd.doserr; }
void *u_crt_getptd(void) { return &ptd; }
void u_crt_invalid_parameter(void) { ++host_invalid_parameter_calls; }
void *u_crt_malloc(size_t n) { return malloc(n ? n : 1); }
void *u_crt_calloc(size_t n, size_t m) { return calloc(n ? n : 1, m ? m : 1); }
void *u_crt_realloc(void *p, size_t n) { return realloc(p, n ? n : 1); }
void u_crt_free(void *p) { free(p); }
void u_crt_lock(int which) { (void)which; }
void u_crt_unlock(int which) { (void)which; }
void u_crt_dosmaperr(unsigned long e) { ptd.doserr = e; ptd.err = 22; }
int host_errno(void) { return ptd.err; }
void host_set_errno(int e) { ptd.err = e; }
