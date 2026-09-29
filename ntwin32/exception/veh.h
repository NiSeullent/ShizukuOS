/* SPDX-License-Identifier: GPL-2.0-only
 * Portable ReactOS-reference handler core. This is NOT a Win32 exported ABI.
 * See PROVENANCE.md and README.md for port changes and native binding gaps.
 */
#ifndef NTWE_VEH_H
#define NTWE_VEH_H
#include <stddef.h>
#include <stdint.h>
#define NTWE_MAX_HANDLERS 128u
#define NTWE_MAX_DISPATCHES 64u
#define NTWE_CONTINUE_SEARCH 0
#define NTWE_CONTINUE_EXECUTION (-1)
enum ntwe_kind { NTWE_EXCEPTION=0, NTWE_CONTINUE=1 };
enum ntwe_status { NTWE_OK=0, NTWE_PENDING=1, NTWE_INVALID=-1,
    NTWE_NO_MEMORY=-2, NTWE_LIMIT=-3, NTWE_NOT_FOUND=-4, NTWE_CLOSED=-5 };
typedef uint32_t ntwe_handle;
typedef struct ntwe_pointers { void *exception_record; void *context_record; } ntwe_pointers;
typedef int32_t (*ntwe_handler)(ntwe_pointers *exception, void *user);
typedef struct ntwe_ops {
    void *user;
    void *(*allocate)(void *user,size_t bytes);
    void (*release)(void *user,void *allocation,size_t bytes);
    void (*lock)(void *user);
    void (*unlock)(void *user);
} ntwe_ops;
struct ntwe_node;
typedef struct ntwe_registry {
    ntwe_ops ops;
    struct ntwe_node *head[2], *tail[2];
    uint32_t count[2], dispatches, next_handle, closed;
} ntwe_registry;
typedef struct ntwe_stats { uint32_t exception_count,continue_count,dispatches,closed; } ntwe_stats;

/* Init/reinit and registry storage lifetime require external exclusion.
 * Other operations are concurrent-safe under the supplied lock. Callbacks,
 * allocators and release callbacks are always invoked outside that lock.
 * Callback code/user data and record/context must remain valid until all
 * potentially reserving dispatch calls return; remove never waits for them.
 * Callbacks must return normally (no longjmp/foreign unwind through this C).
 */
int ntwe_init(ntwe_registry *registry,const ntwe_ops *ops);
int ntwe_add(ntwe_registry *,enum ntwe_kind,int first,ntwe_handler,void *,ntwe_handle *out);
int ntwe_remove(ntwe_registry *,enum ntwe_kind,ntwe_handle);
int ntwe_dispatch(ntwe_registry *,enum ntwe_kind,void *record,void *context,int32_t *out_disposition);
int ntwe_get_stats(ntwe_registry *,ntwe_stats *out);
/* Close rejects subsequent add/dispatch and detaches both lists. PENDING
 * means dispatch references are still live; repeat after dispatch threads join.
 * Even OK does not authorize freeing registry storage while another public
 * call is in progress (e.g. its allocator), or while callers can enter again.
 */
int ntwe_close(ntwe_registry *);
#endif
