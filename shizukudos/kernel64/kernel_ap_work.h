/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed-operation descriptors. All *_locked calls require the existing
 * scheduler ticket. Payload computation alone runs outside that ticket. */
#ifndef SHZ_KERNEL_AP_WORK_H
#define SHZ_KERNEL_AP_WORK_H
#include <stdint.h>
#define SHZ_AP_WORK_SLOTS 16u
#define SHZ_AP_WORK_BYTES 4096u
#define SHZ_AP_WORK_MAX_GENERATION (UINT64_MAX >> 4)
enum { SHZ_AP_JOB_FREE,SHZ_AP_JOB_QUEUED,SHZ_AP_JOB_RUNNING,SHZ_AP_JOB_DONE };
enum { SHZ_AP_WORK_PREPARED,SHZ_AP_WORK_RUNNING,SHZ_AP_WORK_DRAINING,SHZ_AP_WORK_FAILED };
typedef struct {
    uint64_t generation,cookie,mask,digest,worker;
    uint32_t state,bytes,cpu;
    uint8_t payload[SHZ_AP_WORK_BYTES];
} shz_ap_work_job_t;
typedef struct {
    uint64_t mask,submitted,completed;
    uint32_t state,occupied;
    shz_ap_work_job_t job[SHZ_AP_WORK_SLOTS];
} shz_ap_work_pool_t;
void shz_ap_work_init(shz_ap_work_pool_t *,uint64_t mask);
int shz_ap_work_start_locked(shz_ap_work_pool_t *,uint64_t actual_mask);
int shz_ap_work_submit_locked(shz_ap_work_pool_t *,const void *,unsigned bytes,uint64_t mask,uint64_t *cookie);
int shz_ap_work_claim_locked(shz_ap_work_pool_t *,unsigned cpu,uint64_t worker,unsigned *slot);
int shz_ap_work_complete_locked(shz_ap_work_pool_t *,unsigned slot,uint64_t cookie,unsigned cpu,uint64_t worker,uint64_t digest);
int shz_ap_work_poll_locked(const shz_ap_work_pool_t *,uint64_t cookie,uint64_t *digest);
int shz_ap_work_release_locked(shz_ap_work_pool_t *,uint64_t cookie);
int shz_ap_work_drain_locked(shz_ap_work_pool_t *);
void shz_ap_work_fail_locked(shz_ap_work_pool_t *);
unsigned shz_ap_work_pending_locked(const shz_ap_work_pool_t *);
/* FNV-1a over exactly 256 traversals of the copied payload; no caller function,
 * shared pointer, allocation, callback or unbounded computation is admitted. */
uint64_t shz_ap_work_digest(const uint8_t *,unsigned bytes);
#endif
