/* SPDX-License-Identifier: GPL-2.0-only */
#include "k64.h"
#include "kernel_ap_work.h"
void shz_ap_work_init(shz_ap_work_pool_t *p,uint64_t mask)
{ memset(p,0,sizeof *p);p->mask=mask;p->state=SHZ_AP_WORK_PREPARED; }
int shz_ap_work_start_locked(shz_ap_work_pool_t *p,uint64_t mask)
{
    if(!p || p->state!=SHZ_AP_WORK_PREPARED || !mask || (mask&1) || (mask>>32) || mask!=p->mask) return -1;
    p->state=SHZ_AP_WORK_RUNNING;return 0;
}
int shz_ap_work_submit_locked(shz_ap_work_pool_t *p,const void *data,unsigned bytes,uint64_t mask,uint64_t *cookie)
{
    if(!p || p->state!=SHZ_AP_WORK_RUNNING || !data || !cookie || !bytes || bytes>SHZ_AP_WORK_BYTES ||
       !mask || (mask&~p->mask) || p->submitted==UINT64_MAX) return -1;
    for(unsigned i=0;i<SHZ_AP_WORK_SLOTS;i++) {
        shz_ap_work_job_t *j=&p->job[i];
        if(j->state!=SHZ_AP_JOB_FREE || j->generation>=SHZ_AP_WORK_MAX_GENERATION) continue;
        ++j->generation;j->cookie=(j->generation<<4)|i;j->mask=mask;j->bytes=bytes;
        j->worker=j->digest=0;j->cpu=UINT32_MAX;memcpy(j->payload,data,bytes);
        j->state=SHZ_AP_JOB_QUEUED;++p->occupied;++p->submitted;*cookie=j->cookie;return 0;
    }
    return -2;
}
int shz_ap_work_claim_locked(shz_ap_work_pool_t *p,unsigned cpu,uint64_t worker,unsigned *slot)
{
    if(!p || !slot || !worker || !cpu || cpu>=32 || !(p->mask&(1ull<<cpu)) ||
       (p->state!=SHZ_AP_WORK_RUNNING && p->state!=SHZ_AP_WORK_DRAINING)) return 0;
    for(unsigned i=0;i<SHZ_AP_WORK_SLOTS;i++) {
        shz_ap_work_job_t *j=&p->job[i];
        if(j->state!=SHZ_AP_JOB_QUEUED || !(j->mask&(1ull<<cpu))) continue;
        j->worker=worker;j->cpu=cpu;j->state=SHZ_AP_JOB_RUNNING;*slot=i;return 1;
    }
    return 0;
}
int shz_ap_work_complete_locked(shz_ap_work_pool_t *p,unsigned slot,uint64_t cookie,unsigned cpu,uint64_t worker,uint64_t digest)
{
    if(!p || slot>=SHZ_AP_WORK_SLOTS || p->completed==UINT64_MAX) return -1;
    shz_ap_work_job_t *j=&p->job[slot];
    if(j->state!=SHZ_AP_JOB_RUNNING || j->cookie!=cookie || j->cpu!=cpu || j->worker!=worker) return -1;
    j->digest=digest;j->state=SHZ_AP_JOB_DONE;++p->completed;return 0;
}
int shz_ap_work_poll_locked(const shz_ap_work_pool_t *p,uint64_t cookie,uint64_t *digest)
{
    if(!p || !digest || !(cookie>>4)) return -1;
    const shz_ap_work_job_t *j=&p->job[cookie&15];
    if(j->state==SHZ_AP_JOB_FREE || j->cookie!=cookie) return -1;
    if(j->state!=SHZ_AP_JOB_DONE) return 0;
    *digest=j->digest;return 1;
}
int shz_ap_work_release_locked(shz_ap_work_pool_t *p,uint64_t cookie)
{
    if(!p || !(cookie>>4)) return -1;
    shz_ap_work_job_t *j=&p->job[cookie&15];
    if(j->state!=SHZ_AP_JOB_DONE || j->cookie!=cookie || !p->occupied) return -1;
    j->state=SHZ_AP_JOB_FREE;--p->occupied;return 0;
}
int shz_ap_work_drain_locked(shz_ap_work_pool_t *p)
{
    if(!p || p->state!=SHZ_AP_WORK_RUNNING) return -1;
    p->state=SHZ_AP_WORK_DRAINING;return 0;
}
void shz_ap_work_fail_locked(shz_ap_work_pool_t *p)
{ if(p) p->state=SHZ_AP_WORK_FAILED; }
unsigned shz_ap_work_pending_locked(const shz_ap_work_pool_t *p)
{
    unsigned n=0;if(p) for(unsigned i=0;i<SHZ_AP_WORK_SLOTS;i++)
        n+=p->job[i].state==SHZ_AP_JOB_QUEUED || p->job[i].state==SHZ_AP_JOB_RUNNING;
    return n;
}
uint64_t shz_ap_work_digest(const uint8_t *p,unsigned bytes)
{
    uint64_t h=14695981039346656037ull;
    if(!p || !bytes || bytes>SHZ_AP_WORK_BYTES) return 0;
    for(unsigned pass=0;pass<256;pass++)for(unsigned i=0;i<bytes;i++)h=(h^p[i])*1099511628211ull;
    return h;
}
