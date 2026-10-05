/* SPDX-License-Identifier: GPL-2.0-only
 * SHZSETUP: block devices through the Kernel64 installer syscalls (ntdll stubs generated from kernel64/ntsys.h
 * SYSCALL_LIST_SETUP). See blkio.h.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include "blkio.h"
#include "../../kernel64/setup_abi.h"
#include "../../kernel64/setup_target_abi.h"
static int public_disk_info(unsigned,plat_disk_t *);
static int public_disk_io(unsigned,uint64_t,uint32_t,void *,int);
static int public_disk_flush(unsigned);

LONG NTAPI NtShzSetupBlkQuery(ULONG_PTR index, void *info, ULONG_PTR size);
LONG NTAPI NtShzSetupBlkRead(ULONG_PTR index, ULONG_PTR lba, ULONG_PTR count, void *buf);
LONG NTAPI NtShzSetupBlkWrite(ULONG_PTR index, ULONG_PTR lba, ULONG_PTR count, const void *buf);
LONG NTAPI NtShzSetupBlkFlush(ULONG_PTR index);
LONG NTAPI NtShzSetupPower(ULONG_PTR action);

#define MAX_DEVS 32
static shz_setup_blk_info_t devs[MAX_DEVS];
static unsigned ndevs;

_Static_assert(BLKIO_MAX_SECTORS <= SHZ_SETUP_MAX_SECTORS, "per-call limit");

int blkio_init(void)
{
    ndevs = 0;
    while (ndevs < MAX_DEVS) {
        LONG st = NtShzSetupBlkQuery(ndevs, &devs[ndevs], sizeof devs[ndevs]);
        if (st == (LONG)0x8000001A) break;                          /* STATUS_NO_MORE_ENTRIES */
        if (st) return -1;
        ++ndevs;
    }
    return 0;
}

unsigned blkio_count(void *ctx) { (void)ctx; return ndevs; }

int blkio_info(void *ctx, unsigned i, plat_disk_t *o)
{
    unsigned k;
    (void)ctx;
    {int rc=public_disk_info(i,o);if(rc<=0)return rc;}
    if (i >= ndevs || NtShzSetupBlkQuery(i,&devs[i],sizeof devs[i])) return -1;
    memset(o, 0, sizeof *o);
    for (k = 0; k < sizeof o->name - 1 && devs[i].name[k]; ++k) o->name[k] = devs[i].name[k];
    for (k = 0; k < sizeof o->serial - 1 && devs[i].serial[k]; ++k) o->serial[k] = devs[i].serial[k];
    o->sectors = devs[i].sectors;
    o->sector_size = devs[i].sector_size;
    o->flags = (devs[i].flags & SHZ_SETUP_BLK_PARTITION ? PLAT_DISK_PARTITION : 0) |
               (devs[i].flags & SHZ_SETUP_BLK_READONLY ? PLAT_DISK_READONLY : 0) |
               (devs[i].flags & SHZ_SETUP_BLK_REMOVABLE ? PLAT_DISK_REMOVABLE : 0);
    return 0;
}

int blkio_read(void *ctx, unsigned i, uint64_t lba, uint32_t n, void *buf)
{
    (void)ctx;
    {int rc=public_disk_io(i,lba,n,buf,0);if(rc<=0)return rc;}
    return i < ndevs && !NtShzSetupBlkRead(devs[i].index, lba, n, buf) ? 0 : -1;
}

int blkio_write(void *ctx, unsigned i, uint64_t lba, uint32_t n, const void *buf)
{
    (void)ctx;
    {int rc=public_disk_io(i,lba,n,(void *)(uintptr_t)buf,1);if(rc<=0)return rc;}
    return i < ndevs && !NtShzSetupBlkWrite(devs[i].index, lba, n, buf) ? 0 : -1;
}

int blkio_flush(void *ctx, unsigned i)
{
    (void)ctx;
    {int rc=public_disk_flush(i);if(rc<=0)return rc;}
    return i < ndevs && !NtShzSetupBlkFlush(devs[i].index) ? 0 : -1;
}

void blkio_power(int action) { NtShzSetupPower((ULONG_PTR)action); }

/* Public prepared-archive target authority. The wire and role semantics are
 * provided by the existing kernel storage authority; no UI approval flag or
 * ordinal/name is accepted as a write capability. Private 0xb5 stays separate. */
__declspec(dllimport) int32_t __stdcall NtShzSetupTarget(shz_setup_target_call_v1 *,uint64_t);
static struct {
    int active,prepared,claimed,broken;
    uint32_t max_io;
    uint64_t sources[2],claim;
    shz_setup_target_source_v1 source_info[2];
    shz_setup_target_v1 wire;
    setup_plan_t plan;
} public_io;
static void target_init(shz_setup_target_call_v1 *r,unsigned op)
{memset(r,0,sizeof *r);r->version=SHZ_SETUP_TARGET_VERSION;r->bytes=sizeof *r;r->operation=op;}
static int target_call(shz_setup_target_call_v1 *r)
{return NtShzSetupTarget(r,sizeof *r)?-1:0;}
static int public_finish(void *unused);
static int public_source_check(unsigned i)
{
    shz_setup_target_call_v1 r;
    if(i>=2||!public_io.sources[i])return -1;
    target_init(&r,SHZ_SETUP_TARGET_INFO);r.handle=public_io.sources[i];
    return target_call(&r)||memcmp(&r.source,&public_io.source_info[i],sizeof r.source)?-1:0;
}
static int public_prepare(void *unused,const char *payload)
{
    shz_setup_target_call_v1 r;unsigned i;size_t n;char path[SHZ_SETUP_TARGET_PATH];(void)unused;
    if(public_io.active)return -1;
    memset(&public_io,0,sizeof public_io);public_io.active=1;
    target_init(&r,SHZ_SETUP_TARGET_CAPS);
    if(target_call(&r)||r.target_authority_available!=1||r.max_io_bytes<512||
       r.max_io_bytes>SHZ_SETUP_TARGET_IO_MAX||r.max_io_bytes%512||!r.max_source_bytes)goto fail;
    public_io.max_io=r.max_io_bytes;n=strlen(payload);
    if(n+1+13>=sizeof path)goto fail;
    for(i=0;i<2;++i){
        uint8_t any=0;unsigned j;
        memcpy(path,payload,n);path[n]='\\';strcpy(path+n+1,i?"ESP.SIM":"manifest.json");
        target_init(&r,SHZ_SETUP_TARGET_OPEN);r.index=i;strcpy(r.path,path);
        if(target_call(&r)||!r.handle)goto fail;
        public_io.sources[i]=r.handle;public_io.source_info[i]=r.source;
        for(j=0;j<16;++j)any|=r.source.id[j];
        if(!any||!r.source.generation||!r.source.bytes)goto fail;
        target_init(&r,SHZ_SETUP_TARGET_VALIDATE_SOURCE);r.handle=public_io.sources[i];r.index=i;
        if(target_call(&r)||memcmp(&r.source,&public_io.source_info[i],sizeof r.source)||public_source_check(i))goto fail;
    }
    public_io.prepared=1;return 0;
fail:
    public_io.broken=1;(void)public_finish(0);return -1;
}
static void reason_copy(char *dst,size_t cap,const char *value)
{size_t n=strlen(value);if(!cap)return;if(n>=cap)n=cap-1;memcpy(dst,value,n);dst[n]=0;}
static int public_review(void *unused,unsigned i,setup_target_t *target,char *reason,size_t cap)
{
    shz_setup_target_call_v1 r;plat_disk_t disk;shz_setup_blk_info_t raw;(void)unused;
    if(!target)return -1;
    memset(target,0,sizeof *target);target->index=i;
    if(NtShzSetupBlkQuery(i,&raw,sizeof raw)||blkio_info(0,i,&disk)){
        reason_copy(reason,cap,"Device no longer available");return -1;
    }
    target->disk=disk;
    if(disk.flags&PLAT_DISK_PARTITION){reason_copy(reason,cap,"Partition; choose a whole disk");return -1;}
    if(disk.flags&PLAT_DISK_READONLY){reason_copy(reason,cap,"Read-only, mounted, or source/system disk");return -1;}
    if(disk.flags&PLAT_DISK_REMOVABLE){reason_copy(reason,cap,"Removable target installation not supported in this version");return -1;}
    if(disk.sector_size!=512){reason_copy(reason,cap,"Unsupported sector size");return -1;}
    if(!public_io.prepared||public_io.claimed||public_io.broken||public_source_check(0)||public_source_check(1)){
        reason_copy(reason,cap,"Installer source authority unavailable");return -1;
    }
    target_init(&r,SHZ_SETUP_TARGET_REVIEW);r.handle=public_io.sources[0];r.other_handle=public_io.sources[1];r.index=i;
    if(target_call(&r)||r.target.sectors!=disk.sectors||r.target.sector_size!=disk.sector_size||
       (r.target.flags&15u)||!(r.target.flags&16u)){
        reason_copy(reason,cap,"Source/system disk, mounted volume, or target unavailable");return -1;
    }
    memcpy(target->whole_id,r.target.whole_id,16);target->generation=r.target.generation;target->authority_flags=r.target.flags;
    if(cap)reason[0]=0;
    return 0;
}
static int public_claim(void *unused,const setup_plan_t *plan)
{
    shz_setup_target_call_v1 r;setup_target_t current;char reason[160];(void)unused;
    if(!plan||public_io.claimed||!public_io.prepared||public_io.broken||
       public_review(0,plan->target.index,&current,reason,sizeof reason)||
       memcmp(&current,&plan->target,sizeof current)||
       memcmp(plan->image.manifest_sha256,public_io.source_info[0].sha256,32))return -1;
    target_init(&r,SHZ_SETUP_TARGET_CLAIM);r.handle=public_io.sources[0];r.other_handle=public_io.sources[1];r.index=current.index;
    memcpy(r.target.whole_id,current.whole_id,16);r.target.generation=current.generation;
    r.target.sectors=current.disk.sectors;r.target.sector_size=current.disk.sector_size;r.target.flags=current.authority_flags;
    if(target_call(&r)||!r.handle)return -1;
    public_io.claim=r.handle;public_io.wire=r.target;public_io.plan=*plan;public_io.claimed=1;return 0;
}
static int public_check(void *unused,const setup_plan_t *plan)
{
    shz_setup_target_call_v1 r;(void)unused;
    if(!plan||!public_io.claimed||public_io.broken||memcmp(plan,&public_io.plan,sizeof *plan)||
       public_source_check(0)||public_source_check(1))return -1;
    target_init(&r,SHZ_SETUP_TARGET_CHECK);r.handle=public_io.claim;r.target=public_io.wire;return target_call(&r);
}
static int public_release(void *unused)
{
    shz_setup_target_call_v1 r;int rc;(void)unused;
    if(!public_io.claimed)return -1;
    target_init(&r,SHZ_SETUP_TARGET_RELEASE);r.handle=public_io.claim;r.target=public_io.wire;
    rc=target_call(&r);public_io.claimed=0;public_io.claim=0;
    if(rc)public_io.broken=1;
    return rc;
}
static int public_finish(void *unused)
{
    unsigned i;int rc=0;(void)unused;
    if(public_io.claimed&&public_release(0))rc=-1;
    for(i=0;i<2;++i)if(public_io.sources[i]){
        shz_setup_target_call_v1 r;target_init(&r,SHZ_SETUP_TARGET_CLOSE);r.handle=public_io.sources[i];
        if(target_call(&r))rc=-1;
        public_io.sources[i]=0;
    }
    /* A failed close is not reported as kernel custody reaped. Process teardown
     * owns any unresolved handles and the UI returns failure. */
    public_io.prepared=0;return rc;
}
static int public_disk_info(unsigned i,plat_disk_t *out)
{
    if(!public_io.active)return 1;
    if(!public_io.claimed)return 1;
    if(i!=public_io.plan.target.index||public_check(0,&public_io.plan))return -1;
    *out=public_io.plan.target.disk;return 0;
}
static int public_disk_io(unsigned i,uint64_t lba,uint32_t count,void *buffer,int write)
{
    uint8_t *p=buffer;
    if(!public_io.active)return 1;
    if(!buffer||!count||!public_io.claimed||i!=public_io.plan.target.index||public_check(0,&public_io.plan)||
       lba>public_io.wire.sectors||count>public_io.wire.sectors-lba)return -1;
    while(count){shz_setup_target_call_v1 r;uint32_t n=count;
        if(n>public_io.max_io/512)n=public_io.max_io/512;
        target_init(&r,write?SHZ_SETUP_TARGET_WRITE_SECTORS:SHZ_SETUP_TARGET_READ_SECTORS);
        r.handle=public_io.claim;r.target=public_io.wire;r.offset=lba;
        r.buffer=(uint64_t)(uintptr_t)p;r.length=n*512;
        if(target_call(&r))return -1;
        p+=n*512;lba+=n;count-=n;
    }
    return 0;
}
static int public_disk_flush(unsigned i)
{
    shz_setup_target_call_v1 r;
    if(!public_io.active)return 1;
    if(!public_io.claimed||i!=public_io.plan.target.index||public_check(0,&public_io.plan))return -1;
    target_init(&r,SHZ_SETUP_TARGET_FLUSH);r.handle=public_io.claim;r.target=public_io.wire;return target_call(&r);
}
int blkio_public_backend(setup_ui_backend_t *b)
{
    if(!b)return -1;
    memset(b,0,sizeof *b);b->prepare=public_prepare;b->finish=public_finish;
    b->review=public_review;b->claim=public_claim;b->check=public_check;b->release=public_release;return 0;
}
