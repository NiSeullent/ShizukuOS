/* SPDX-License-Identifier: GPL-2.0-only */
#include "device.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static unsigned checks;
#undef assert
#define assert(x) do { ++checks; if(!(x)){fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x);abort();} } while(0)
struct backend { int valid, start_error, close_error; unsigned starts, closes, releases; int revoke_on_close; };
static int valid(void *p,uint64_t owner,uint64_t gen) {
    struct backend *b=p; return b->valid && owner==17 && gen>=1 ? SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int start(void *p) { struct backend *b=p; ++b->starts; return b->start_error; }
static int close_device(void *p) { struct backend *b=p; ++b->closes;if(b->revoke_on_close)b->valid=0; return b->close_error; }
static void release(void *p) { ++((struct backend *)p)->releases; }
static void bind(struct shz_device *d,struct backend *b,uint64_t gen) {
    struct shz_device_ops o={b,valid,start,close_device,release};
    assert(shz_device_bind(d,&o,17,gen)==SHZ_DRIVER_OK);
}
int main(void) {
    struct shz_device d={0}; struct backend b={1,0,0,0,0,0,0};
    struct shz_ticket a={0},c={0},old; unsigned i;
    bind(&d,&b,1); assert(shz_device_start(&d)==SHZ_DRIVER_OK);
    assert(shz_device_admit(&d,&a)==SHZ_DRIVER_OK); old=a;
    assert(shz_device_stop(&d,0)==SHZ_BUSY);
    assert(d.state==SHZ_DEVICE_STOPPING && b.closes==0);
    assert(shz_device_admit(&d,&c)==SHZ_BUSY);
    assert(shz_device_complete(&d,&a)==SHZ_DRIVER_OK);
    assert(shz_device_complete(&d,&a)==SHZ_STALE);
    b.close_error=SHZ_TIMEOUT;
    assert(shz_device_stop(&d,0)==SHZ_QUARANTINED);
    assert(d.state==SHZ_DEVICE_QUARANTINED && b.releases==0);
    assert(shz_device_start(&d)==SHZ_BUSY);
    { struct shz_device_ops o={&b,valid,start,close_device,release};
      assert(shz_device_bind(&d,&o,17,2)==SHZ_BUSY); }
    b.valid=0; b.close_error=0;
    assert(shz_device_stop(&d,0)==SHZ_QUARANTINED);
    assert(b.closes==1 && b.releases==0);
    b.valid=1; assert(shz_device_stop(&d,0)==SHZ_DRIVER_OK);
    assert(b.closes==2 && b.releases==1);
    assert(shz_device_stop(&d,0)==SHZ_DRIVER_OK && b.releases==1);
    bind(&d,&b,2); assert(shz_device_start(&d)==SHZ_DRIVER_OK);
    assert(shz_device_complete(&d,&old)==SHZ_STALE);
    assert(shz_device_admit(&d,&a)==SHZ_DRIVER_OK);
    c=a; ++c.sequence;
    assert(shz_device_complete(&d,&c)==SHZ_STALE && d.pending==1);
    assert(shz_device_stop(&d,1)==SHZ_BUSY);
    assert(shz_device_complete(&d,&a)==SHZ_DRIVER_OK);
    assert(shz_device_stop(&d,1)==SHZ_DRIVER_OK && b.releases==1);
    assert(d.state==SHZ_DEVICE_SUSPENDED);
    assert(shz_device_resume(&d)==SHZ_DRIVER_OK && b.starts==3);
    for(i=0;i<SHZ_DEVICE_SLOTS;i++) assert(shz_device_admit(&d,&a)==SHZ_DRIVER_OK);
    assert(shz_device_admit(&d,&c)==SHZ_CAPACITY);
    for(i=0;i<SHZ_DEVICE_SLOTS;i++) {
        a.generation=2; a.sequence=d.slots[i]; a.slot=i;
        assert(shz_device_complete(&d,&a)==SHZ_DRIVER_OK);
    }
    b.valid=0; memset(&c,0xa5,sizeof(c)); a=c;
    assert(shz_device_admit(&d,&c)==SHZ_REVOKED);
    assert(memcmp(&a,&c,sizeof(a))==0 && d.pending==0);
    b.valid=1; assert(shz_device_stop(&d,0)==SHZ_DRIVER_OK);
    bind(&d,&b,3); b.start_error=SHZ_IO; b.close_error=SHZ_TIMEOUT;
    assert(shz_device_start(&d)==SHZ_QUARANTINED && b.releases==2);
    b.close_error=0; assert(shz_device_stop(&d,0)==SHZ_DRIVER_OK && b.releases==3);
    bind(&d,&b,4);b.start_error=0;assert(shz_device_start(&d)==SHZ_DRIVER_OK);
    d.next_sequence=UINT64_MAX;assert(shz_device_admit(&d,&a)==SHZ_CAPACITY && d.pending==0);
    b.revoke_on_close=1;
    assert(shz_device_stop(&d,0)==SHZ_QUARANTINED && b.releases==3);
    assert(d.state==SHZ_DEVICE_QUARANTINED);
    b.valid=1;b.revoke_on_close=0;
    assert(shz_device_stop(&d,0)==SHZ_DRIVER_OK && b.releases==4);
    printf("common lifecycle: %u assertions PASS\n",checks); return 0;
}
