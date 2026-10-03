/* SPDX-License-Identifier: GPL-2.0-only */
#include "laptop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
struct sink { int valid,error;unsigned calls;int32_t x,y;uint8_t buttons; };
static int validate(void *context,uint64_t owner,uint64_t generation) {
    struct sink *s=context;return s->valid && owner==7 && generation==9?SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int emit(void *context,int32_t x,int32_t y,uint8_t buttons) {
    struct sink *s=context;if(s->error)return s->error;
    ++s->calls;s->x=x;s->y=y;s->buttons=buttons;return SHZ_DRIVER_OK;
}
static struct shz_pointer point(int32_t x,int32_t y,int relative,uint16_t id) {
    struct shz_pointer p={0};p.count=1;p.relative=(uint8_t)relative;
    p.contacts[0]=(struct shz_contact){x,y,id,1,1,1};return p;
}
static void descriptor_classes(struct shz_pointer_adapter *a,struct sink *s) {
    /* Genuine short-item descriptors: one touchpad Application and unrelated
     * keyboard/sensor Applications with separate IDs, plus mixed-axis mouse. */
    const uint8_t composite[]={
        0x05,0x0d,0x09,5,0xa1,1,0x85,1,0x09,0x42,0x15,0,0x25,1,
        0x75,1,0x95,1,0x81,2,0x75,7,0x81,1,0x05,1,0x09,0x30,0x09,0x31,
        0x75,8,0x95,2,0x25,0x7f,0x81,2,0xc0,
        0x05,1,0x09,6,0xa1,1,0x85,2,0x05,7,0x09,1,0x15,0,0x25,1,
        0x75,8,0x95,1,0x81,2,0xc0,
        0x05,1,0x09,4,0xa1,1,0x85,3,0x09,0x30,0x09,0x31,0x25,0x7f,
        0x75,8,0x95,2,0x81,2,0xc0};
    const uint8_t mixed[]={0x05,1,0x09,2,0xa1,1,0x09,0x30,0x15,0x81,0x25,0x7f,
        0x75,8,0x95,1,0x81,6,0x09,0x31,0x81,2,0xc0};
    const uint8_t pad[]={1,1,50,60},keyboard[]={2,1},sensor[]={3,10,100},axes[]={1,100};
    struct shz_hid_layout l;struct shz_pointer_adapter old;unsigned calls;
    C(shz_hid_parse_report(composite,sizeof composite,&l)==SHZ_DRIVER_OK && l.touchpad);
    C(l.report_count==3 && l.reports[0].pointer_class==2 && l.reports[1].pointer_class==4 && l.reports[2].pointer_class==4);
    C(shz_pointer_adapter_report(a,&l,pad,sizeof pad)==SHZ_DRIVER_OK && a->tracking);
    old=*a;calls=s->calls;
    C(shz_pointer_adapter_report(a,&l,keyboard,sizeof keyboard)==SHZ_UNSUPPORTED);
    C(calls==s->calls && !memcmp(a,&old,sizeof old));
    C(shz_pointer_adapter_report(a,&l,sensor,sizeof sensor)==SHZ_UNSUPPORTED);
    C(calls==s->calls && !memcmp(a,&old,sizeof old));
    /* Real tip-up preserves its pointer class/axes and resets the baseline. */
    {const uint8_t lift[]={1,0,50,60};C(shz_pointer_adapter_report(a,&l,lift,sizeof lift)==SHZ_DRIVER_OK && !a->tracking);}
    old=*a;calls=s->calls;
    C(shz_hid_parse_report(mixed,sizeof mixed,&l)==SHZ_DRIVER_OK);
    C(shz_pointer_adapter_report(a,&l,axes,sizeof axes)==SHZ_UNSUPPORTED);
    C(calls==s->calls && !memcmp(a,&old,sizeof old));
    /* One ReportID shared across pointer and keyboard Applications is not a
     * supported class contract; retaining an app mask must reject it too. */
    {uint8_t joined[sizeof composite];memcpy(joined,composite,sizeof joined);
     for(size_t i=0;i+1<sizeof joined;++i)if(joined[i]==0x85 && joined[i+1]==2)joined[i+1]=1;
     C(shz_hid_parse_report(joined,sizeof joined,&l)==SHZ_DRIVER_OK && l.reports[0].pointer_class==6);
     const uint8_t shared[]={1,1,50,60,1};C(shz_pointer_adapter_report(a,&l,shared,sizeof shared)==SHZ_UNSUPPORTED);
     C(calls==s->calls && !memcmp(a,&old,sizeof old));}
}
int main(void) {
    struct sink s={.valid=1};struct shz_pointer_adapter a={0},old;
    struct shz_pointer_sink ops={&s,validate,emit};struct shz_pointer p;
    C(shz_pointer_adapter_bind(&a,&ops,7,9,0,1)==SHZ_INVALID && !a.bound);
    C(shz_pointer_adapter_bind(&a,&ops,7,9,4,8)==SHZ_DRIVER_OK);
    C(shz_pointer_adapter_bind(&a,&ops,7,10,4,8)==SHZ_BUSY);
    p=point(101,201,0,4);p.buttons=1;
    C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && s.x==0 && s.y==0 && s.buttons==1);
    p=point(108,190,0,4);
    C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && s.x==1 && s.y==-1);
    C(a.remainder_x==3 && a.remainder_y==-3);
    p=point(109,185,0,4);s.error=SHZ_CAPACITY;old=a;
    C(shz_pointer_adapter_input(&a,&p)==SHZ_CAPACITY && !memcmp(&a,&old,sizeof a));
    s.error=0;C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && s.x==1 && s.y==-1);
    p=point(900,800,0,5);C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && !s.x && !s.y);
    p.count=0;C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && !a.tracking);
    p=point(5,6,0,5);C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && !s.x && !s.y);
    p.count=2;old=a;unsigned calls=s.calls;
    C(shz_pointer_adapter_input(&a,&p)==SHZ_UNSUPPORTED && !memcmp(&a,&old,sizeof a) && calls==s.calls);
    p.count=1;p.buttons=8;C(shz_pointer_adapter_input(&a,&p)==SHZ_UNSUPPORTED && calls==s.calls);
    p.buttons=0;p.contacts[0].has_y=0;C(shz_pointer_adapter_input(&a,&p)==SHZ_MALFORMED && calls==s.calls);
    s.valid=0;p=point(20,30,0,5);C(shz_pointer_adapter_input(&a,&p)==SHZ_REVOKED && calls==s.calls);
    s.valid=1;C(shz_pointer_adapter_close(&a)==SHZ_DRIVER_OK);
    C(shz_pointer_adapter_bind(&a,&ops,7,9,1,1)==SHZ_STALE);
    /* A different immutable creation epoch needs an explicit fresh adapter. */
    memset(&a,0,sizeof a);C(shz_pointer_adapter_bind(&a,&ops,7,9,1,1)==SHZ_DRIVER_OK);
    p=point(INT32_MIN,INT32_MAX,0,6);C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK);
    p=point(INT32_MAX,INT32_MIN,0,6);old=a;calls=s.calls;
    C(shz_pointer_adapter_input(&a,&p)==SHZ_CAPACITY && !memcmp(&a,&old,sizeof a) && calls==s.calls);
    C(shz_pointer_adapter_close(&a)==SHZ_DRIVER_OK);memset(&a,0,sizeof a);
    C(shz_pointer_adapter_bind(&a,&ops,7,9,2,2)==SHZ_DRIVER_OK);
    p=point(-3,3,1,0);C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && s.x==-1 && s.y==1);
    p=point(-1,1,1,0);C(shz_pointer_adapter_input(&a,&p)==SHZ_DRIVER_OK && s.x==-1 && s.y==1);
    p.relative=2;calls=s.calls;C(shz_pointer_adapter_input(&a,&p)==SHZ_MALFORMED && calls==s.calls);
    p.relative=1;p.count=0;C(shz_pointer_adapter_input(&a,&p)==SHZ_MALFORMED && calls==s.calls);
    descriptor_classes(&a,&s);
    printf("pointer adapter: %u assertions PASS\n",checks);return 0;
}
