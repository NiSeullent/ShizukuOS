/* SPDX-License-Identifier: GPL-2.0-only */
#define main existing_ahci_tests
#include "../ahci_native/test_ahci.c"
#undef main
#include "native_sessions.h"
struct lease {int valid;unsigned checks,revoke_at;};
static int lease_valid(void *p,uint64_t owner,uint64_t generation) {
    struct lease *l=p;++l->checks;if(l->revoke_at && l->checks==l->revoke_at)l->valid=0;
    return l->valid && owner==22 && generation>=1 ? SHZ_OK:SHZ_REVOKED;
}
int main(void) {
    struct model m;struct lease lease={1,0,0};struct shz_ahci_session s={0};
    struct ahci_ops ops;struct ahci_config cfg=config_rw();
    struct shz_core_owner owner={&lease,lease_valid};uint8_t data[512],old[512];
    CHECK(existing_ahci_tests()==0);reset(&m);w16(m.identify+166,0x6400);ops=callbacks(&m);
    CHECK(shz_ahci_bind(&s,&owner,&ops,&cfg,22,1)==SHZ_OK);
    CHECK(shz_device_start(&s.lifecycle)==SHZ_OK && m.allocation);
    {unsigned calls=m.calls;
      CHECK(shz_ahci_read(&s,5,1,m.allocation,512)==SHZ_INVALID && m.calls==calls);
      CHECK(shz_ahci_read(&s,5,1,&s.lifecycle,512)==SHZ_INVALID && m.calls==calls);
      CHECK(shz_ahci_write(&s,5,1,&s.lifecycle,512)==SHZ_INVALID && m.calls==calls);}
    CHECK(shz_ahci_read(&s,5,1,data,sizeof(data))==SHZ_OK && data[0]==pattern(5,0));
    memset(data,0x7d,512);CHECK(shz_ahci_write(&s,5,1,data,512)==SHZ_OK);
    CHECK(shz_ahci_flush(&s)==SHZ_OK && m.flushes==1);
    m.stop_stuck=1;CHECK(shz_device_stop(&s.lifecycle,1)==SHZ_QUARANTINED);
    CHECK(m.allocation && m.releases==0 && s.core.state==AHCI_RETAINED);
    CHECK(shz_ahci_read(&s,5,1,data,512)==SHZ_BUSY);
    CHECK(shz_ahci_bind(&s,&owner,&ops,&cfg,22,2)==SHZ_BUSY);
    m.stop_stuck=0;CHECK(shz_device_stop(&s.lifecycle,1)==SHZ_OK && !m.allocation);
    CHECK(shz_device_resume(&s.lifecycle)==SHZ_OK && m.allocation);
    memset(data,0xa5,512);memcpy(old,data,512);
    lease.revoke_at=lease.checks+8;
    CHECK(shz_ahci_read(&s,5,1,data,512)!=SHZ_OK && memcmp(data,old,512)==0);
    CHECK(s.lifecycle.state==SHZ_DEVICE_QUARANTINED && m.allocation && m.releases==1);
    CHECK(shz_device_stop(&s.lifecycle,0)==SHZ_QUARANTINED && m.releases==1);
    lease.valid=1;lease.revoke_at=0;
    CHECK(shz_device_stop(&s.lifecycle,0)==SHZ_OK);no_leaks(&m);
    printf("AHCI actual core/session: %u cumulative assertions PASS\n",assertions);return 0;
}
