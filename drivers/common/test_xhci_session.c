/* SPDX-License-Identifier: GPL-2.0-only */
#define main existing_xhci_tests
#include "../xhci_native/test_xhci.c"
#undef main
#include "native_sessions.h"
struct lease {int valid;unsigned checks,revoke_at;};
static int lease_valid(void *p,uint64_t owner,uint64_t generation) {
    struct lease *l=p;++l->checks;if(l->revoke_at && l->checks==l->revoke_at)l->valid=0;
    return l->valid && owner==23 && generation>=1 ? SHZ_OK:SHZ_REVOKED;
}
int main(void) {
    struct model m;struct lease lease={1,0,0};struct shz_xhci_session s={0};
    struct xhci_ops ops;struct xhci_config cfg=config();
    struct shz_core_owner owner={&lease,lease_valid};
    CHECK(existing_xhci_tests()==0);reset(&m);ops=callbacks(&m);
    CHECK(shz_xhci_bind(&s,&owner,&ops,&cfg,23,1)==SHZ_OK);
    CHECK(shz_device_start(&s.lifecycle)==SHZ_OK && m.memory);
    CHECK(shz_xhci_noop(&s)==SHZ_OK);
    m.halt_stuck=1;CHECK(shz_device_stop(&s.lifecycle,1)==SHZ_QUARANTINED);
    CHECK(m.memory && m.releases==0 && s.core.state==XHCI_RETAINED);
    CHECK(shz_xhci_noop(&s)==SHZ_BUSY);
    CHECK(shz_xhci_bind(&s,&owner,&ops,&cfg,23,2)==SHZ_BUSY);
    m.halt_stuck=0;CHECK(shz_device_stop(&s.lifecycle,1)==SHZ_OK && !m.memory);
    CHECK(shz_device_resume(&s.lifecycle)==SHZ_OK && m.memory);
    lease.revoke_at=lease.checks+8;
    CHECK(shz_xhci_noop(&s)!=SHZ_OK);
    CHECK(s.lifecycle.state==SHZ_DEVICE_QUARANTINED && m.memory && m.releases==1);
    CHECK(shz_device_stop(&s.lifecycle,0)==SHZ_QUARANTINED && m.releases==1);
    lease.valid=1;lease.revoke_at=0;
    CHECK(shz_device_stop(&s.lifecycle,0)==SHZ_OK);no_leaks(&m);
    printf("xHCI actual core/session: %u cumulative assertions PASS\n",assertions);return 0;
}
