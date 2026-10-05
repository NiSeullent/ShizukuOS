/* SPDX-License-Identifier: GPL-2.0-only */
#include "../reply.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
int main(void)
{
    shz_saw_reply r;
    memset(&r, 0, sizeof r); r.version = SHZ_SAW_VERSION; r.size = sizeof r;
    r.count = r.targets = r.completed = 1;
    r.rows[0].pid = 1842; r.rows[0].generation = 42; r.rows[0].lifecycle = SHZ_SAW_EXITED;
    assert(cs_reply_valid(&r)); assert(cs_reply_sawed(&r));
    r.flags = SHZ_SAW_REPLY_PENDING; assert(!cs_reply_sawed(&r));
    r.flags = SHZ_SAW_REPLY_ADMITTED; assert(!cs_reply_sawed(&r));
    r.flags = SHZ_SAW_REPLY_PROTECTED; assert(!cs_reply_sawed(&r));
    r.flags = 0; r.rows[0].lifecycle = SHZ_SAW_EXIT_PENDING; assert(!cs_reply_sawed(&r));
    r.rows[0].lifecycle = SHZ_SAW_EXITED; r.rows[0].status = -1; assert(!cs_reply_sawed(&r));
    r.rows[0].status = 0; r.count = 65; assert(!cs_reply_valid(&r));
    r.count = 1; r.rows[0].generation = 0; assert(!cs_reply_valid(&r));
    r.rows[0].generation = 42; memset(r.rows[0].name, 'x', sizeof r.rows[0].name); assert(!cs_reply_valid(&r));
    r.rows[0].name[31] = 0; r.rows[0].classification = 4; assert(!cs_reply_valid(&r));
    r.rows[0].classification = 0; r.rows[0].reasons = 0x80000000u; assert(!cs_reply_valid(&r));
    r.rows[0].reasons = 0; r.count = r.targets = r.completed = 2; r.rows[1] = r.rows[0]; assert(!cs_reply_valid(&r));
    r.count = r.targets = 1; r.completed = 0; r.rows[0].generation = 0; r.rows[0].lifecycle = 0;
    r.rows[0].status = r.status = (int32_t)0xC0000022u; r.rows[0].reasons = SHZ_SAW_REASON_ACCESS;
    assert(cs_reply_valid(&r)); assert(!cs_reply_sawed(&r)); /* deliberately redacted refusal */
    memset(&r.rows[0],0,sizeof r.rows[0]); r.rows[0].status=r.status;
    r.rows[0].reasons=SHZ_SAW_REASON_ACCESS;
    assert(cs_reply_valid(&r)); assert(!cs_reply_sawed(&r)); /* private descendant */
    r.rows[0].name[0]='x'; assert(!cs_reply_valid(&r));
    r.rows[0].name[0]=0; r.rows[0].reasons=SHZ_SAW_REASON_IDENTITY; assert(!cs_reply_valid(&r));
    r.rows[0].pid=1842;r.rows[0].generation=42;r.targets=0;
    assert(cs_reply_valid(&r)); assert(!cs_reply_sawed(&r)); /* diagnostic row, no acquired target */
    puts("CHAINSAW replies: pending/admitted/protected cannot claim SAWED; malformed/duplicate identities rejected PASS");
    return 0;
}
