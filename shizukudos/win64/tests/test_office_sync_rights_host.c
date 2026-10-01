/* SPDX-License-Identifier: GPL-2.0-only */
#include "../../kernel64/office_sync_rights.h"
#include <assert.h>
#include <stdio.h>
int main(void)
{
    uint32_t value;unsigned checks=0;
#define CHECK(c) do{++checks;assert(c);}while(0)
    CHECK(shz_sync_map_access(0,&value)&&value==0);
    CHECK(!shz_sync_rights_present(value,SHZ_SYNCHRONIZE));
    CHECK(!shz_sync_rights_present(value,SHZ_SYNC_MODIFY));
    CHECK(shz_sync_map_access(SHZ_SYNCHRONIZE,&value)&&value==SHZ_SYNCHRONIZE);
    CHECK(shz_sync_rights_present(value,SHZ_SYNCHRONIZE));
    CHECK(!shz_sync_rights_present(value,SHZ_SYNC_MODIFY));
    CHECK(shz_sync_map_access(SHZ_SYNC_MODIFY,&value)&&value==SHZ_SYNC_MODIFY);
    CHECK(!shz_sync_rights_present(value,SHZ_SYNCHRONIZE));
    CHECK(shz_sync_rights_present(value,SHZ_SYNC_MODIFY));
    CHECK(shz_sync_map_access(0x80000000u,&value)&&value==0x120001u);
    CHECK(!shz_sync_rights_present(value,SHZ_SYNC_MODIFY));
    CHECK(shz_sync_map_access(0x40000000u,&value)&&value==0x120002u);
    CHECK(!shz_sync_rights_present(value,SHZ_SYNC_QUERY));
    CHECK(shz_sync_map_access(0x20000000u,&value)&&value==0x120000u);
    CHECK(shz_sync_map_access(0x10000000u,&value)&&value==SHZ_SYNC_ALL_ACCESS);
    CHECK(shz_sync_map_access(0x02000000u,&value)&&value==SHZ_SYNC_ALL_ACCESS);
    CHECK(shz_sync_map_access(SHZ_SYNC_ALL_ACCESS,&value)&&value==SHZ_SYNC_ALL_ACCESS);
    value=0x55555555u;CHECK(!shz_sync_map_access(4,&value)&&value==0x55555555u);
    CHECK(!shz_sync_map_access(0x01000000u,&value));
    CHECK(!shz_sync_map_access(0xffffffffu,&value));
    puts("OFFICE-SYNC-RIGHTS-HOST:20 checks passed; exact zero/access/generic rights, unsupported bits, modification and synchronization distinction");return checks!=20;
}
