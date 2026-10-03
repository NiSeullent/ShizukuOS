/* SPDX-License-Identifier: GPL-2.0-only */
#include "laptop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
struct model {int valid,absent,wrong_count,wrong_type,fail,revoke,charging;uint64_t temperature;uint32_t remaining,full;unsigned calls;int relative,rtv_missing,rtv_error;};
static int valid(void *p,uint64_t o,uint64_t g,uint64_t node) {
    struct model *m=p;return m->valid && o==13 && g==3 && node==7 ? SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int evaluate(void *p,uint64_t node,const char name[5],struct shz_acpi_value *v,
                    size_t cap,size_t *count,uint32_t timeout) {
    struct model *m=p;size_t i;(void)node;C(timeout==200);++m->calls;
    if(m->fail)return SHZ_TIMEOUT;
    for(i=0;i<cap;i++){v[i].kind=SHZ_ACPI_INTEGER;v[i].integer=0;}
    if(strcmp(name,"_STA")==0){*count=1;v[0].integer=m->absent ? 0x0f:0x1f;}
    else if(strcmp(name,"_BIF")==0){C(cap>=13);*count=13;v[2].integer=m->full;for(i=9;i<13;i++)v[i].kind=SHZ_ACPI_STRING;}
    else if(strcmp(name,"_BST")==0){C(cap>=4);*count=4;v[0].integer=(uint64_t)m->charging;v[1].integer=50;v[2].integer=m->remaining;v[3].integer=12000;}
    else if(strcmp(name,"_RTV")==0){
        if(m->rtv_missing)return SHZ_NOT_FOUND;
        if(m->rtv_error)return SHZ_UNSUPPORTED;
        *count=1;v[0].integer=(uint64_t)m->relative;
    }
    else if(strcmp(name,"_TMP")==0){*count=1;v[0].integer=m->temperature;}
    else if(strcmp(name,"_PSR")==0 || strcmp(name,"_LID")==0){*count=1;v[0].integer=1;}
    else return SHZ_UNSUPPORTED;
    if(m->wrong_count)++*count;
    if(m->wrong_type)v[0].kind=SHZ_ACPI_STRING;
    if(m->revoke)m->valid=0;
    return SHZ_DRIVER_OK;
}
int main(void) {
    struct model m={.valid=1,.charging=1,.temperature=2982,.remaining=2500,.full=5000};
    struct shz_acpi_provider p={&m,valid,evaluate,13,3,200};
    struct shz_battery b,old;int32_t t=999;int state=8;
    C(shz_acpi_battery(&p,7,&b)==SHZ_DRIVER_OK && b.present && b.percent_known && b.percent==50);
    C(b.state==1 && b.remaining==2500 && b.rate==50 && b.voltage==12000);
    m.charging=8;C(shz_acpi_battery(&p,7,&b)==SHZ_DRIVER_OK && b.state==8);m.charging=1;
    m.full=0x80000000u;C(shz_acpi_battery(&p,7,&b)==SHZ_MALFORMED);m.full=5000;
    C(shz_acpi_temperature(&p,7,&t)==SHZ_DRIVER_OK && t==25050);
    m.relative=1;t=777;{unsigned n=m.calls;C(shz_acpi_temperature(&p,7,&t)==SHZ_UNSUPPORTED && t==777 && m.calls==n+1);}
    m.relative=0;m.rtv_missing=1;C(shz_acpi_temperature(&p,7,&t)==SHZ_DRIVER_OK && t==25050);m.rtv_missing=0;
    m.rtv_error=1;t=777;C(shz_acpi_temperature(&p,7,&t)==SHZ_UNSUPPORTED && t==777);m.rtv_error=0;
    C(shz_acpi_ac_power(&p,7,&state)==SHZ_DRIVER_OK && state==1);
    C(shz_acpi_lid(&p,7,&state)==SHZ_DRIVER_OK && state==1);
    m.absent=1;{unsigned n=m.calls;C(shz_acpi_battery(&p,7,&b)==SHZ_DRIVER_OK && !b.present && m.calls==n+1);}
    m.absent=0;m.remaining=UINT32_MAX;C(shz_acpi_battery(&p,7,&b)==SHZ_DRIVER_OK && !b.percent_known);
    m.remaining=5001;C(shz_acpi_battery(&p,7,&b)==SHZ_MALFORMED);
    m.remaining=2500;m.charging=3;C(shz_acpi_battery(&p,7,&b)==SHZ_MALFORMED);
    m.charging=1;old=b;m.wrong_count=1;
    C(shz_acpi_battery(&p,7,&b)==SHZ_MALFORMED && memcmp(&b,&old,sizeof(b))==0);
    m.wrong_count=0;m.wrong_type=1;t=777;
    C(shz_acpi_temperature(&p,7,&t)==SHZ_MALFORMED && t==777);
    m.wrong_type=0;m.temperature=UINT64_MAX;C(shz_acpi_temperature(&p,7,&t)==SHZ_MALFORMED && t==777);
    m.temperature=2982;m.fail=1;C(shz_acpi_temperature(&p,7,&t)==SHZ_TIMEOUT && t==777);
    m.fail=0;m.valid=0;{unsigned n=m.calls;C(shz_acpi_ac_power(&p,7,&state)==SHZ_REVOKED && m.calls==n);}
    m.valid=1;m.revoke=1;C(shz_acpi_lid(&p,7,&state)==SHZ_REVOKED);
    p.evaluate=0;C(shz_acpi_temperature(&p,7,&t)==SHZ_UNSUPPORTED);
    printf("ACPI battery/thermal/lid/power: %u assertions PASS\n",checks);return 0;
}
