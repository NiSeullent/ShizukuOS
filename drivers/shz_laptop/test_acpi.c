/* SPDX-License-Identifier: GPL-2.0-only */
#include "laptop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
static void put32(uint8_t *p,uint32_t n) { unsigned i; for(i=0;i<4;i++) p[i]=(uint8_t)(n>>(i*8)); }
static void table(uint8_t *p,size_t n,const char *sig) {
    memset(p,0,n); memcpy(p,sig,4); put32(p+4,(uint32_t)n); p[8]=1;
}
static void sum(uint8_t *p,size_t n) { unsigned s=0;size_t i;p[9]=0;for(i=0;i<n;i++)s+=p[i];p[9]=(uint8_t)(0u-s); }
struct io { int valid; unsigned writes,reads; uint32_t ca,cb,ea,eb; uint64_t time; int stuck,require_dword; };
static int valid(void *p,uint64_t o,uint64_t g,const struct shz_gas *gas,unsigned bytes,int write) {
    struct io *i=p;(void)write;
    if(i->require_dword && gas->address==0x100 && bytes!=4)return SHZ_REVOKED;
    return i->valid && o==4 && g==2 &&
        gas->space==1 && bytes>=1 && bytes<=4 && gas->address>=0x100 &&
        gas->address<=0xffff ? SHZ_DRIVER_OK:SHZ_REVOKED;
}
static int rd(void *p,const struct shz_gas *g,unsigned bytes,uint32_t *v) {
    struct io *i=p;(void)bytes;++i->reads;
    if(g->address==0x110) *v=i->ca; else if(g->address==0x112) *v=i->cb;
    else if(g->address==0x100) *v=i->ea; else if(g->address==0x104) *v=i->eb;
    else return SHZ_IO;
    return SHZ_DRIVER_OK;
}
static int wr(void *p,const struct shz_gas *g,unsigned bytes,uint32_t v) {
    struct io *i=p;(void)bytes;++i->writes;
    if(g->address==0x120) { C(v==0xa0);if(!i->stuck){i->ca|=1;i->cb|=1;} }
    else if(g->address==0x100) {
        if(bytes==4)i->ea=(v&0xffff0000u)|((i->ea&65535u)&~v);
        else i->ea&=~v;
    }
    else if(g->address==0x104) i->eb&=~v;
    else if(g->address==0x130) C(v==6);
    else return SHZ_IO;
    return SHZ_DRIVER_OK;
}
static uint64_t now(void *p) { return ((struct io *)p)->time; }
static void relax(void *p) { ((struct io *)p)->time+=10; }
int main(void) {
    uint8_t f[244],e[83];struct shz_fixed out,old;struct shz_ec_table ec,eo;
    struct io i={1,0,0,0,0,0x1000100,0x2000200,0,0,0};uint16_t active=0;
    struct shz_fixed_power power;
    table(f,sizeof(f),"FACP");f[46]=9;put32(f+48,0x120);f[52]=0xa0;
    put32(f+56,0x100);put32(f+60,0x104);put32(f+64,0x110);put32(f+68,0x112);
    f[88]=4;f[89]=2;put32(f+112,1u<<10);
    f[116]=1;f[117]=8;f[119]=1;put32(f+120,0x130);f[128]=6;sum(f,sizeof(f));
    C(shz_parse_fadt(f,sizeof(f),&out)==SHZ_DRIVER_OK);
    C(out.control_a.address==0x110 && out.control_b.address==0x112 && out.sci==9);
    memset(&power,0,sizeof(power));power.table=out;
    power.ops=(struct shz_register_ops){&i,valid,rd,wr,now,relax};
    power.owner=4;power.generation=2;power.timeout_us=100;
    C(shz_fixed_events(&power,&active)==SHZ_DRIVER_OK && active==0x300);
    C(shz_fixed_ack(&power,0x100)==SHZ_DRIVER_OK && i.ea==0x1000000 && i.eb==0x2000200);
    C(shz_fixed_enable(&power)==SHZ_DRIVER_OK && i.ca==1 && i.cb==1);
    C(shz_fixed_reset(&power)==SHZ_DRIVER_OK);
    i.require_dword=1;i.ea=0x1000100;power.table.event_a.access=3;
    C(shz_fixed_ack(&power,0x100)==SHZ_DRIVER_OK && i.ea==0x1000000);
    i.require_dword=0;power.table.event_a.access=0;
    i.valid=0;{unsigned writes=i.writes; C(shz_fixed_ack(&power,0x200)==SHZ_REVOKED && i.writes==writes);}
    active=0xbeef;C(shz_fixed_events(&power,&active)==SHZ_REVOKED && active==0xbeef);
    i.valid=1;i.ca=i.cb=0;i.stuck=1;
    C(shz_fixed_enable(&power)==SHZ_TIMEOUT);
    old=out;f[9]++;C(shz_parse_fadt(f,sizeof(f),&out)==SHZ_MALFORMED && memcmp(&out,&old,sizeof(out))==0);
    f[9]--;put32(f+112,1u<<20);sum(f,sizeof(f));C(shz_parse_fadt(f,sizeof(f),&out)==SHZ_UNSUPPORTED);
    put32(f+112,0);f[172]=1;f[173]=16;f[175]=2;put32(f+176,0x210);sum(f,sizeof(f));
    C(shz_parse_fadt(f,sizeof(f),&out)==SHZ_DRIVER_OK && out.control_a.address==0x210);
    f[174]=1;sum(f,sizeof(f));C(shz_parse_fadt(f,sizeof(f),&out)==SHZ_UNSUPPORTED);
    C(shz_parse_fadt(f,115,&out)==SHZ_MALFORMED);
    f[174]=0;put32(f+4,178);sum(f,178);C(shz_parse_fadt(f,178,&out)==SHZ_MALFORMED);
    table(e,sizeof(e),"ECDT");e[36]=1;e[37]=8;e[39]=1;put32(e+40,0x66);
    e[48]=1;e[49]=8;e[51]=1;put32(e+52,0x62);put32(e+60,7);e[64]=12;
    memcpy(e+65,"\\_SB.PCI0.LPC.EC0",17);sum(e,sizeof(e));
    C(shz_parse_ecdt(e,sizeof(e),&ec)==SHZ_DRIVER_OK);
    C(ec.control.address==0x66 && ec.data.address==0x62 && ec.uid==7 && ec.gpe==12);
    eo=ec;e[82]='X';sum(e,sizeof(e));C(shz_parse_ecdt(e,sizeof(e),&ec)==SHZ_MALFORMED && memcmp(&ec,&eo,sizeof(ec))==0);
    e[82]=0;e[49]=16;sum(e,sizeof(e));C(shz_parse_ecdt(e,sizeof(e),&ec)==SHZ_UNSUPPORTED);
    printf("ACPI fixed tables/power: %u assertions PASS\n",checks); return 0;
}
