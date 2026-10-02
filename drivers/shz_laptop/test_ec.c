/* SPDX-License-Identifier: GPL-2.0-only */
#include "laptop.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define C(x) do { ++checks; assert(x); } while(0)
struct model { uint8_t memory[256],command,address,data,query;unsigned phase,writes,reads;
    int valid,ibf,obf,sci,stuck,freeze,reverse,revoke_after_write;uint64_t time; };
static int valid(void *p,uint64_t o,uint64_t g,const struct shz_gas *a,unsigned n,int w) {
    struct model *m=p;(void)w;return m->valid && o==10 && g==2 && n==1 &&
        a->space==1 && (a->address==0x66 || a->address==0x62) ? SHZ_OK:SHZ_REVOKED;
}
static int read_reg(void *p,const struct shz_gas *g,unsigned n,uint32_t *v) {
    struct model *m=p;(void)n;++m->reads;
    if(g->address==0x66) *v=(uint32_t)((m->ibf || m->stuck ? 2:0)|(m->obf ? 1:0)|(m->sci ? 32:0));
    else { if(!m->obf)return SHZ_IO;*v=m->data;m->obf=0; }
    return SHZ_OK;
}
static int write_reg(void *p,const struct shz_gas *g,unsigned n,uint32_t v) {
    struct model *m=p;(void)n;++m->writes;C(!m->ibf && !m->obf);
    m->ibf=1;
    if(g->address==0x66) {
        C(m->phase==0);m->command=(uint8_t)v;m->phase=1;
        if(v==0x84) {m->data=m->query;m->obf=1;m->sci=0;m->phase=0;}
    } else if(m->phase==1) {
        m->address=(uint8_t)v;m->phase=2;
        if(m->command==0x80) {m->data=m->memory[v];m->obf=1;m->phase=0;}
    } else if(m->phase==2 && m->command==0x81) {
        m->memory[m->address]=(uint8_t)v;m->phase=0;
    } else return SHZ_IO;
    if(m->revoke_after_write) m->valid=0;
    return SHZ_OK;
}
static uint64_t now(void *p) { return ((struct model *)p)->time; }
static void relax(void *p) {
    struct model *m=p;m->ibf=0;
    if(m->reverse) --m->time;else if(!m->freeze)m->time+=5;
}
static int recover(void *p) {struct model *m=p;m->ibf=m->obf=m->stuck=0;m->phase=0;return SHZ_OK;}
int main(void) {
    struct model m;struct shz_ec e={0};uint8_t out=0xa5;
    struct shz_ec_table t={{1,8,0,1,0x66},{1,8,0,1,0x62},0,0,"\\_SB.EC0"};
    struct shz_register_ops ops={&m,valid,read_reg,write_reg,now,relax};
    memset(&m,0,sizeof(m));m.valid=1;m.memory[0x32]=0x75;
    C(shz_ec_open(&e,&t,&ops,10,2,100,0)==SHZ_UNSUPPORTED && m.writes==0);
    C(shz_ec_open(&e,&t,&ops,10,2,100,1)==SHZ_OK);
    C(shz_ec_read(&e,0x32,&out)==SHZ_OK && out==0x75 && m.phase==0);
    C(shz_ec_write(&e,0x33,0x64)==SHZ_OK && m.memory[0x33]==0x64);
    out=0xa5;C(shz_ec_query(&e,&out)==SHZ_NO_EVENT && out==0xa5);
    m.sci=1;m.query=0x34;C(shz_ec_query(&e,&out)==SHZ_OK && out==0x34);
    m.stuck=1;out=0x6a;{unsigned n=m.writes;
      C(shz_ec_read(&e,0x32,&out)==SHZ_TIMEOUT && out==0x6a && m.writes==n);}
    C(e.state==SHZ_EC_POISONED && shz_ec_close(&e)==SHZ_QUARANTINED);
    C(shz_ec_read(&e,0x32,&out)==SHZ_QUARANTINED);
    C(shz_ec_open(&e,&t,&ops,10,3,100,1)==SHZ_BUSY);
    C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    C(shz_ec_read(&e,0x32,&out)==SHZ_OK && out==0x75);
    {struct shz_ec_sensor sensor={0x32,1000,-10000,0,200000};int32_t reading=999;
      C(shz_ec_sensor_read(&e,&sensor,&reading)==SHZ_OK && reading==107000);
      sensor.maximum=50000;reading=777;
      C(shz_ec_sensor_read(&e,&sensor,&reading)==SHZ_MALFORMED && reading==777);
      sensor.maximum=INT32_MAX;sensor.offset_milli=INT32_MAX;
      C(shz_ec_sensor_read(&e,&sensor,&reading)==SHZ_MALFORMED && reading==777);}
    m.valid=0;out=0xa5;{unsigned n=m.writes;
      C(shz_ec_write(&e,0x33,0x12)==SHZ_REVOKED && m.writes==n);}
    C(e.state==SHZ_EC_POISONED);m.valid=1;
    C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    m.revoke_after_write=1;out=0xa5;
    C(shz_ec_read(&e,0x32,&out)==SHZ_REVOKED && out==0xa5);
    C(shz_ec_close(&e)==SHZ_QUARANTINED);
    m.valid=1;m.revoke_after_write=0;C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    m.stuck=1;m.freeze=1;C(shz_ec_read(&e,0x32,&out)==SHZ_CLOCK);
    m.freeze=0;C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    m.stuck=1;m.reverse=1;m.time=1000;
    C(shz_ec_read(&e,0x32,&out)==SHZ_CLOCK);
    m.reverse=0;C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    m.obf=1;{unsigned n=m.writes;C(shz_ec_read(&e,0x32,&out)==SHZ_BUSY && m.writes==n);}
    C(shz_ec_recover(&e,recover,&m)==SHZ_OK);
    C(shz_ec_close(&e)==SHZ_OK && e.state==SHZ_EC_CLOSED);
    printf("ACPI EC protocol: %u assertions PASS\n",checks);return 0;
}
