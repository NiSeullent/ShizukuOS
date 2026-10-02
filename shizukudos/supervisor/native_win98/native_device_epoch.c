/* SPDX-License-Identifier: GPL-2.0-only
 * Readonly observations and a bounded protocol, not physical authority. */
#include "native_device_epoch.h"
static int equal(const uint8_t *a,const uint8_t *b,unsigned n)
{unsigned i;uint8_t different=0;for(i=0;i<n;i++)different|=a[i]^b[i];return !different;}
static int nonzero(const uint8_t *p,unsigned n)
{unsigned i;uint8_t v=0;for(i=0;i<n;i++)v|=p[i];return v!=0;}
static void zero(uint8_t *p,unsigned n){for(unsigned i=0;i<n;i++)p[i]=0;}
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(8*i));}
static void put64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(8*i));}
static uint32_t get32(const uint8_t *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void copy(uint8_t *to,const uint8_t *from,unsigned n)
{for(unsigned i=0;i<n;i++)to[i]=from[i];}
static int header(const uint8_t *p,unsigned kind,unsigned bytes,unsigned count)
{
    return get32(p)==W98_EPOCH_MAGIC && p[4]==W98_EPOCH_VERSION && !p[5] &&
           p[6]==kind && !p[7] && get32(p+8)==bytes && get32(p+12)==count;
}
static void make_header(uint8_t *p,unsigned kind,unsigned bytes,unsigned count)
{put32(p,W98_EPOCH_MAGIC);put16(p+4,W98_EPOCH_VERSION);put16(p+6,(uint16_t)kind);put32(p+8,bytes);put32(p+12,count);}
static int expectations(const w98_epoch_expect_t *e)
{
    unsigned present=0;
    if(!e || !e->count || e->count>2 || !nonzero(e->nonce,32))return -1;
    for(unsigned i=0;i<e->count;i++){
        const w98_epoch_device_t *d=&e->device[i];unsigned found=0;
        if(d->bdf>=256 || (d->role!=W98_EPOCH_VGA && d->role!=W98_EPOCH_STORAGE) ||
           (present&(1u<<d->role)) || (i && (d->role<=e->device[i-1].role || d->bdf==e->device[i-1].bdf)) ||
           (d->command_required&d->command_forbidden))return -1;
        if(d->role==W98_EPOCH_VGA){
            if(d->vendor!=0x1234 || d->device!=0x1111 || d->class_code!=0x030000 ||
               !nonzero(e->rom_sha256,32))return -1;
        }else if(d->vendor!=0x1af4 || (d->device!=0x1001 && d->device!=0x1042) || d->class_code!=0x010000)return -1;
        if(!nonzero(e->config_sha256[d->role-1],32))return -1;
        present|=1u<<d->role;
        for(unsigned b=0;b<6;b++){
            uint32_t raw=d->raw_bar[b];uint64_t base;
            if(!raw)continue;
            ++found;
            if(raw&1){if(raw&2 || !(raw&~3u))return -1;}
            else if((raw&6)==4){
                if(b==5)return -1;
                base=(uint64_t)d->raw_bar[b+1]<<32|(raw&~15u);
                if(!base)return -1;
                ++b;
            }else if((raw&6) || !(raw&~15u))return -1;
        }
        if(!found)return -1;
    }
    for(unsigned role=1;role<=2;role++)if(!(present&(1u<<role)) && nonzero(e->config_sha256[role-1],32))return -1;
    if(!(present&(1u<<W98_EPOCH_VGA)) && nonzero(e->rom_sha256,32))return -1;
    /* Unselected slots must not hide candidate resources in this protocol. */
    if(e->count==1){
        const w98_epoch_device_t *d=&e->device[1];
        if(d->bdf || d->role || d->vendor || d->device || d->class_code || d->command_required || d->command_forbidden)return -1;
        for(unsigned b=0;b<6;b++)if(d->raw_bar[b])return -1;
    }
    return 0;
}
static int current(w98_epoch_gate_t *g,uint64_t deadline)
{
    uint64_t now;
    if(g->state!=W98_EPOCH_EXCHANGING || g->deadline!=deadline)return -1;
    now=g->io.now(g->io.opaque);
    if(now<g->last_now || now>=deadline || g->state!=W98_EPOCH_EXCHANGING || g->deadline!=deadline)return -1;
    g->last_now=now;return 0;
}
static int transfer(w98_epoch_gate_t *g,uint8_t *p,unsigned bytes,int send,uint64_t deadline)
{
    unsigned done=0;
    while(done<bytes){
        int n;
        if(current(g,deadline) || g->io_calls>=W98_EPOCH_MAX_IO_CALLS)return -1;
        ++g->io_calls;
        n=send?g->io.send(g->io.opaque,p+done,bytes-done):g->io.receive(g->io.opaque,p+done,bytes-done);
        if(current(g,deadline) || n<0 || (unsigned)n>bytes-done)return -1;
        if(n)done+=(unsigned)n;
        else {g->io.pause(g->io.opaque);if(current(g,deadline))return -1;}
    }
    return 0;
}
static int snapshot(w98_epoch_gate_t *g,uint32_t raw[2][10],uint64_t deadline)
{
    for(unsigned i=0;i<g->expected.count;i++){
        const w98_epoch_device_t *d=&g->expected.device[i];
        for(unsigned r=0;r<10;r++){
            if(current(g,deadline) || g->io.pci_read(g->io.opaque,d->bdf,r*4,&raw[i][r]) || current(g,deadline))return -1;
        }
        if(raw[i][0]!=((uint32_t)d->device<<16|d->vendor) || raw[i][2]>>8!=d->class_code ||
           (raw[i][3]&0x7f0000u) || (raw[i][1]&d->command_required)!=d->command_required ||
           (raw[i][1]&d->command_forbidden))return -1;
        for(unsigned b=0;b<6;b++)if(raw[i][b+4]!=d->raw_bar[b])return -1;
    }
    return 0;
}
static int failure(w98_epoch_gate_t *g)
{g->protocol_admitted=0;g->state=W98_EPOCH_FAILED;return -1;}
int w98_native_epoch_gate(w98_epoch_gate_t *g,const w98_epoch_expect_t *expected,
                          const w98_epoch_io_t *io,uint64_t deadline)
{
    uint8_t challenge[W98_EPOCH_CHALLENGE_BYTES],grant[W98_EPOCH_GRANT_BYTES];
    uint32_t first[2][10]={{0}},last[2][10]={{0}};
    if(!g)return -1;
    if(g->state!=W98_EPOCH_NEW || g->nonce_consumed || !deadline || expectations(expected) ||
       !io || !io->pci_read || !io->receive || !io->send || !io->now || !io->pause)return failure(g);
    g->state=W98_EPOCH_EXCHANGING;g->protocol_admitted=0;g->nonce_consumed=1;
    g->expected=*expected;g->io=*io;g->deadline=deadline;g->last_now=0;g->io_calls=0;
    if(current(g,deadline) || transfer(g,challenge,sizeof challenge,0,deadline) ||
       !header(challenge,W98_EPOCH_CHALLENGE,sizeof challenge,0) ||
       !equal(challenge+16,g->expected.nonce,32) || snapshot(g,first,deadline))return failure(g);
    zero(g->report,sizeof g->report);
    make_header(g->report,W98_EPOCH_REPORT,sizeof g->report,g->expected.count);
    copy(g->report+16,g->expected.nonce,32);copy(g->report+48,g->expected.config_sha256[0],32);
    copy(g->report+80,g->expected.config_sha256[1],32);copy(g->report+112,g->expected.rom_sha256,32);
    put64(g->report+144,deadline);
    for(unsigned i=0;i<g->expected.count;i++){
        uint8_t *row=g->report+152+i*48;
        put16(row,g->expected.device[i].bdf);put16(row+2,g->expected.device[i].role);
        for(unsigned r=0;r<10;r++)put32(row+8+r*4,first[i][r]);
    }
    if(transfer(g,g->report,sizeof g->report,1,deadline) || transfer(g,grant,sizeof grant,0,deadline) ||
       !header(grant,W98_EPOCH_GRANT,sizeof grant,g->expected.count) ||
       !equal(grant+16,g->report,sizeof g->report) || snapshot(g,last,deadline))return failure(g);
    for(unsigned i=0;i<g->expected.count;i++)for(unsigned r=0;r<10;r++)if(last[i][r]!=first[i][r])return failure(g);
    if(current(g,deadline))return failure(g);
    g->state=W98_EPOCH_ADMITTED;g->protocol_admitted=1;return 0;
}
