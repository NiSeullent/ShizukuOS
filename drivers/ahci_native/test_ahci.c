/* SPDX-License-Identifier: GPL-2.0-only -- original asynchronous HBA model (read, write, flush). */
#include "ahci.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while(0)
enum { P=0x100, CLB=0, CLBU=4, FB=8, FBU=12, PIS=16, PIE=20, CMD=24,
       TFD=32, SIG=36, SSTS=40, SERR=48, SACT=52, CI=56 };
struct model {
    uint32_t regs[0x1100/4];
    uint8_t identify[512];
    uint8_t *allocation;
    uint64_t bus,clock,lba;
    unsigned calls,fault,reads,writes,allocations,releases,commands,syncs;
    unsigned pending,never_complete,late_error,short_transfer,unplug,stop_stuck;
    unsigned freeze_time,reverse_time,allocation_bad,bohc_stuck;
    unsigned cpu_sync,device_sync,opcode;
    uint32_t selected_base;
    uint32_t cold_signature,delivered_signature;
    /* media written through WRITE DMA EXT (reads of these LBAs return the stored bytes) */
    uint64_t written_lba[8]; uint8_t written[8][512]; unsigned nwritten,writes_done,flushes;
    uint8_t pending_data[512];
};
static uint32_t u32(const uint8_t *p)
{ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static void w32(uint8_t *p,uint32_t v)
{ unsigned i;for(i=0;i<4;++i)p[i]=(uint8_t)(v>>(i*8)); }
static void w16(uint8_t *p,uint16_t v)
{ p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8); }
static int failed(struct model *m)
{ return ++m->calls==m->fault; }
static uint8_t pattern(uint64_t lba,unsigned i)
{ return (uint8_t)(lba^(lba>>16)^(lba>>32)^(i*13u)); }
static int stored(const struct model *m,uint64_t lba)
{ unsigned i; for(i=0;i<m->nwritten;++i) if(m->written_lba[i]==lba) return (int)i; return -1; }
static void finish_command(struct model *m)
{
    unsigned i; uint32_t base=m->selected_base; int k;
    CHECK(m->allocation && m->pending);
    if(m->opcode==0xec) memcpy(m->allocation+2048,m->identify,512);
    else if(m->opcode==0x35) {
        /* The device consumes the DMA data when the command completes successfully. */
        if(!m->late_error && !m->short_transfer && !m->unplug) {
            k=stored(m,m->lba);
            if(k<0) { CHECK(m->nwritten<8); k=(int)m->nwritten++; m->written_lba[k]=m->lba; }
            memcpy(m->written[k],m->pending_data,512); ++m->writes_done;
        }
    } else if(m->opcode==0xea) {
        if(!m->late_error && !m->unplug) ++m->flushes;
    } else if((k=stored(m,m->lba))>=0) memcpy(m->allocation+2048,m->written[k],512);
    else for(i=0;i<512;++i)m->allocation[2048+i]=pattern(m->lba,i);
    w32(m->allocation+4,m->opcode==0xea?(m->short_transfer?512u:0u):m->short_transfer?256:512);
    m->regs[(base+CI)/4]=0;
    m->regs[(base+TFD)/4]=0x50;
    if(m->late_error==1) { m->regs[(base+PIS)/4]|=1u<<30; m->regs[(base+TFD)/4]=0x51; }
    if(m->late_error==2)m->regs[(base+TFD)/4]=0x70; /* DF without TFES */
    if(m->late_error==3)m->regs[(base+TFD)/4]=0x51; /* ERR even if IRQ bit absent */
    if(m->unplug)m->regs[(base+SSTS)/4]=0;
    m->pending=0;
}
static int read32(void *opaque,uint32_t offset,uint32_t *value)
{
    struct model *m=opaque;
    CHECK(!(offset&3u) && offset<sizeof(m->regs));++m->reads;
    /* Completion happens between the driver's first status read and CI read,
     * deliberately requiring a final status recheck after observing CI clear. */
    if(offset==m->selected_base+CI && m->pending && !m->never_complete)finish_command(m);
    if(offset==m->selected_base+SIG && m->cold_signature &&
        (m->regs[(m->selected_base+CMD)/4]&0x4000u)) {
        CHECK(m->allocation && !(m->regs[(m->selected_base+CMD)/4]&1u));
        if(m->delivered_signature) {
            m->regs[(m->selected_base+SIG)/4]=m->delivered_signature;
            m->regs[(m->selected_base+TFD)/4]=0x130;m->cold_signature=0;
        }
    }
    if(failed(m))return 0;
    *value=m->regs[offset/4];return 1;
}
static void issue_command(struct model *m,uint32_t value)
{
    const uint8_t *header=m->allocation,*table=header+1280;
    uint64_t table_bus,data_bus; unsigned i; uint32_t base=m->selected_base;
    CHECK(value==1 && m->allocation && !m->pending);
    CHECK((m->regs[(base+CMD)/4]&0xc011u)==0xc011u);
    CHECK(m->regs[(base+CLB)/4]==(uint32_t)m->bus && m->regs[(base+CLBU)/4]==(uint32_t)(m->bus>>32));
    CHECK(m->regs[(base+FB)/4]==(uint32_t)(m->bus+1024));
    CHECK(m->regs[(base+FBU)/4]==(uint32_t)((m->bus+1024)>>32));
    CHECK(table[0]==0x27 && table[1]==0x80 &&
          (table[2]==0xec || table[2]==0x25 || table[2]==0x35 || table[2]==0xea));
    /* DW0: CFL 5, W (bit 6) only for the host-to-device write, one PRDT except for the non-data flush */
    CHECK(u32(header)==(table[2]==0xea?0x5u:table[2]==0x35?0x10045u:0x10005u) && u32(header+4)==0);
    table_bus=(uint64_t)u32(header+8)|((uint64_t)u32(header+12)<<32);
    CHECK(table_bus==m->bus+1280);
    if(table[2]!=0xea) {
        data_bus=(uint64_t)u32(table+128)|((uint64_t)u32(table+132)<<32);
        CHECK(data_bus==m->bus+2048);
        CHECK(u32(table+136)==0 && u32(table+140)==511);
    } else {
        for(i=128;i<144;++i) CHECK(table[i]==0);
    }
    CHECK(m->device_sync>=3);
    m->opcode=table[2]; m->lba=0;
    for(i=0;i<3;++i) m->lba|=(uint64_t)table[4+i]<<(i*8);
    for(i=0;i<3;++i) m->lba|=(uint64_t)table[8+i]<<((i+3)*8);
    if(m->opcode==0x25 || m->opcode==0x35) CHECK(table[7]==0x40 && table[12]==1 && table[13]==0);
    else if(m->opcode==0xea) CHECK(m->lba==0 && table[7]==0x40 && table[12]==0 && table[13]==0);
    else CHECK(m->lba==0 && table[7]==0 && table[12]==0);
    if(m->opcode==0x35) memcpy(m->pending_data,header+2048,512);   /* what the HBA fetches over DMA */
    m->pending=1;++m->commands;m->cpu_sync=m->device_sync=0;
}
static int write32(void *opaque,uint32_t offset,uint32_t value)
{
    struct model *m=opaque; int failure;uint32_t base=offset&~0x7fu;
    CHECK(!(offset&3u) && offset<sizeof(m->regs));++m->writes;
    failure=failed(m);
    /* A callback failure does not prove the write missed the device. */
    if(offset>=P && offset-base==CMD) {
        CHECK(!(value&8u));
        if((value&1u) && base==m->selected_base)
            CHECK(m->regs[(base+SIG)/4]==0x101 && !(m->regs[(base+TFD)/4]&0x88u));
        if(!(value&16u))CHECK(!(m->regs[(base+CMD)/4]&0x8000u));
        m->regs[offset/4]=value&~0xc000u;
        if((value&1u) || (base==m->selected_base && m->stop_stuck))m->regs[offset/4]|=0x8000u;
        if(value&16u)m->regs[offset/4]|=0x4000u;
        if(base==m->selected_base && !(m->regs[offset/4]&0xc000u))m->pending=0;
    } else if(offset==m->selected_base+CI) {
        issue_command(m,value);m->regs[offset/4]|=value;
    } else if(offset==m->selected_base+PIS || offset==m->selected_base+SERR || offset==8) {
        m->regs[offset/4]&=~value;
    } else if(offset==40) {
        CHECK(!(value&12u));
        m->regs[offset/4]=m->bohc_stuck?value:2;
    } else m->regs[offset/4]=value;
    return !failure;
}
static int allocate(void *opaque,size_t bytes,size_t alignment,uint64_t limit,struct ahci_dma *block)
{
    struct model *m=opaque;
    CHECK(!m->allocation && bytes==4096 && alignment==1024);
    CHECK(limit==((m->regs[0]&0x80000000u)?UINT64_MAX:UINT32_MAX));
    if(failed(m))return 0;
    m->allocation=aligned_alloc(4096,8192);CHECK(m->allocation!=NULL);
    memset(m->allocation,0xa5,8192);++m->allocations;
    block->cpu=m->allocation;block->bus=m->bus;block->bytes=4096;
    if(m->allocation_bad==1)++block->bus;
    if(m->allocation_bad==2)block->bytes=4095;
    if(m->allocation_bad==3)block->cpu=m->allocation+1;
    return 1;
}
static void release(void *opaque,struct ahci_dma *block)
{
    struct model *m=opaque;
    CHECK(m->allocation && block->cpu && !m->pending);
    CHECK(!(m->regs[(m->selected_base+CMD)/4]&0xc011u));
    free(m->allocation);m->allocation=NULL;++m->releases;
}
static int sync_dma(void *opaque,const struct ahci_dma *block,size_t offset,size_t bytes,int to_device)
{
    struct model *m=opaque;
    CHECK(block->cpu==m->allocation && offset<4096 && bytes<=4096-offset);
    CHECK(to_device==0 || to_device==1);++m->syncs;
    if(failed(m))return 0;
    if(to_device)++m->device_sync;else { CHECK(!m->pending);++m->cpu_sync; }
    return 1;
}
static uint64_t now(void *opaque)
{
    struct model *m=opaque;
    if(m->reverse_time && m->clock) return --m->clock;
    return m->clock;
}
static void relax(void *opaque)
{ struct model *m=opaque;if(!m->freeze_time)m->clock+=1000; }
static struct ahci_ops callbacks(struct model *m)
{
    const struct ahci_ops ops={m,read32,write32,allocate,release,sync_dma,now,relax};return ops;
}
static struct ahci_config config(void)
{
    const struct ahci_config cfg={0x010601,6,0x1000,AHCI_AUTO_PORT,1000000,1,0};return cfg;
}
static void reset(struct model *m)
{
    unsigned i; static const char name[]="ORIGINAL MOCK SATA READ ONLY DISK        ";
    memset(m,0,sizeof(*m));m->bus=0x120000;m->selected_base=P;
    m->regs[0]=0x80000000u;m->regs[12/4]=1;m->regs[16/4]=0x10301;
    m->regs[(P+SSTS)/4]=0x123;m->regs[(P+SIG)/4]=0x101;m->regs[(P+TFD)/4]=0x50;
    w16(m->identify,0x0040);w16(m->identify+98,0x0300);w16(m->identify+152,0x0006);
    w16(m->identify+166,0x4400);w32(m->identify+200,0x12345678);w32(m->identify+204,0x1234);
    for(i=0;i<40;++i)m->identify[54+(i^1u)]=(uint8_t)name[i];
}
static void no_leaks(struct model *m)
{ CHECK(!m->allocation && m->allocations==m->releases && !m->pending); }
static void success_and_bounds(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config();
    uint8_t output[513];unsigned i,calls;
    reset(&m);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==AHCI_OK);
    CHECK(a.state==AHCI_READY && a.identity.sectors==UINT64_C(0x123412345678));
    CHECK(a.identity.sector_bytes==512 && !strcmp(a.identity.model,"ORIGINAL MOCK SATA READ ONLY DISK"));
    memset(output,0xa5,sizeof(output));
    CHECK(ahci_read_sector(&a,UINT64_C(0x123401020304),output,sizeof(output))==AHCI_OK);
    for(i=0;i<512;++i)CHECK(output[i]==pattern(UINT64_C(0x123401020304),i));
    CHECK(output[512]==0xa5 && m.commands==2 && m.cpu_sync==2);
    calls=m.calls;
    CHECK(ahci_read_sector(&a,a.identity.sectors,output,512)==AHCI_INVALID);
    CHECK(ahci_read_sector(&a,UINT64_MAX,output,512)==AHCI_INVALID);
    CHECK(ahci_read_sector(&a,0,output,511)==AHCI_INVALID);
    CHECK(ahci_read_sector(&a,0,a.dma.cpu,512)==AHCI_INVALID);
    CHECK(ahci_read_sector(&a,0,&a,512)==AHCI_INVALID);
    CHECK(ahci_read_sector(&a,0,NULL,512)==AHCI_INVALID && m.calls==calls);
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_INVALID);
    CHECK(ahci_close(&a)==AHCI_OK);CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
    CHECK(ahci_read_sector(&a,0,output,512)==AHCI_INVALID);
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_OK);CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
}
static void callback_failures(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config();
    unsigned total,which;uint8_t out[512];int result;
    reset(&m);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==0);
    CHECK(ahci_read_sector(&a,7,out,512)==0);CHECK(ahci_close(&a)==0);total=m.calls;no_leaks(&m);
    for(which=1;which<=total;++which) {
        memset(&a,0,sizeof(a));reset(&m);m.fault=which;ops=callbacks(&m);
        result=ahci_open(&a,&ops,&cfg);
        if(!result) result=ahci_read_sector(&a,7,out,512);
        if(!result) result=ahci_close(&a);
        CHECK(result!=AHCI_OK);
        if(a.state==AHCI_RETAINED) { CHECK(m.allocation);CHECK(ahci_close(&a)==AHCI_OK); }
        no_leaks(&m);
    }
    printf("Fault injected after each of %u MMIO/allocation/sync operations\n",total);
}
static void command_errors(void)
{
    struct model m;struct ahci_device a;struct ahci_ops ops;struct ahci_config cfg=config();
    uint8_t output[512];unsigned mode,i;int result;
    for(mode=0;mode<8;++mode) {
        memset(&a,0,sizeof(a));reset(&m);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==0);
        memset(output,0xa5,sizeof(output));
        if(mode==0)m.late_error=1;
        if(mode==1)m.short_transfer=1;
        if(mode==2)m.unplug=1;
        if(mode>=3 && mode<6)m.never_complete=1;
        if(mode==4)m.freeze_time=1;
        if(mode==5){m.reverse_time=1;m.clock=100;}
        if(mode==6)m.late_error=2;
        if(mode==7)m.late_error=3;
        result=ahci_read_sector(&a,0,output,512);
        CHECK(result==((mode<2 || mode>=6)?AHCI_DEVICE_ERROR:mode==2?AHCI_NO_DEVICE:mode==5?AHCI_CLOCK:AHCI_TIMEOUT));
        CHECK(a.state==AHCI_CLOSED);
        for(i=0;i<512;++i)CHECK(output[i]==0xa5);
        no_leaks(&m);
    }
    memset(&a,0,sizeof(a));reset(&m);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==0);
    m.never_complete=1;m.stop_stuck=1;
    CHECK(ahci_read_sector(&a,0,output,512)==AHCI_QUARANTINED);
    CHECK(a.state==AHCI_RETAINED && a.dma_owned && m.allocation && !m.releases);
    CHECK(ahci_read_sector(&a,0,output,512)==AHCI_INVALID);
    CHECK(ahci_close(&a)==AHCI_QUARANTINED && m.allocation);
    m.stop_stuck=0;CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
}
static void capability_and_dma_errors(void)
{
    struct model m;struct ahci_device a;struct ahci_ops ops;struct ahci_config cfg;
    unsigned mode;int result;
    for(mode=0;mode<15;++mode) {
        reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg=config();
        if(mode==0)cfg.pci_class=0x010802;
        if(mode==1)cfg.pci_command=2;
        if(mode==2)cfg.exclusive=0;
        if(mode==3)m.regs[12/4]=0;
        if(mode==4)m.regs[16/4]=0;
        if(mode==5)m.regs[12/4]=0x80000000u;
        if(mode==6)m.regs[(P+SIG)/4]=0xeb140101;
        if(mode==7)m.regs[(P+SSTS)/4]=0;
        if(mode==8)m.regs[(P+CI)/4]=1;
        if(mode==9)m.regs[(P+SACT)/4]=1;
        if(mode==10)m.stop_stuck=1;
        if(mode>=11 && mode<=13)m.allocation_bad=mode-10;
        if(mode==14){m.regs[0]=0;m.bus=UINT64_C(0x100000000);}
        result=ahci_open(&a,&ops,&cfg);CHECK(result!=AHCI_OK);no_leaks(&m);
        if(mode<3)CHECK(!m.calls);
    }
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg=config();m.bus=UINT64_C(0x123456780000);
    CHECK(ahci_open(&a,&ops,&cfg)==0);CHECK(ahci_close(&a)==0);no_leaks(&m);
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);m.regs[0]=0;m.bus=UINT64_C(0xfffffc00);
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_INVALID);no_leaks(&m);
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);m.bus=UINT64_C(0xfffffffffffffc00);
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_INVALID);no_leaks(&m);
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);m.regs[36/4]=1;m.regs[40/4]=0x19;
    CHECK(ahci_open(&a,&ops,&cfg)==0 && m.regs[40/4]==2);CHECK(ahci_close(&a)==0);no_leaks(&m);
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);m.regs[36/4]=1;m.regs[40/4]=0x11;m.bohc_stuck=1;
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_TIMEOUT);CHECK(m.writes==1 && !m.allocations);no_leaks(&m);
}
static void identify_errors(void)
{
    struct model m;struct ahci_identity id,sentinel;uint8_t data[512];unsigned mode,sum,i;
    reset(&m);memset(&sentinel,0xa5,sizeof(sentinel));
    CHECK(ahci_parse_identify(m.identify,&id)==0);
    for(mode=0;mode<9;++mode) {
        memcpy(data,m.identify,512);memcpy(&id,&sentinel,sizeof(id));
        if(mode==0)memset(data,0,512);
        if(mode==1)memset(data,0xff,512);
        if(mode==2)w16(data,0x8040);
        if(mode==3)w16(data+98,0x100);
        if(mode==4)w16(data,0x0044); /* incomplete IDENTIFY */
        if(mode==5)w16(data+166,0x0400);
        if(mode==6)memset(data+200,0,8);
        if(mode==7)w32(data+204,0x10001);
        if(mode==8){w16(data+212,0x5000);w32(data+234,2048);}
        CHECK(ahci_parse_identify(data,&id)!=0 && !memcmp(&id,&sentinel,sizeof(id)));
    }
    memcpy(data,m.identify,512);data[510]=0xa5;data[511]=0;sum=0;
    for(i=0;i<512;++i)sum+=data[i];data[511]=(uint8_t)(0u-sum);
    CHECK(ahci_parse_identify(data,&id)==0);data[80]^=1;
    CHECK(ahci_parse_identify(data,&id)==AHCI_BAD_IDENTIFY);
    CHECK(ahci_parse_identify(NULL,&id)==AHCI_INVALID);
}
static void sparse_ports_and_initial_state(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config();
    uint8_t output[512];uint32_t other=P+5u*0x80u;unsigned i;
    reset(&m);ops=callbacks(&m);m.regs[0]|=1;m.regs[12/4]|=1u<<5;
    m.regs[(other+CMD)/4]=0xc011;m.regs[(other+PIE)/4]=UINT32_MAX;
    CHECK(ahci_open(&a,&ops,&cfg)==0);
    CHECK(!(m.regs[(other+CMD)/4]&0xc011u) && m.regs[(other+PIE)/4]==0);
    CHECK(ahci_close(&a)==0);no_leaks(&m);
    /* NP is a port count, not a highest-index check: a sparse port31 is legal. */
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg.abar_bytes=0x1100;
    m.regs[12/4]=1u<<31;m.selected_base=P+31u*0x80u;
    m.regs[(m.selected_base+SSTS)/4]=0x123;m.regs[(m.selected_base+SIG)/4]=0x101;
    m.regs[(m.selected_base+TFD)/4]=0x50;
    CHECK(ahci_open(&a,&ops,&cfg)==0 && a.port==31);
    CHECK(ahci_read_sector(&a,3,output,512)==0);
    for(i=0;i<512;++i)CHECK(output[i]==pattern(3,i));
    CHECK(ahci_close(&a)==0);no_leaks(&m);
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg=config();
    m.regs[(P+CMD)/4]=0xc019; /* inherited active engine plus transient CLO */
    m.regs[(P+SERR)/4]=0x100;m.regs[(P+PIS)/4]=1u<<30;m.regs[8/4]=1;
    CHECK(ahci_open(&a,&ops,&cfg)==0);
    CHECK(m.regs[(P+SERR)/4]==0 && m.regs[(P+PIS)/4]==0 && m.regs[8/4]==0);
    CHECK(ahci_close(&a)==0);no_leaks(&m);
}
static void cold_signature_and_fbs(void)
{
    struct model m;struct ahci_device a;struct ahci_ops ops;struct ahci_config cfg=config();
    unsigned mode;
    for(mode=0;mode<3;++mode) {
        reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);
        m.cold_signature=1;m.delivered_signature=mode==0?0x101u:mode==1?0xeb140101u:0;
        m.regs[(P+SIG)/4]=UINT32_MAX;m.regs[(P+TFD)/4]=0x7f;
        CHECK(ahci_open(&a,&ops,&cfg)==(mode==0?AHCI_OK:mode==1?AHCI_UNSUPPORTED:AHCI_TIMEOUT));
        if(mode==0)CHECK(m.commands==1 && ahci_close(&a)==0);
        else CHECK(m.commands==0 && a.state==AHCI_CLOSED);
        no_leaks(&m);
    }
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);
    m.regs[0]|=1u<<16;m.regs[(P+64)/4]=1;
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_UNSUPPORTED && !m.allocations);no_leaks(&m);
}
static void qemu_identify_contract(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config();
    struct ahci_identity id;uint8_t output[512];unsigned i;
    static const char name[]="QEMU HARDDISK                           ";
    reset(&m);ops=callbacks(&m);
    /* Factual words observed from a disposable 8MiB QEMU10.1 AHCI disk.
     * This original fixture combines cold signature readiness and omitted
     * speed metadata; it is not a copied IDENTIFY sector or emulator code. */
    w16(m.identify,0x0040);w16(m.identify+98,0x0b00);
    w16(m.identify+152,0x0100);w16(m.identify+166,0x7400);
    w16(m.identify+212,0x6000);w32(m.identify+200,0x4000);w32(m.identify+204,0);
    for(i=0;i<40;++i)m.identify[54+(i^1u)]=(uint8_t)name[i];
    CHECK(ahci_parse_identify(m.identify,&id)==0 && id.sectors==16384 && id.sector_bytes==512);
    CHECK(!strcmp(id.model,"QEMU HARDDISK"));
    m.cold_signature=1;m.delivered_signature=0x101;
    m.regs[(P+SIG)/4]=UINT32_MAX;m.regs[(P+TFD)/4]=0x7f;
    CHECK(ahci_open(&a,&ops,&cfg)==0);
    CHECK(ahci_read_sector(&a,16383,output,512)==0);
    for(i=0;i<512;++i)CHECK(output[i]==pattern(16383,i));
    CHECK(ahci_read_sector(&a,16384,output,512)==AHCI_INVALID);
    CHECK(ahci_close(&a)==0);no_leaks(&m);
    /* The parser does not infer live transport from optional word76. */
    w16(m.identify+152,0);CHECK(ahci_parse_identify(m.identify,&id)==0);
    w16(m.identify+152,0xffff);CHECK(ahci_parse_identify(m.identify,&id)==0);
}
static struct ahci_config config_rw(void)
{
    struct ahci_config cfg=config();cfg.allow_write=1;return cfg;
}
static void write_read_flush(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config_rw();
    uint8_t in[512],copy_in[512],out[512];unsigned i,calls;
    const uint64_t lba=UINT64_C(0x123400000777);
    reset(&m);w16(m.identify+166,0x6400);ops=callbacks(&m);
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_OK && a.writable==1 && (a.identity.features&AHCI_FEATURE_FLUSH_EXT));
    for(i=0;i<512;++i) in[i]=(uint8_t)(i*7u+3u);
    memcpy(copy_in,in,512);
    CHECK(ahci_read_sector(&a,lba,out,512)==AHCI_OK && out[5]==pattern(lba,5));
    CHECK(ahci_write_sector(&a,lba,in,512)==AHCI_OK);
    CHECK(!memcmp(in,copy_in,512) && m.writes_done==1 && m.nwritten==1 && m.written_lba[0]==lba);
    CHECK(!memcmp(m.written[0],in,512));
    memset(out,0,512);
    CHECK(ahci_read_sector(&a,lba,out,512)==AHCI_OK && !memcmp(out,in,512));
    CHECK(ahci_read_sector(&a,lba+1,out,512)==AHCI_OK && out[9]==pattern(lba+1,9));
    CHECK(ahci_flush(&a)==AHCI_OK && m.flushes==1);
    CHECK(ahci_write_sector(&a,a.identity.sectors-1,in,512)==AHCI_OK && m.nwritten==2);
    calls=m.calls;
    CHECK(ahci_write_sector(&a,a.identity.sectors,in,512)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,UINT64_MAX,in,512)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,0,in,511)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,0,in,513)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,0,NULL,512)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,0,(uint8_t *)a.dma.cpu+2048,512)==AHCI_INVALID);
    CHECK(ahci_write_sector(&a,0,&a,512)==AHCI_INVALID && m.calls==calls);
    CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
    CHECK(ahci_write_sector(&a,0,in,512)==AHCI_INVALID && ahci_flush(&a)==AHCI_INVALID);
    /* read-only open: writes and flushes are refused without touching the device */
    reset(&m);memset(&a,0,sizeof(a));w16(m.identify+166,0x6400);ops=callbacks(&m);cfg=config();
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_OK && a.writable==0);calls=m.calls;
    CHECK(ahci_write_sector(&a,1,in,512)==AHCI_UNSUPPORTED && ahci_flush(&a)==AHCI_UNSUPPORTED);
    CHECK(m.calls==calls && m.commands==1 && a.state==AHCI_READY);
    CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
    /* no FLUSH CACHE EXT in IDENTIFY: refused before any command */
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg=config_rw();
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_OK && !(a.identity.features&AHCI_FEATURE_FLUSH_EXT));calls=m.calls;
    CHECK(ahci_flush(&a)==AHCI_UNSUPPORTED && m.calls==calls && a.state==AHCI_READY);
    CHECK(ahci_write_sector(&a,2,in,512)==AHCI_OK && m.writes_done==1);
    CHECK(ahci_close(&a)==AHCI_OK);no_leaks(&m);
    /* allow_write must be 0 or 1 */
    reset(&m);memset(&a,0,sizeof(a));ops=callbacks(&m);cfg=config();cfg.allow_write=2;
    CHECK(ahci_open(&a,&ops,&cfg)==AHCI_INVALID && !m.calls);
}
static void write_callback_failures(void)
{
    struct model m;struct ahci_device a={0};struct ahci_ops ops;struct ahci_config cfg=config_rw();
    unsigned total,which;uint8_t in[512];int result;
    memset(in,0x5a,sizeof(in));
    reset(&m);w16(m.identify+166,0x6400);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==0);
    CHECK(ahci_write_sector(&a,9,in,512)==0);CHECK(ahci_flush(&a)==0);CHECK(ahci_close(&a)==0);total=m.calls;no_leaks(&m);
    for(which=1;which<=total;++which) {
        memset(&a,0,sizeof(a));reset(&m);w16(m.identify+166,0x6400);m.fault=which;ops=callbacks(&m);
        result=ahci_open(&a,&ops,&cfg);
        if(!result) result=ahci_write_sector(&a,9,in,512);
        if(!result) result=ahci_flush(&a);
        if(!result) result=ahci_close(&a);
        CHECK(result!=AHCI_OK);
        if(a.state==AHCI_RETAINED) { CHECK(m.allocation);CHECK(ahci_close(&a)==AHCI_OK); }
        no_leaks(&m);
    }
    printf("Write path: fault injected after each of %u MMIO/allocation/sync operations\n",total);
}
static void write_command_errors(void)
{
    struct model m;struct ahci_device a;struct ahci_ops ops;struct ahci_config cfg=config_rw();
    uint8_t in[512];unsigned mode,op;int result;
    memset(in,0x3c,sizeof(in));
    for(op=0;op<2;++op) for(mode=0;mode<8;++mode) {
        memset(&a,0,sizeof(a));reset(&m);w16(m.identify+166,0x6400);ops=callbacks(&m);CHECK(ahci_open(&a,&ops,&cfg)==0);
        if(mode==0)m.late_error=1;
        if(mode==1)m.short_transfer=1;
        if(mode==2)m.unplug=1;
        if(mode>=3 && mode<6)m.never_complete=1;
        if(mode==4)m.freeze_time=1;
        if(mode==5){m.reverse_time=1;m.clock=100;}
        if(mode==6)m.late_error=2;
        if(mode==7)m.late_error=3;
        result=op?ahci_flush(&a):ahci_write_sector(&a,4,in,512);
        CHECK(result==((mode<2 || mode>=6)?AHCI_DEVICE_ERROR:mode==2?AHCI_NO_DEVICE:mode==5?AHCI_CLOCK:AHCI_TIMEOUT));
        CHECK(a.state==AHCI_CLOSED);
        if(op==0 && mode>=3 && mode<6) CHECK(m.nwritten==0);
        no_leaks(&m);
    }
}
int main(void)
{
    success_and_bounds();callback_failures();command_errors();capability_and_dma_errors();identify_errors();
    write_read_flush();write_callback_failures();write_command_errors();
    sparse_ports_and_initial_state();
    cold_signature_and_fbs();
    qemu_identify_contract();
    printf("PASS: AHCI native core %u assertions; no model DMA freed while active\n",assertions);
    return 0;
}
