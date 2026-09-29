/* SPDX-License-Identifier: GPL-2.0-only
 * Original AHCI implementation from public interface facts. See REFERENCES.md.
 * Commands: IDENTIFY DEVICE, READ DMA EXT and, when the caller opted in (ahci_config.allow_write), WRITE DMA EXT and
 * FLUSH CACHE EXT. One slot, one 512-byte sector per command, polled completion.
 */
#include "ahci.h"

enum { CAP=0, GHC=4, IS=8, PI=12, VS=16, CAP2=36, BOHC=40,
       CLB=0, CLBU=4, FB=8, FBU=12, PIS=16, PIE=20, CMD=24,
       TFD=32, SIG=36, SSTS=40, SERR=48, SACT=52, CI=56, FBS=64,
       FIS_OFFSET=1024, TABLE_OFFSET=1280, DATA_OFFSET=2048 };
#define GHC_AE UINT32_C(0x80000000)
#define CAP_64 UINT32_C(0x80000000)
#define PORT_ERRORS UINT32_C(0x7d800010)
#define CMD_ST UINT32_C(1)
#define CMD_FRE UINT32_C(16)
#define CMD_FR UINT32_C(0x4000)
#define CMD_CR UINT32_C(0x8000)
#define STOP_US UINT32_C(500000)

static void zero(void *memory, size_t bytes)
{ uint8_t *p=memory; while(bytes--) *p++=0; }
static void copy(void *out, const void *in, size_t bytes)
{ uint8_t *d=out; const uint8_t *s=in; while(bytes--) *d++=*s++; }
static uint16_t get16(const uint8_t *p)
{ return (uint16_t)((uint16_t)p[0] | (uint16_t)((uint16_t)p[1]<<8)); }
static uint32_t get32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static void put32(uint8_t *p, uint32_t value)
{ unsigned i; for(i=0;i<4;++i) p[i]=(uint8_t)(value>>(i*8)); }
static int rd(struct ahci_device *a, uint32_t offset, uint32_t *value)
{
    if ((offset&3u) || offset>a->abar_bytes-4u) return AHCI_INVALID;
    return a->ops.read32(a->ops.context,offset,value) ? AHCI_OK : AHCI_IO;
}
static int wr(struct ahci_device *a, uint32_t offset, uint32_t value)
{
    if ((offset&3u) || offset>a->abar_bytes-4u) return AHCI_INVALID;
    return a->ops.write32(a->ops.context,offset,value) ? AHCI_OK : AHCI_IO;
}
struct deadline { uint64_t start, last; uint32_t polls; };
static void begin(struct ahci_device *a, struct deadline *d)
{ d->start=d->last=a->ops.now_us(a->ops.context); d->polls=0; }
static int expired(struct ahci_device *a, struct deadline *d, uint32_t limit)
{
    uint64_t now=a->ops.now_us(a->ops.context);
    if (now<d->last) return AHCI_CLOCK;
    d->last=now;
    if (now-d->start>=limit || ++d->polls>=AHCI_POLL_LIMIT) return AHCI_TIMEOUT;
    a->ops.relax(a->ops.context);
    return AHCI_OK;
}
static int wait_bits(struct ahci_device *a, uint32_t offset, uint32_t mask,
                      uint32_t expected, uint32_t timeout)
{
    struct deadline d; uint32_t value; int result;
    begin(a,&d);
    for (;;) {
        result=rd(a,offset,&value); if(result) return result;
        if ((value&mask)==expected) return AHCI_OK;
        result=expired(a,&d,timeout); if(result) return result;
    }
}
static int stop_port(struct ahci_device *a, uint32_t base)
{
    uint32_t value; int result;
    if ((result=rd(a,base+CMD,&value))!=0) return result;
    /* CLO is an action bit, never replay it in a read/modify/write. */
    if ((result=wr(a,base+CMD,value&~(CMD_ST|8u)))!=0) return result;
    if ((result=wait_bits(a,base+CMD,CMD_CR,0,STOP_US))!=0) return result;
    if ((result=rd(a,base+CMD,&value))!=0) return result;
    if ((result=wr(a,base+CMD,value&~(CMD_FRE|CMD_ST|8u)))!=0) return result;
    return wait_bits(a,base+CMD,CMD_FR|CMD_CR|CMD_ST|CMD_FRE,0,STOP_US);
}
static int clear_status(struct ahci_device *a)
{
    int result;
    if ((result=rd(a,a->port_base+SERR,&a->last_serr))!=0 ||
        (result=rd(a,a->port_base+PIS,&a->last_is))!=0) return result;
    if ((result=wr(a,a->port_base+SERR,a->last_serr))!=0 ||
        (result=wr(a,a->port_base+PIS,a->last_is))!=0 ||
        (result=wr(a,IS,UINT32_C(1)<<a->port))!=0) return result;
    return AHCI_OK;
}
static int sync_area(struct ahci_device *a,size_t offset,size_t bytes,int to_device)
{ return a->ops.sync(a->ops.context,&a->dma,offset,bytes,to_device)?AHCI_OK:AHCI_IO; }

int ahci_close(struct ahci_device *a)
{
    int result;
    if (!a) return AHCI_INVALID;
    if (a->state==AHCI_EMPTY || a->state==AHCI_CLOSED) return AHCI_OK;
    if (a->dma_published) {
        result=stop_port(a,a->port_base);
        if (!result) result=wr(a,a->port_base+PIE,0);
        if (!result) result=wr(a,a->port_base+CLB,0);
        if (!result) result=wr(a,a->port_base+CLBU,0);
        if (!result) result=wr(a,a->port_base+FB,0);
        if (!result) result=wr(a,a->port_base+FBU,0);
        if (result) {
            a->state=AHCI_RETAINED;
            a->last_error=AHCI_QUARANTINED;
            return AHCI_QUARANTINED;
        }
        a->dma_published=0;
    }
    if (a->dma_owned) {
        a->ops.release(a->ops.context,&a->dma);
        zero(&a->dma,sizeof(a->dma)); a->dma_owned=0;
    }
    a->state=AHCI_CLOSED;
    return AHCI_OK;
}
static int fail(struct ahci_device *a,int reason)
{
    a->last_error=reason;
    return ahci_close(a)==AHCI_QUARANTINED ? AHCI_QUARANTINED : reason;
}
static int handoff(struct ahci_device *a)
{
    uint32_t cap2=0,bohc,ghc; int result;
    if (a->version>=UINT32_C(0x00010200)) {
        if ((result=rd(a,CAP2,&cap2))!=0) return result;
        if (cap2&1u) {
            if ((result=rd(a,BOHC,&bohc))!=0) return result;
            /* Preserve BIOS-owned bits, disable ownership-change interrupt,
             * avoid acknowledging W1C OOC as a side effect. Never force BOS. */
            if ((result=wr(a,BOHC,(bohc&0x11u)|2u))!=0) return result;
            if ((result=wait_bits(a,BOHC,0x13u,2,2025000))!=0) return result;
        }
    }
    a->ownership_acquired=1;
    if ((result=rd(a,GHC,&ghc))!=0) return result;
    if (ghc&1u) return AHCI_BUSY; /* reset in progress */
    if ((result=wr(a,GHC,(ghc|GHC_AE)&~2u))!=0) return result;
    return wait_bits(a,GHC,GHC_AE|3u,GHC_AE,STOP_US);
}
static int wait_signature(struct ahci_device *a)
{
    struct deadline d; uint32_t signature,status; int result;
    begin(a,&d);
    for (;;) {
        if ((result=rd(a,a->port_base+SIG,&signature))!=0 ||
            (result=rd(a,a->port_base+SSTS,&status))!=0 ||
            (result=rd(a,a->port_base+TFD,&a->last_tfd))!=0) return result;
        if ((status&0xf0fu)!=0x103u) return AHCI_NO_DEVICE;
        if (signature && signature!=UINT32_MAX) {
            if (signature!=0x00000101) return AHCI_UNSUPPORTED;
            if (!(a->last_tfd&0x88u))
                /* Initial signature status is not a command completion.
                 * QEMU10.1 sends status0x30/error1 here; readiness is BSY/DRQ.
                 * Issued command completion below still checks DF and ERR. */
                return AHCI_OK;
        }
        if ((result=expired(a,&d,a->timeout_us))!=0) return result;
    }
}

int ahci_parse_identify(const uint8_t data[512], struct ahci_identity *out)
{
    struct ahci_identity identity; uint16_t word; unsigned i,sum=0;
    uint64_t sectors;
    if (!data || !out) return AHCI_INVALID;
    if (get16(data)==0 || get16(data)==0xffff || (get16(data)&0x8004u))
        return AHCI_BAD_IDENTIFY; /* ATA device; complete IDENTIFY data */
    if ((get16(data+98)&0x0300u)!=0x0300u) return AHCI_UNSUPPORTED;
    /* Word76 speed advertisement is not a READ DMA EXT prerequisite.
     * The live path establishes ATA/SATA transport with SSTS and SIG;
     * emulated disks can omit speed bits while supporting DMA and LBA48. */
    word=get16(data+166);
    if ((word&0xc400u)!=0x4400u) return AHCI_UNSUPPORTED; /* valid LBA48 */
    sectors=(uint64_t)get32(data+200)|((uint64_t)get32(data+204)<<32);
    if (!sectors || sectors>UINT64_C(0x0001000000000000)) return AHCI_BAD_IDENTIFY;
    word=get16(data+212);
    if ((word&0xc000u)==0x4000u && (word&0x1000u))
        return AHCI_UNSUPPORTED;
    if (data[510]==0xa5) {
        for(i=0;i<512;++i) sum+=data[i];
        if ((sum&255u)!=0) return AHCI_BAD_IDENTIFY;
    }
    zero(&identity,sizeof(identity)); identity.sectors=sectors; identity.sector_bytes=512;
    if (get16(data+166)&0x2000u) identity.features|=AHCI_FEATURE_FLUSH_EXT;       /* word 83 bit 13 */
    word=get16(data+170);                                                         /* word 85: enabled features */
    if ((get16(data+174)&0xc000u)==0x4000u && (word&0x20u)) identity.features|=AHCI_FEATURE_WRITE_CACHE;
    for(i=0;i<40;++i) {
        uint8_t c=data[54+(i^1u)];
        identity.model[i]=(char)(c>=32 && c<127?c:'?');
    }
    for(i=40;i>0 && identity.model[i-1]==' ';--i) identity.model[i-1]=0;
    copy(out,&identity,sizeof(identity));
    return AHCI_OK;
}

/* Opcodes: 0xec IDENTIFY DEVICE and 0x25 READ DMA EXT (device to host, 512 bytes), 0x35 WRITE DMA EXT (host to
 * device, the 512 bytes at `input`), 0xea FLUSH CACHE EXT (no data, no PRDT). */
static int issue(struct ahci_device *a,uint8_t command,uint64_t lba,const void *input)
{
    uint8_t *memory=a->dma.cpu,*table=memory+TABLE_OFFSET;
    uint64_t table_bus=a->dma.bus+TABLE_OFFSET,data_bus=a->dma.bus+DATA_OFFSET;
    uint32_t value,active,status,expect_bytes=512; struct deadline d; unsigned i; int result;
    if (command!=0xec && command!=0x25 && command!=0x35 && command!=0xea) return AHCI_UNSUPPORTED;
    if ((command==0x35)!=(input!=0)) return AHCI_INVALID;
    if ((result=rd(a,a->port_base+CMD,&status))!=0) return result;
    if ((status&(CMD_ST|CMD_FRE|CMD_CR|CMD_FR))!=(CMD_ST|CMD_FRE|CMD_CR|CMD_FR))
        return AHCI_DEVICE_ERROR;
    if ((result=rd(a,a->port_base+CI,&value))!=0 ||
        (result=rd(a,a->port_base+SACT,&active))!=0) return result;
    if (value || active) return AHCI_BUSY;
    if ((result=wait_bits(a,a->port_base+TFD,0x88,0,a->timeout_us))!=0) return result;
    if ((result=clear_status(a))!=0) return result;
    zero(memory,32); zero(table,256);
    if (input) copy(memory+DATA_OFFSET,input,512); else zero(memory+DATA_OFFSET,512);
    if (command==0xea) {
        put32(memory,5u); expect_bytes=0; /* 20-byte CFIS, no PRDT: non-data command */
    } else {
        /* 20-byte CFIS, one PRDT; W (bit 6) set only for the host-to-device WRITE DMA EXT */
        put32(memory,5u|(command==0x35?(1u<<6):0u)|(1u<<16));
    }
    put32(memory+8,(uint32_t)table_bus); put32(memory+12,(uint32_t)(table_bus>>32));
    table[0]=0x27; table[1]=0x80; table[2]=command;
    if (command==0x25 || command==0x35) {
        uint32_t lower=(uint32_t)lba,upper=(uint32_t)(lba>>24);
        table[7]=0x40; table[12]=1;
        for(i=0;i<3;++i) { table[4+i]=(uint8_t)(lower>>(i*8)); table[8+i]=(uint8_t)(upper>>(i*8)); }
    } else if (command==0xea) {
        table[7]=0x40;
    }
    if (expect_bytes) {
        put32(table+128,(uint32_t)data_bus); put32(table+132,(uint32_t)(data_bus>>32));
        put32(table+140,511); /* exact 512 bytes, no interrupt-on-completion */
    }
    if ((result=sync_area(a,0,32,1))!=0 ||
        (result=sync_area(a,TABLE_OFFSET,256,1))!=0 ||
        (result=sync_area(a,DATA_OFFSET,512,1))!=0) return result;
    if ((result=wr(a,a->port_base+CI,1))!=0) return result;
    begin(a,&d);
    for (;;) {
        if ((result=rd(a,a->port_base+PIS,&a->last_is))!=0 ||
            (result=rd(a,a->port_base+TFD,&a->last_tfd))!=0 ||
            (result=rd(a,a->port_base+SSTS,&status))!=0 ||
            (result=rd(a,a->port_base+CI,&value))!=0 ||
            (result=rd(a,a->port_base+SACT,&active))!=0) return result;
        /* PxTFD may still contain the initial signature or prior status while
         * this command is pending. New interrupt error bits are authoritative
         * during execution; final TFD is validated after CI/SACT clear. */
        if (a->last_is&PORT_ERRORS) return AHCI_DEVICE_ERROR;
        if ((status&0xf0fu)!=0x103u) return AHCI_NO_DEVICE;
        if (!value && !active) break;
        if ((value&~1u) || active) return AHCI_BUSY;
        if ((result=expired(a,&d,a->timeout_us))!=0) return result;
    }
    /* Completion may race the earlier status reads. Sample final status only
     * after observing CI/SACT clear; never accept a late task-file error. */
    if ((result=rd(a,a->port_base+PIS,&a->last_is))!=0 ||
        (result=rd(a,a->port_base+TFD,&a->last_tfd))!=0 ||
        (result=rd(a,a->port_base+SSTS,&status))!=0) return result;
    if ((a->last_is&PORT_ERRORS) || (a->last_tfd&0xa9u)) return AHCI_DEVICE_ERROR;
    if ((status&0xf0fu)!=0x103u) return AHCI_NO_DEVICE;
    if ((result=sync_area(a,0,32,0))!=0 ||
        (result=sync_area(a,DATA_OFFSET,512,0))!=0) return result;
    return get32(memory+4)==expect_bytes ? AHCI_OK : AHCI_DEVICE_ERROR;
}

int ahci_open(struct ahci_device *a,const struct ahci_ops *ops,const struct ahci_config *cfg)
{
    uint32_t i,base,value,signature,count=0; uint64_t max_bus; int result;
    struct ahci_ops callbacks; struct ahci_config config;
    if (!a || !ops || !cfg || (a->state!=AHCI_EMPTY && a->state!=AHCI_CLOSED) ||
        !ops->read32 || !ops->write32 || !ops->allocate || !ops->release ||
        !ops->sync || !ops->now_us || !ops->relax || cfg->exclusive!=1 ||
        cfg->pci_class!=0x010601 || (cfg->pci_command&6u)!=6u ||
        cfg->abar_bytes<0x180 || cfg->port>AHCI_AUTO_PORT ||
        !cfg->command_timeout_us || cfg->command_timeout_us>30000000 || cfg->allow_write>1)
        return AHCI_INVALID;
    copy(&callbacks,ops,sizeof(callbacks)); copy(&config,cfg,sizeof(config));
    ops=&callbacks; cfg=&config;
    zero(a,sizeof(*a)); copy(&a->ops,ops,sizeof(a->ops)); a->abar_bytes=cfg->abar_bytes;
    a->timeout_us=cfg->command_timeout_us; a->writable=cfg->allow_write?1u:0u; a->state=AHCI_STARTING;
    if ((result=rd(a,CAP,&a->cap))!=0 || (result=rd(a,PI,&a->ports))!=0 ||
        (result=rd(a,VS,&a->version))!=0) return fail(a,result);
    if (a->cap==UINT32_MAX || !a->ports || a->version<0x10000 || a->version>0x10301)
        return fail(a,AHCI_UNSUPPORTED);
    for(i=0;i<32;++i) if(a->ports&(UINT32_C(1)<<i)) {
        ++count;
        if (0x100u+(i+1u)*0x80u>a->abar_bytes) return fail(a,AHCI_INVALID);
    }
    if (count>(a->cap&31u)+1u) return fail(a,AHCI_INVALID);
    if (cfg->port<32 && !(a->ports&(UINT32_C(1)<<cfg->port))) return fail(a,AHCI_NO_DEVICE);
    if ((result=handoff(a))!=0) return fail(a,result);
    for(i=0;i<32;++i) if(a->ports&(UINT32_C(1)<<i)) {
        base=0x100u+i*0x80u;
        if ((result=wr(a,base+PIE,0))!=0 || (result=stop_port(a,base))!=0)
            return fail(a,result);
    }
    a->port=AHCI_AUTO_PORT;
    for(i=0;i<32;++i) if((a->ports&(UINT32_C(1)<<i)) && (cfg->port==AHCI_AUTO_PORT || cfg->port==i)) {
        base=0x100u+i*0x80u;
        if ((result=rd(a,base+SSTS,&value))!=0 || (result=rd(a,base+SIG,&signature))!=0)
            return fail(a,result);
        /* A connected device may not have delivered its initial D2H signature
         * while FRE was disabled. Select a candidate without assuming SIG is
         * valid; final ATA confirmation follows owned FIS-buffer setup. */
        if ((value&0xf0fu)==0x103u &&
            (signature==0x00000101 || signature==0 || signature==UINT32_MAX)) {
            a->port=i; break;
        }
    }
    if(a->port==AHCI_AUTO_PORT) return fail(a,AHCI_NO_DEVICE);
    a->port_base=0x100u+a->port*0x80u;
    if ((result=rd(a,a->port_base+CI,&value))!=0 || (result=rd(a,a->port_base+SACT,&signature))!=0)
        return fail(a,result);
    if(value || signature) return fail(a,AHCI_BUSY);
    /* FIS-based switching needs 4 KiB of receive storage, not our 256 bytes.
     * Reject inherited FBS before publishing the small receive buffer. */
    if (a->cap&(UINT32_C(1)<<16)) {
        if ((result=rd(a,a->port_base+FBS,&value))!=0) return fail(a,result);
        if(value&1u) return fail(a,AHCI_UNSUPPORTED);
    }
    max_bus=(a->cap&CAP_64)?UINT64_MAX:UINT32_MAX;
    if (!ops->allocate(ops->context,AHCI_DMA_BYTES,1024,max_bus,&a->dma)) return fail(a,AHCI_NO_MEMORY);
    a->dma_owned=1;
    if (!a->dma.cpu || ((uintptr_t)a->dma.cpu&1023u) ||
        (uintptr_t)a->dma.cpu>UINTPTR_MAX-(AHCI_DMA_BYTES-1u) || (a->dma.bus&1023u) ||
        a->dma.bytes<AHCI_DMA_BYTES || a->dma.bus>max_bus-(AHCI_DMA_BYTES-1u))
        return fail(a,AHCI_INVALID);
    zero(a->dma.cpu,AHCI_DMA_BYTES);
    if ((result=sync_area(a,0,AHCI_DMA_BYTES,1))!=0) return fail(a,result);
    /* From the first base write onward, any ambiguous failure must quiesce the
     * engine before freeing; write callbacks may fail after reaching hardware. */
    a->dma_published=1;
    if ((result=wr(a,a->port_base+CLB,(uint32_t)a->dma.bus))!=0 ||
        (result=wr(a,a->port_base+CLBU,(uint32_t)(a->dma.bus>>32)))!=0 ||
        (result=wr(a,a->port_base+FB,(uint32_t)(a->dma.bus+FIS_OFFSET)))!=0 ||
        (result=wr(a,a->port_base+FBU,(uint32_t)((a->dma.bus+FIS_OFFSET)>>32)))!=0 ||
        (result=clear_status(a))!=0 || (result=rd(a,a->port_base+CMD,&value))!=0)
        return fail(a,result);
    if (value&(UINT32_C(1)<<17)) return fail(a,AHCI_UNSUPPORTED); /* port multiplier */
    value&=~(UINT32_C(0xf0000000)|(UINT32_C(1)<<26)|(UINT32_C(1)<<24)|8u);
    if ((result=wr(a,a->port_base+CMD,value|CMD_FRE))!=0 ||
        (result=wait_bits(a,a->port_base+CMD,CMD_FR,CMD_FR,STOP_US))!=0 ||
        (result=wait_signature(a))!=0 ||
        (result=wr(a,a->port_base+CMD,value|CMD_FRE|CMD_ST))!=0 ||
        (result=wait_bits(a,a->port_base+CMD,CMD_CR,CMD_CR,STOP_US))!=0)
        return fail(a,result);
    if ((result=issue(a,0xec,0,0))!=0) return fail(a,result);
    if ((result=ahci_parse_identify((uint8_t *)a->dma.cpu+DATA_OFFSET,&a->identity))!=0)
        return fail(a,result);
    a->state=AHCI_READY; return AHCI_OK;
}

int ahci_read_sector(struct ahci_device *a,uint64_t lba,void *out,size_t bytes)
{
    int result; uintptr_t start=(uintptr_t)out,dma,context;
    if (!a || a->state!=AHCI_READY || !out || bytes<512 || lba>=a->identity.sectors ||
        lba>=UINT64_C(0x0001000000000000) || start>UINTPTR_MAX-512u) return AHCI_INVALID;
    dma=(uintptr_t)a->dma.cpu; context=(uintptr_t)a;
    if ((start<=dma ? dma-start<512u : start-dma<AHCI_DMA_BYTES) ||
        (start<=context ? context-start<512u : start-context<sizeof(*a))) return AHCI_INVALID;
    if ((result=issue(a,0x25,lba,0))!=0) return fail(a,result);
    copy(out,(uint8_t *)a->dma.cpu+DATA_OFFSET,512);
    return AHCI_OK;
}

int ahci_write_sector(struct ahci_device *a,uint64_t lba,const void *in,size_t bytes)
{
    int result; uintptr_t start=(uintptr_t)in,dma,context;
    if (!a || a->state!=AHCI_READY || !in || bytes!=512 || lba>=a->identity.sectors ||
        lba>=UINT64_C(0x0001000000000000) || start>UINTPTR_MAX-512u) return AHCI_INVALID;
    if (!a->writable) return AHCI_UNSUPPORTED;
    dma=(uintptr_t)a->dma.cpu; context=(uintptr_t)a;
    if ((start<=dma ? dma-start<512u : start-dma<AHCI_DMA_BYTES) ||
        (start<=context ? context-start<512u : start-context<sizeof(*a))) return AHCI_INVALID;
    if ((result=issue(a,0x35,lba,in))!=0) return fail(a,result);
    return AHCI_OK;
}

int ahci_flush(struct ahci_device *a)
{
    int result;
    if (!a || a->state!=AHCI_READY) return AHCI_INVALID;
    if (!a->writable) return AHCI_UNSUPPORTED;
    if (!(a->identity.features&AHCI_FEATURE_FLUSH_EXT)) return AHCI_UNSUPPORTED;
    if ((result=issue(a,0xea,0,0))!=0) return fail(a,result);
    return AHCI_OK;
}
