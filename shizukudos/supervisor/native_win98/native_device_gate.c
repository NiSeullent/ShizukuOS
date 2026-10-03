/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor-only control channel. No PCI data write, BAR probe, VGA access,
 * MMIO/reset/DMA operation is performed by this gate. Physical provenance is
 * supplied only by the future actual owned host counterpart, not this parser. */
#include "native_device_gate.h"
#include "l1_vga.h"
#include "persistence_config.h"
#include "../src/cpu.h"
static w98_native_gate_t lifetime;
static uint16_t le16(const uint8_t *p){return p[0]|(uint16_t)p[1]<<8;}
static uint32_t le32(const uint8_t *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t le64(const uint8_t *p){return (uint64_t)le32(p)|(uint64_t)le32(p+4)<<32;}
static uint32_t be32(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static void copy(uint8_t *d,const uint8_t *s,unsigned n){for(unsigned i=0;i<n;i++)d[i]=s[i];}
static void zero(uint8_t *d,unsigned n){for(unsigned i=0;i<n;i++)d[i]=0;}
static int empty(const uint8_t *p,unsigned n){unsigned a=0;for(unsigned i=0;i<n;i++)a|=p[i];return !a;}
static int equal(const uint8_t *p,const uint8_t *q,unsigned n){unsigned a=0;for(unsigned i=0;i<n;i++)a|=p[i]^q[i];return !a;}
static uint32_t rotate(uint32_t v,unsigned n){return v>>n|v<<(32-n);}
static void sha_block(uint32_t h[8],const uint8_t b[64])
{
    static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64],a=h[0],b0=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7];
    for(unsigned i=0;i<16;i++)w[i]=be32(b+i*4);
    for(unsigned i=16;i<64;i++)w[i]=w[i-16]+(rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10));
    for(unsigned i=0;i<64;i++){uint32_t t=z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t q=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b0)^(a&c)^(b0&c));z=g;g=f;f=e;e=d+t;d=c;c=b0;b0=a;a=t+q;}
    h[0]+=a;h[1]+=b0;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
}
int w98_gate_sha256(const uint8_t *p,uint64_t n,uint8_t out[32])
{
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};uint8_t tail[128];unsigned at=0,remaining;
    if(!out || (!p && n) || n>65536)return -1;
    while(n-at>=64){sha_block(h,p+at);at+=64;}
    zero(tail,sizeof tail);remaining=(unsigned)n-at;if(remaining)copy(tail,p+at,remaining);tail[remaining]=0x80;
    unsigned extent=remaining<56?64:128;uint64_t bits=n*8;for(unsigned i=0;i<8;i++)tail[extent-1-i]=(uint8_t)(bits>>(i*8));
    sha_block(h,tail);if(extent==128)sha_block(h,tail+64);
    for(unsigned i=0;i<32;i++)out[i]=(uint8_t)(h[i/4]>>(24-(i%4)*8));
    return 0;
}
static const shz_blob_t *blob(const shz_info_t *i,const char *name,int *error)
{
    const shz_blob_t *found=0;
    for(unsigned b=0;b<SHZ_MAX_BLOBS;b++){unsigned n=0;while(n<16 && name[n] && i->blobs[b].name[n]==name[n])n++;
        if(n<16 && !name[n] && !i->blobs[b].name[n]){const shz_blob_t *v=&i->blobs[b];if(found || !v->base || !v->size || v->base>UINT64_MAX-v->size){*error=1;return 0;}found=v;}}
    return found;
}
static int current(w98_native_gate_t *g)
{
    uint64_t n=g->ports.now(g->ports.opaque);if(g->deadline!=g->original_deadline || n<g->last_now || n>=g->original_deadline)return -1;g->last_now=n;return 0;
}
static int read_port(w98_native_gate_t *g,uint16_t port,unsigned bytes,uint32_t *out)
{if(current(g) || g->port_calls>=W98_GATE_PORT_CALLS_MAX)return -1;++g->port_calls;return g->ports.read(g->ports.opaque,port,bytes,out) || (bytes==1 && *out>255) || current(g)?-1:0;}
static int write_port(w98_native_gate_t *g,uint16_t port,unsigned bytes,uint32_t value)
{if(current(g) || g->port_calls>=W98_GATE_PORT_CALLS_MAX)return -1;++g->port_calls;return g->ports.write(g->ports.opaque,port,bytes,value) || current(g)?-1:0;}
static int fw_read(w98_native_gate_t *g,unsigned selector,uint8_t *out,unsigned n)
{
    uint32_t v;if(write_port(g,0x510,2,selector))return -1;
    for(unsigned i=0;i<n;i++){if(read_port(g,0x511,1,&v) || v>255)return -1;out[i]=(uint8_t)v;}return 0;
}
static int policy_read(w98_native_gate_t *g,uint8_t policy[256])
{
    uint8_t signature[4],count[4],row[64];uint16_t selectors[W98_GATE_DIRECTORY_MAX];unsigned chosen=0;
    if(fw_read(g,0,signature,4) || !equal(signature,(const uint8_t *)"QEMU",4) || write_port(g,0x510,2,0x19))return -1;
    for(unsigned i=0;i<4;i++){uint32_t v;if(read_port(g,0x511,1,&v) || v>255)return -1;count[i]=(uint8_t)v;}
    unsigned entries=be32(count);if(!entries || entries>W98_GATE_DIRECTORY_MAX)return -1;
    for(unsigned i=0;i<entries;i++){
        for(unsigned b=0;b<64;b++){uint32_t v;if(read_port(g,0x511,1,&v) || v>255)return -1;row[b]=(uint8_t)v;}
        unsigned selector=(unsigned)row[4]<<8|row[5];if(selector<0x20 || selector>=0x4000 || row[6] || row[7])return -1;
        for(unsigned b=0;b<i;b++)if(selectors[b]==selector)return -1;
        selectors[i]=(uint16_t)selector;
        unsigned b=0;while(b<56 && row[8+b]){if(row[8+b]<32 || row[8+b]>=127)return -1;b++;}if(b==56)return -1;
        if(b==sizeof W98_GATE_POLICY_NAME-1 && equal(row+8,(const uint8_t *)W98_GATE_POLICY_NAME,b)){
            if(chosen || be32(row)!=256 || !empty(row+8+b,56-b))return -1;
            chosen=selector;
        }
    }
    return !chosen || fw_read(g,chosen,policy,256)?-1:0;
}
static int config_hash(const shz_blob_t *b,const uint8_t expected[32])
{uint8_t digest[32];return !b || w98_gate_sha256((const uint8_t *)(uintptr_t)b->base,b->size,digest) || !equal(digest,expected,32)?-1:0;}
static void snapshot_blob(shz_blob_t *out,const shz_blob_t *source,uint8_t *target)
{*out=*source;copy(target,(const uint8_t *)(uintptr_t)source->base,(unsigned)source->size);out->base=(uintptr_t)target;}
static int storage_valid(const w98_persist_config_t *c)
{
    unsigned mem=0;
    if(c->magic!=W98_PERSIST_CONFIG_MAGIC || c->version!=1 || c->bdf>=256 || c->reserved16 || c->reserved32 || c->reserved64 || c->vendor!=0x1af4 || (c->device!=0x1001 && c->device!=0x1042) || c->esp_bytes!=(2304ull<<20) || c->member_bytes!=(2ull<<30) || c->volume_id!=0x53485739)return -1;
    for(unsigned i=0;i<6;i++){const w98_persist_bar_t *b=&c->bar[i];
        if(b->reserved || b->kind>3)return -1;
        if(!b->kind){if(b->base || b->bytes)return -1;continue;}
        if(!b->bytes || (b->bytes&(b->bytes-1)) || !b->base || b->base&(b->bytes-1) || b->base>UINT64_MAX-b->bytes)return -1;
        if(b->kind==3){if(b->base+b->bytes>65536)return -1;}else{if(b->bytes<16 || b->base+b->bytes>(64ull<<30))return -1;mem++;}
        if(b->kind==1 && b->base+b->bytes>(1ull<<32))return -1;
        if(b->kind==2 && (i==5 || c->bar[i+1].kind || c->bar[i+1].base || c->bar[i+1].bytes || c->bar[i+1].reserved))return -1;
        for(unsigned j=0;j<i;j++)if(c->bar[j].kind && (c->bar[j].kind==3)==(b->kind==3) && b->base<c->bar[j].base+c->bar[j].bytes && c->bar[j].base<b->base+b->bytes)return -1;
    }
    return mem?0:-1;
}
static int storage_bars(const w98_persist_config_t *c,const uint32_t raw[6])
{
    for(unsigned i=0;i<6;i++){const w98_persist_bar_t *b=&c->bar[i];uint64_t base;
        if(!b->kind){if(raw[i])return -1;continue;}
        if(b->kind==3){if((raw[i]&3)!=1)return -1;base=raw[i]&~3u;}
        else if(b->kind==1){if(raw[i]&7)return -1;base=raw[i]&~15u;}
        else{if((raw[i]&7)!=4 || i==5)return -1;base=(raw[i]&~15u)|(uint64_t)raw[i+1]<<32;i++;}
        if(base!=b->base)return -1;
    }
    return 0;
}
static int policy_bind(w98_native_gate_t *g,const uint8_t p[256],unsigned roles,
                       const shz_blob_t *v,const shz_blob_t *r,const shz_blob_t *s,w98_epoch_expect_t *e)
{
    if(le32(p)!=W98_GATE_POLICY_MAGIC || le16(p+4)!=1 || le16(p+6)!=256 || le32(p+8)!=roles ||
       !empty(p+12,4) || empty(p+16,32) || !le64(p+144) || le32(p+152)!=10000 ||
       le16(p+156)!=W98_GATE_COM2 || !empty(p+158,2) || !empty(p+164,4) || !empty(p+216,40))return -1;
    zero((uint8_t *)e,sizeof *e);copy(e->nonce,p+16,32);g->host_deadline_ns=le64(p+144);
    for(unsigned role=1;role<=2;role++){
        const uint8_t *hash=p+48+(role-1)*32;const uint8_t *raw=p+168+(role-1)*24;
        if(!(roles&(1u<<(role-1)))){if(!empty(hash,32) || le16(p+160+(role-1)*2) || !empty(raw,24) || (role==1 && !empty(p+112,32)))return -1;continue;}
        w98_epoch_device_t *d=&e->device[e->count++];d->role=(uint16_t)role;d->bdf=le16(p+160+(role-1)*2);if(d->bdf>=256)return -1;
        copy(e->config_sha256[role-1],hash,32);for(unsigned b=0;b<6;b++)d->raw_bar[b]=le32(raw+b*4);
        if(role==1){const w98_vga_config_t *c=(const void *)(uintptr_t)v->base;
            if(!w98_vga_config_valid(c,v->size) || d->bdf!=c->bdf || config_hash(v,hash) || config_hash(r,p+112) || !equal(c->rom_sha256,p+112,32) || d->raw_bar[0]!=(c->lfb_base|8))return -1;
            d->vendor=0x1234;d->device=0x1111;d->class_code=0x030000;d->command_required=3;copy(e->rom_sha256,p+112,32);
        }else{const w98_persist_config_t *c=(const void *)(uintptr_t)s->base;
            if(storage_valid(c) || d->bdf!=c->bdf || config_hash(s,hash) || storage_bars(c,d->raw_bar))return -1;
            d->vendor=c->vendor;d->device=c->device;d->class_code=0x010000;
        }
    }
    return current(g);
}
static int pci_read(void *ctx,uint16_t bdf,unsigned off,uint32_t *out)
{
    w98_native_gate_t *g=ctx;uint32_t saved;
    if(bdf>=256 || off>36 || off&3 || read_port(g,0xcf8,4,&saved) || write_port(g,0xcf8,4,0x80000000u|(uint32_t)bdf<<8|off))return -1;
    int failed=read_port(g,0xcfc,4,out);if(write_port(g,0xcf8,4,saved))return -1;return failed;
}
static int uart_receive(void *ctx,uint8_t *out,unsigned bytes)
{
    w98_native_gate_t *g=ctx;uint32_t status,v;unsigned n=0;
    while(n<bytes && n<16){if(read_port(g,W98_GATE_COM2+5,1,&status) || status&0x1e)return -1;if(!(status&1))break;
        if(read_port(g,W98_GATE_COM2,1,&v) || v>255)return -1;
        out[n++]=(uint8_t)v;}return (int)n;
}
static int uart_send(void *ctx,const uint8_t *p,unsigned bytes)
{
    w98_native_gate_t *g=ctx;uint32_t status;unsigned n=0;
    while(n<bytes && n<16){if(read_port(g,W98_GATE_COM2+5,1,&status) || status&0x1e)return -1;if(!(status&0x20))break;
        if(write_port(g,W98_GATE_COM2,1,p[n++]))return -1;}return (int)n;
}
static uint64_t ticks(void *ctx){w98_native_gate_t *g=ctx;return g->ports.now(g->ports.opaque);}
static void pause_gate(void *ctx){w98_native_gate_t *g=ctx;g->ports.pause(g->ports.opaque);}
int w98_native_device_gate_with_io(w98_native_gate_t *g,const shz_info_t *i,const shz_caps_t *caps,const w98_gate_port_io_t *io)
{
    int error=0;unsigned roles;uint8_t policy[256];w98_epoch_expect_t expected;
    if(!g)return -1;
    g->admitted=0;g->protocol.protocol_admitted=0;if(g->attempted || !i)return -1;
    const shz_blob_t *v=blob(i,"VGACFG.BIN",&error),*r=blob(i,"VGAROM.BIN",&error),*s=blob(i,"W98PERS.BIN",&error);
    if(!error && !v && !r && !s)return 0; /* no control-port touch in default RAM */
    g->attempted=1;
    if(error || !!v!=!!r || (v && (v->size!=136 || v->base&7 || r->size!=65536)) || (s && (s->size!=192 || s->base&7)) ||
       !caps || !caps->hypervisor_bit || i->magic!=SHZ_INFO_MAGIC || i->version!=SHZ_INFO_VERSION || i->size!=sizeof *i ||
       !(i->loader_flags&SHZ_LOADER_NATIVE_WIN98) || i->tsc_hz<1000000 || i->tsc_hz>1000000000000ull ||
       !io || !io->read || !io->write || !io->now || !io->pause)return -1;
    const shz_blob_t *source_slot[3]={v,r,s};shz_blob_t original[3];
    if(v){original[0]=*v;original[1]=*r;v=&original[0];r=&original[1];}
    if(s){original[2]=*s;s=&original[2];}
    roles=(v?1u:0u)|(s?2u:0u);g->ports=*io;g->hz=i->tsc_hz;g->last_now=io->now(io->opaque);
    if(g->last_now>UINT64_MAX-g->hz*10)return -1;
    g->deadline=g->last_now+g->hz*10;g->original_deadline=g->deadline;
    if(policy_read(g,policy))return -1;
    /* Freeze before hashing. These copies stay outside all submitted DMA
     * request buffers and are never replaced/reused during this lifetime. */
    if(v){snapshot_blob(&g->snapshots[0],v,g->config[0]);snapshot_blob(&g->snapshots[1],r,g->rom);}
    if(s)snapshot_blob(&g->snapshots[2],s,g->config[1]);
    if(policy_bind(g,policy,roles,v?&g->snapshots[0]:0,r?&g->snapshots[1]:0,s?&g->snapshots[2]:0,&expected) ||
       (v && (config_hash(v,policy+48) || config_hash(r,policy+112))) || (s && config_hash(s,policy+80)) || current(g))return -1;
    /* Only the approved control UART is programmed; no UART IRQ is enabled. */
    static const uint8_t offsets[]={3,1,3,0,1,3,2,4},values[]={3,0,128,1,0,3,0xc7,3};
    for(unsigned b=0;b<sizeof offsets;b++)if(write_port(g,W98_GATE_COM2+offsets[b],1,values[b]))return -1;
    /* FIFO setup discards old/preboot bytes. Host waits for this exact nonce
     * READY on the owned channel before supplying the reviewed challenge. */
    uint8_t ready[48]={0x57,0x44,0x45,0x31,1,0,W98_GATE_READY,0,48};unsigned sent=0,calls=0;
    copy(ready+16,expected.nonce,32);
    while(sent<sizeof ready){
        if(current(g) || calls++>=W98_EPOCH_MAX_IO_CALLS)return -1;
        int n=uart_send(g,ready+sent,(unsigned)sizeof ready-sent);if(n<0 || (unsigned)n>sizeof ready-sent)return -1;
        sent+=(unsigned)n;if(!n){pause_gate(g);if(current(g))return -1;}
    }
    const w98_epoch_io_t stream={g,pci_read,uart_receive,uart_send,ticks,pause_gate};
    if(w98_native_epoch_gate(&g->protocol,&expected,&stream,g->deadline) ||
       (v && (!equal((const uint8_t *)source_slot[0],(const uint8_t *)&original[0],sizeof original[0]) || !equal((const uint8_t *)source_slot[1],(const uint8_t *)&original[1],sizeof original[1]))) ||
       (s && !equal((const uint8_t *)source_slot[2],(const uint8_t *)&original[2],sizeof original[2])) ||
       (v && (config_hash(v,policy+48) || config_hash(r,policy+112) || config_hash(&g->snapshots[0],policy+48) || config_hash(&g->snapshots[1],policy+112))) ||
       (s && (config_hash(s,policy+80) || config_hash(&g->snapshots[2],policy+80))) || current(g)){
        g->protocol.protocol_admitted=0;g->protocol.state=W98_EPOCH_FAILED;return -1;
    }
    g->admitted=1;return 0;
}
static int native_read(void *unused,uint16_t port,unsigned bytes,uint32_t *out)
{(void)unused;if(bytes==1)*out=inb(port);else if(bytes==4)*out=inl(port);else return -1;return 0;}
static int native_write(void *unused,uint16_t port,unsigned bytes,uint32_t value)
{(void)unused;if(bytes==1)outb(port,(uint8_t)value);else if(bytes==2)outw(port,(uint16_t)value);else if(bytes==4)outl(port,value);else return -1;return 0;}
static uint64_t native_now(void *unused){(void)unused;return rdtsc();}
static void native_pause(void *ctx)
{
    w98_native_gate_t *g=ctx;uint64_t start=rdtsc();
    /* At most1ms and100000 finite pauses; frozen TSC cannot make this unbounded. */
    for(unsigned n=0;n<100000;n++){uint64_t t=rdtsc();if(t<start || t>=g->deadline || t-start>=g->hz/1000)break;pause_cpu();}
}
int w98_native_device_gate(const shz_info_t *i,const shz_caps_t *caps)
{
    const w98_gate_port_io_t io={&lifetime,native_read,native_write,native_now,native_pause};
    return w98_native_device_gate_with_io(&lifetime,i,caps,&io);
}
const shz_blob_t *w98_native_device_gate_blob(const char *name)
{
    if(!name || !lifetime.admitted || !lifetime.protocol.protocol_admitted)return 0;
    for(unsigned b=0;b<3;b++){const shz_blob_t *s=&lifetime.snapshots[b];unsigned n=0;
        while(n<16 && name[n] && s->name[n]==name[n])n++;
        if(n<16 && !name[n] && !s->name[n] && s->base && s->size)return s;}
    return 0;
}

/* Word0..6 are completed by the immutable calling-domain binding. */
int w98_native_gate_gop_words(const w98_native_gate_t *g,uint32_t out[40])
{
    const w98_epoch_device_t *v=0;
    if(!g || !out || !g->admitted || !g->attempted ||
       !g->protocol.protocol_admitted || !g->protocol.nonce_consumed ||
       g->protocol.state!=W98_EPOCH_ADMITTED || !g->host_deadline_ns ||
       !g->protocol.expected.count || g->protocol.expected.count>2 ||
       empty(g->protocol.expected.nonce,32))return -1;
    for(unsigned i=0;i<g->protocol.expected.count;i++)
        if(g->protocol.expected.device[i].role==W98_EPOCH_VGA){
            if(v)return -1;
            v=&g->protocol.expected.device[i];
        }
    if(!v || v->bdf>=256 || v->vendor!=0x1234 || v->device!=0x1111 ||
       v->class_code!=0x030000 ||
       g->snapshots[0].base!=(uintptr_t)g->config[0] || g->snapshots[0].size!=136 ||
       g->snapshots[1].base!=(uintptr_t)g->rom || g->snapshots[1].size!=65536 ||
       config_hash(&g->snapshots[0],g->protocol.expected.config_sha256[0]) ||
       config_hash(&g->snapshots[1],g->protocol.expected.rom_sha256))return -1;
    zero((uint8_t *)out,160);
    out[7]=v->bdf;out[8]=v->vendor|(uint32_t)v->device<<16;out[9]=v->class_code;
    for(unsigned i=0;i<6;i++)out[10+i]=v->raw_bar[i];
    for(unsigned i=0;i<8;i++){
        out[16+i]=le32(g->protocol.expected.nonce+i*4);
        out[24+i]=le32(g->protocol.expected.config_sha256[0]+i*4);
        out[32+i]=le32(g->protocol.expected.rom_sha256+i*4);
    }
    return 0;
}
int w98_native_device_gate_gop_words(uint32_t out[40])
{return w98_native_gate_gop_words(&lifetime,out);}
