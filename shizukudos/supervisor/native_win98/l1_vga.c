/* SPDX-License-Identifier: GPL-2.0-only
 * One explicitly bound L1 QEMU std-VGA. PCI writes are private shadow writes;
 * data ports and MMIO reach only that admitted device. No instruction emulator,
 * reconstructed desktop, live BAR sizing or arbitrary PCI forwarding.
 */
#include "l1_vga.h"
#include "../src/ept.h"
#include "../src/cpu.h"
#define PCI_FIRST 0x08000000u
#define PCI_END 0xfec00000u
#define ROM_INITIAL 0xfc000000u
static uint32_t le32(const uint8_t *p){return p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static unsigned le16(const uint8_t *p){return p[0]|(unsigned)p[1]<<8;}
static void put32(uint8_t *p,uint32_t n){for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(n>>(i*8));}
static int nonzero(const uint8_t *p){unsigned n=0;for(unsigned i=0;i<32;++i)n|=p[i];return n!=0;}
static uint32_t rotate(uint32_t n,unsigned b){return n>>b|n<<(32-b);}
static void sha_block(uint32_t h[8],const uint8_t b[64])
{
    static const uint32_t k[64]={0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
    uint32_t w[64],a=h[0],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],z=h[7],v=h[1];
    for(unsigned i=0;i<16;++i)w[i]=(uint32_t)b[i*4]<<24|(uint32_t)b[i*4+1]<<16|(uint32_t)b[i*4+2]<<8|b[i*4+3];
    for(unsigned i=16;i<64;++i)w[i]=w[i-16]+(rotate(w[i-15],7)^rotate(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rotate(w[i-2],17)^rotate(w[i-2],19)^(w[i-2]>>10));
    for(unsigned i=0;i<64;++i){uint32_t t=z+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^(~e&g))+k[i]+w[i];uint32_t q=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&v)^(a&c)^(v&c));z=g;g=f;f=e;e=d+t;d=c;c=v;v=a;a=t+q;}
    h[0]+=a;h[1]+=v;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
}
static int rom_valid(const uint8_t *r,uint64_t bytes,const uint8_t expected[32])
{
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};uint8_t tail[64]={0};
    unsigned extent,pcir,sum=0,difference=0;
    if(!r || bytes!=W98_VGA_ROM_BYTES || ((uintptr_t)r&4095) || r[0]!=0x55 || r[1]!=0xaa || !r[2])return 0;
    extent=(unsigned)r[2]*512;pcir=le16(r+0x18);
    if(extent>bytes || pcir>extent-24 || pcir<0x1a || le32(r+pcir)!=0x52494350u || le16(r+pcir+4)!=0x1234 || le16(r+pcir+6)!=0x1111 || le16(r+pcir+0x0a)<24 || le16(r+pcir+0x0a)>extent-pcir || r[pcir+0x0d]!=0 || r[pcir+0x0e]!=0 || r[pcir+0x0f]!=3 || le16(r+pcir+0x10)*512!=extent || r[pcir+0x14]!=0 || r[pcir+0x15]!=0x80)return 0;
    for(unsigned i=0;i<extent;++i)sum+=r[i];
    if(sum&255)return 0;
    for(unsigned i=extent;i<bytes;++i)if(r[i])return 0;
    for(unsigned i=0;i<bytes;i+=64)sha_block(h,r+i);
    tail[0]=0x80;uint64_t bits=bytes*8;for(unsigned i=0;i<8;++i)tail[63-i]=(uint8_t)(bits>>(i*8));sha_block(h,tail);
    for(unsigned i=0;i<32;++i)difference|=(uint8_t)(h[i/4]>>(24-(i%4)*8))^expected[i];
    return difference==0;
}
int w98_vga_config_valid(const w98_vga_config_t *c,uint64_t bytes)
{
    return c && bytes==sizeof *c && c->magic==W98_VGA_MAGIC && c->version==1 && c->bytes==sizeof *c && c->flags==1 && c->bdf<256 && !c->reserved && c->lfb_bytes==W98_VGA_LFB_BYTES && c->lfb_base>=PCI_FIRST && c->lfb_base<=PCI_END-W98_VGA_LFB_BYTES && !(c->lfb_base&(W98_VGA_LFB_BYTES-1)) && nonzero(c->rom_sha256) && nonzero(c->source_sha256) && nonzero(c->config_sha256);
}
static int span(uint32_t b,uint32_t n){return b>=PCI_FIRST && b<=PCI_END-n && !(b&(n-1));}
static int overlap(uint32_t a,uint32_t an,uint32_t b,uint32_t bn){return a<b+bn && b<a+an;}
static int map(w98_l1_vga_t *v,uint32_t g,uint64_t h,uint32_t n,uint64_t p)
{if(v->ops.map(v->ops.opaque,g,h,n,p)){v->failed=1;return -1;}return 0;}
static int legacy_map(w98_l1_vga_t *v)
{return map(v,0xa0000,0xa0000,0x20000,(v->config[4]&2)?EPT_R|EPT_W|EPT_UC:0);}
static int bar_map(w98_l1_vga_t *v)
{
    for(unsigned off=0;off<W98_VGA_LFB_BYTES;off+=0x100000)
        if(map(v,v->bar0+off,v->binding.lfb_base+(v->a20_on?off:off&~0x100000u),0x100000,(v->config[4]&2)?EPT_R|EPT_W|EPT_UC:0))return -1;
    return 0;
}
static int rom_map(w98_l1_vga_t *v)
{
    uint32_t base=v->rombar&~65535u;
    uint64_t flags=((v->config[4]&2)&&(v->rombar&1)&&(v->a20_on || !(base&0x100000)))?EPT_R|EPT_X|EPT_WB:0;
    if(map(v,base,(uintptr_t)v->rom,W98_VGA_ROM_BYTES,flags))return -1;
    if(!v->a20_on && !(base&0x100000))return map(v,base|0x100000,(uintptr_t)v->rom,W98_VGA_ROM_BYTES,flags);
    return 0;
}
static int rom_revoke(w98_l1_vga_t *v)
{
    uint32_t base=v->rombar&~65535u;
    if(map(v,base,0,W98_VGA_ROM_BYTES,0))return -1;
    if(!v->a20_on && !(base&0x100000))return map(v,base|0x100000,0,W98_VGA_ROM_BYTES,0);
    return 0;
}
int w98_l1_vga_init(w98_l1_vga_t *v,const w98_vga_config_t *c,uint64_t cb,const uint8_t *r,uint64_t rb,const w98_vga_ops_t *ops)
{
    unsigned displays=0;uint32_t target[4]={0};
    if(!v || !w98_vga_config_valid(c,cb) || !rom_valid(r,rb,c->rom_sha256) || !ops || !ops->cfg_read || !ops->in || !ops->out || !ops->map || !ops->host_uc || !ops->exclude_display_writers || !ops->a20_get)return -1;
    int a20=ops->a20_get(ops->opaque);if(a20!=0 && a20!=1)return -1;
    for(unsigned bdf=0;bdf<256;++bdf){uint32_t id=ops->cfg_read(ops->opaque,(uint16_t)bdf,0);if(id==0xffffffffu || !(id&65535))continue;uint32_t class=ops->cfg_read(ops->opaque,(uint16_t)bdf,8);if((class>>24)!=3)continue;++displays;
        if(bdf==c->bdf){target[0]=id;target[1]=ops->cfg_read(ops->opaque,(uint16_t)bdf,4);target[2]=ops->cfg_read(ops->opaque,(uint16_t)bdf,12);target[3]=ops->cfg_read(ops->opaque,(uint16_t)bdf,16);if((class&0xffffff00u)!=0x03000000u)return -1;}}
    if(displays!=1 || target[0]!=0x11111234u || (target[1]&3)!=3 || (target[2]&0x00ff0000u) || (target[3]&15)!=8 || (target[3]&~15u)!=c->lfb_base || overlap((uint32_t)c->lfb_base,W98_VGA_LFB_BYTES,ROM_INITIAL,W98_VGA_ROM_BYTES))return -1;
    memset(v,0,sizeof *v);v->binding=*c;v->ops=*ops;v->rom=r;v->aperture_pointer=(uint8_t *)(uintptr_t)0xa0000;v->bar0=(uint32_t)c->lfb_base;v->rombar=ROM_INITIAL;v->a20_on=(unsigned)a20;
    put32(v->config,0x11111234);v->config[4]=3;v->config[0xb]=3;put32(v->config+16,v->bar0|8);put32(v->config+48,v->rombar);
    /* Host caching and all display writers are excluded before mode programming.
     * A later failure leaves ownership excluded; caller must never resume guest. */
    if(ops->host_uc(ops->opaque,c->lfb_base,c->lfb_bytes) || ops->exclude_display_writers(ops->opaque) || legacy_map(v) || bar_map(v) || rom_map(v))return -1;
    uint32_t id,enabled,memory_64k;
    if(ops->out(ops->opaque,0x1ce,2,0) || ops->in(ops->opaque,0x1cf,2,&id) || id<0xb0c0 || id>0xb0c5 ||
       ops->out(ops->opaque,0x1ce,2,10) || ops->in(ops->opaque,0x1cf,2,&memory_64k) || memory_64k!=256 ||
       ops->out(ops->opaque,0x1ce,2,4) || ops->out(ops->opaque,0x1cf,2,0) || ops->in(ops->opaque,0x1cf,2,&enabled) || enabled!=0)return -1;
    v->dispi_index=4;v->active=1;return 0;
}
static uint32_t pci_value(w98_l1_vga_t *v,unsigned offset)
{
    if(offset==16)return v->bar_probe?0xff000008u:v->bar0|8;
    if(offset==48)return v->rom_probe?0xffff0000u:v->rombar;
    return le32(v->config+offset);
}
static int pci_selected(w98_l1_vga_t *v){return (v->selector&0x80000000u) && ((v->selector>>8)&65535)==v->binding.bdf;}
static int pci_write(w98_l1_vga_t *v,unsigned offset,uint32_t value)
{
    if(offset==4){v->config[4]=(uint8_t)(value&3);if(legacy_map(v) || bar_map(v) || rom_map(v))return -1;}
    else if(offset==16){if((value&~15u)==0xfffffff0u){v->bar_probe=1;return 1;}uint32_t address=value&~(W98_VGA_LFB_BYTES-1);v->bar_probe=0;
        if(!span(address,W98_VGA_LFB_BYTES) || overlap(address,W98_VGA_LFB_BYTES,v->rombar&~65535u,W98_VGA_ROM_BYTES))return 1;
        if(address!=v->bar0 && map(v,v->bar0,0,W98_VGA_LFB_BYTES,0))return -1;
        v->bar0=address;if(bar_map(v))return -1;
    }else if(offset==48){if((value&~1u)==0xfffffffeu || (value&0xfffff800u)==0xfffff800u){v->rom_probe=1;return 1;}uint32_t address=value&~65535u;v->rom_probe=0;
        if(!span(address,W98_VGA_ROM_BYTES) || overlap(address,W98_VGA_ROM_BYTES,v->bar0,W98_VGA_LFB_BYTES))return 1;
        if(address!=(v->rombar&~65535u) && rom_revoke(v))return -1;
        v->rombar=address|(value&1);if(rom_map(v))return -1;
    }
    return 1; /* Identity/status/absent BARs/unsupported command bits are readonly. */
}
static int legacy_port(uint16_t p,unsigned bytes)
{
    if(bytes==2)return p==0x3b4 || p==0x3c4 || p==0x3ce || p==0x3d4;
    return bytes==1 && (p==0x3b4 || p==0x3b5 || p==0x3ba || (p>=0x3c0 && p<=0x3cf) || p==0x3d4 || p==0x3d5 || p==0x3da);
}
static int owned_port(uint16_t p){return (p>=0x3b0&&p<=0x3df) || p==0x1ce || p==0x1cf || (p>=0xcf8&&p<=0xcff);}
int w98_l1_vga_in(w98_l1_vga_t *v,uint16_t p,unsigned bytes,uint32_t *value)
{
    if(!v || !v->active || !value || !owned_port(p))return 0;
    if(v->failed)return -1;
    *value=bytes==1?255:bytes==2?65535:0xffffffffu;
    if(p==0xcf8 && bytes==4){*value=v->selector;return 1;}
    if(p>=0xcfc && p<=0xcff && (bytes==1 || bytes==2 || bytes==4) && !(p&(bytes-1)) && bytes<=0xd00u-p){if(pci_selected(v))*value=pci_value(v,v->selector&252)>>(8*(p-0xcfc));if(bytes<4)*value&=(1u<<(8*bytes))-1;return 1;}
    if((v->config[4]&1) && (legacy_port(p,bytes) || ((p==0x1ce || p==0x1cf)&&bytes==2))){if(v->ops.in(v->ops.opaque,p,bytes,value)){v->failed=1;return -1;}if(bytes<4)*value&=(1u<<(8*bytes))-1;}
    return 1;
}
int w98_l1_vga_out(w98_l1_vga_t *v,uint16_t p,unsigned bytes,uint32_t value)
{
    if(!v || !v->active || !owned_port(p))return 0;
    if(v->failed)return -1;
    if(bytes==1)value&=255;
    else if(bytes==2)value&=65535;
    if(p==0xcf8 && bytes==4){v->selector=value&0x80fffffcu;return 1;}
    if(p>=0xcfc && p<=0xcff && (bytes==1 || bytes==2 || bytes==4) && !(p&(bytes-1)) && bytes<=0xd00u-p){if(!pci_selected(v))return 1;unsigned offset=v->selector&252,shift=8*(p-0xcfc);uint32_t mask=bytes==4?0xffffffffu:((1u<<(bytes*8))-1)<<shift;return pci_write(v,offset,(pci_value(v,offset)&~mask)|((value<<shift)&mask));}
    if(!(v->config[4]&1))return 1;
    if(p==0x1ce && bytes==2){if(value>10)return 1;v->dispi_index=(uint16_t)value;}
    else if(p==0x1cf && bytes==2){if(v->dispi_index==7 || v->dispi_index==10)return 1;value&=65535;if(v->dispi_index==0 && (value<0xb0c0 || value>0xb0c5))return 1;if(v->dispi_index==4 && (value&~0xe3u))return 1;}
    else if(!legacy_port(p,bytes))return 1;
    if(v->ops.out(v->ops.opaque,p,bytes,value)){v->failed=1;return -1;}return 1;
}
int w98_l1_vga_physical(w98_l1_vga_t *v,uint32_t g,unsigned n,int write,uint8_t **p)
{
    if(!v || !v->active || !p || !n)return 0;
    uint64_t end=(uint64_t)g+n;
    if(end>0xa0000 && g<0xc0000){*p=g>=0xa0000 && !v->failed && (v->config[4]&2) && end<=0xc0000?v->aperture_pointer+g-0xa0000:0;return 1;}
    if(end>v->bar0 && (uint64_t)g<v->bar0+W98_VGA_LFB_BYTES){*p=g>=v->bar0 && !v->failed && (v->config[4]&2) && end<=v->bar0+W98_VGA_LFB_BYTES?(uint8_t *)(uintptr_t)(v->binding.lfb_base+g-v->bar0):0;return 1;}
    uint32_t rb=v->rombar&~65535u;
    if(end>rb && (uint64_t)g<rb+W98_VGA_ROM_BYTES){*p=g>=rb && !v->failed && !write && (v->config[4]&2) && (v->rombar&1) && end<=rb+W98_VGA_ROM_BYTES?(uint8_t *)(uintptr_t)(v->rom+g-rb):0;return 1;}
    return 0;
}
int w98_l1_vga_sync_a20(w98_l1_vga_t *v,int on)
{
    if(!v || !v->active)return 0;
    if(v->failed || (on!=0 && on!=1))return -1;
    if((unsigned)on==v->a20_on)return 0;
    if(rom_revoke(v))return -1;
    v->a20_on=(unsigned)on;
    return bar_map(v) || rom_map(v)?-1:0;
}
int w98_l1_vga_page(w98_l1_vga_t *v,uint32_t g,uint64_t *h,uint64_t *p)
{
    if(!v || !v->active || g<0xa0000 || g>=0xc0000)return 0;
    *h=g;*p=!v->failed && (v->config[4]&2)?EPT_R|EPT_W|EPT_UC:0;return 1;
}
