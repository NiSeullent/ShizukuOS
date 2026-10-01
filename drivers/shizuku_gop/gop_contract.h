/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded parser for the Shizuku CSMWrap GOP handoff, version 1.
 * No firmware calls, PCI programming or mapping occurs in this parser.
 */
#ifndef SHIZUKU_GOP_CONTRACT_H
#define SHIZUKU_GOP_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
#define SHZGOP_DESCRIPTOR_BYTES 96u
#define SHZGOP_CB_TAG 0x53485a47UL
#define SHZGOP_LOCATOR_BASE 0x000f0000UL
#define SHZGOP_LOCATOR_BYTES 48u
#define SHZGOP_LOCATOR_REGION_BYTES 0x10000UL
#define SHZGOP_LOCATOR_ALIGN 16u
typedef struct shzgop_locator {
    uint32_t address, descriptor_address, descriptor_checksum;
} shzgop_locator;
typedef struct shzgop_mode {
    uint32_t base, aperture, visible, width, height, pitch;
    uint16_t vendor, device;
    uint8_t bus, devfn;
} shzgop_mode;
static uint32_t shzgop_u32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) |
           ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static uint16_t shzgop_u16(const unsigned char *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1]<<8));
}
static uint16_t shzgop_ip_checksum(const unsigned char *p, uint32_t n) {
    uint32_t sum=0, i;
    for(i=0;i<n;i++) {
        sum += (uint32_t)p[i] << ((i & 1u) ? 8 : 0);
        if(sum>=0x10000UL) sum=(sum+(sum>>16))&0xffffUL;
    }
    return (uint16_t)(~sum & 0xffffu);
}
/* Additive SHZLOC1 ABI: only 16-aligned complete slots in the BIOS F-segment.
 * SeaBIOS AX=6/BX=1 owns the allocation; this is not a RAM signature fallback.
 * Any matching-magic malformed slot or more than one anchor fails closed. */
static int shzgop_locator_scan(const unsigned char *rom, size_t n, shzgop_locator *locator) {
    static const unsigned char magic[8]={'S','H','Z','L','O','C','1',0};
    uint32_t pos, i, found=0, descriptor=0, checksum=0;
    if(!rom || !locator || n!=SHZGOP_LOCATOR_REGION_BYTES) return 0;
    for(pos=0;pos<SHZGOP_LOCATOR_REGION_BYTES;pos+=SHZGOP_LOCATOR_ALIGN) {
        const unsigned char *p=rom+pos;
        uint32_t sum=0, address=SHZGOP_LOCATOR_BASE+pos, target;
        for(i=0;i<8;i++) if(p[i]!=magic[i]) break;
        if(i!=8) continue;
        if(pos>SHZGOP_LOCATOR_REGION_BYTES-SHZGOP_LOCATOR_BYTES) return 0;
        if(found || shzgop_u16(p+8)!=1 || shzgop_u16(p+10)!=0 ||
           shzgop_u32(p+12)!=48 || shzgop_u32(p+20)!=address ||
           shzgop_u32(p+28) || shzgop_u32(p+32)!=96 ||
           shzgop_u32(p+40)!=1 || shzgop_u32(p+44)) return 0;
        for(i=0;i<48;i+=4) sum+=shzgop_u32(p+i);
        target=shzgop_u32(p+24);
        if(sum || target<=0x100000UL || target>0xfffff000UL || (target&4095u)) return 0;
        found=address; descriptor=target; checksum=shzgop_u32(p+36);
    }
    if(!found) return 0;
    locator->address=found; locator->descriptor_address=descriptor;
    locator->descriptor_checksum=checksum;
    return 1;
}
/* The low coreboot table is bounded by its containing physical page. */
static uint32_t shzgop_descriptor_address(const unsigned char *cb, size_t n) {
    uint32_t count, bytes, pos=24, i, found=0;
    if(n<24 || cb[0]!='L'||cb[1]!='B'||cb[2]!='I'||cb[3]!='O') return 0;
    if(shzgop_u32(cb+4)!=24 || shzgop_ip_checksum(cb,24)!=0) return 0;
    bytes=shzgop_u32(cb+12); count=shzgop_u32(cb+20);
    if(bytes>n-24 || count>128 || shzgop_u32(cb+16)>0xffffUL ||
       shzgop_ip_checksum(cb+24,bytes)!=shzgop_u32(cb+16)) return 0;
    for(i=0;i<count;i++) {
        uint32_t tag, size, addr;
        if(pos>24+bytes || 24+bytes-pos<8) return 0;
        tag=shzgop_u32(cb+pos); size=shzgop_u32(cb+pos+4);
        if(size<8 || size>24+bytes-pos) return 0;
        if(tag==SHZGOP_CB_TAG) {
            if(found || size!=24 || shzgop_u32(cb+pos+12)!=0 ||
               shzgop_u32(cb+pos+16)!=96 || shzgop_u32(cb+pos+20)!=0) return 0;
            addr=shzgop_u32(cb+pos+8);
            if(addr<0x100000UL || addr>0xfffff000UL || (addr&4095u)) return 0;
            found=addr;
        }
        pos+=size;
    }
    return pos==24+bytes ? found : 0;
}
static int shzgop_parse(const unsigned char *p, size_t n, shzgop_mode *m) {
    static const unsigned char magic[8]={'S','H','Z','G','O','P','1',0};
    uint32_t i, sum=0, flags, width, height, pitch, visible, base, aperture;
    if(!p || !m || n!=96) return 0;
    for(i=0;i<8;i++) if(p[i]!=magic[i]) return 0;
    if(shzgop_u16(p+8)!=1 || shzgop_u16(p+10)!=0 || shzgop_u32(p+12)!=96) return 0;
    for(i=0;i<96;i+=4) sum+=shzgop_u32(p+i);
    if(sum) return 0;
    flags=shzgop_u32(p+20);
    if((flags&3u)!=3u || (flags&~7u) || shzgop_u32(p+92)) return 0;
    /* Initial Win98 mapping supports 32-bit physical apertures only. */
    if(shzgop_u32(p+28)||shzgop_u32(p+36)||shzgop_u32(p+44)) return 0;
    base=shzgop_u32(p+24); aperture=shzgop_u32(p+32); visible=shzgop_u32(p+40);
    width=shzgop_u32(p+48); height=shzgop_u32(p+52); pitch=shzgop_u32(p+56);
    if(base<0x100000UL || !aperture || aperture>0x10000000UL ||
       aperture-1>0xffffffffUL-base) return 0;
    if(width<640 || width>4096 || height<480 || height>4096 ||
       pitch<width*4u || pitch>65535u || (pitch&3u) || shzgop_u32(p+60)!=32) return 0;
    if(visible!=pitch*height || visible>aperture || visible>0x04000000UL) return 0;
    /* Windows DIB32 consumes B,G,R,X. RGBX and BLT-only are rejected. */
    if(shzgop_u32(p+64)!=0x00ff0000UL || shzgop_u32(p+68)!=0x0000ff00UL ||
       shzgop_u32(p+72)!=0x000000ffUL || shzgop_u32(p+76)!=0xff000000UL) return 0;
    if(!(flags&4u) || shzgop_u16(p+80) || !shzgop_u16(p+84) ||
       shzgop_u16(p+84)==0xffffu || !shzgop_u16(p+86) || shzgop_u16(p+86)==0xffffu) return 0;
    m->base=base; m->aperture=aperture; m->visible=visible;
    m->width=width; m->height=height; m->pitch=pitch;
    m->bus=p[82]; m->devfn=p[83]; m->vendor=shzgop_u16(p+84); m->device=shzgop_u16(p+86);
    return 1;
}
static int shzgop_locator_bind(const shzgop_locator *locator,
                              const unsigned char *descriptor, size_t n, shzgop_mode *m) {
    if(!locator || !shzgop_parse(descriptor,n,m)) return 0;
    return locator->descriptor_checksum==shzgop_u32(descriptor+16);
}
#endif
