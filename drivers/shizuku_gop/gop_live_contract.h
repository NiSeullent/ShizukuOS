/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only PM16 current-boot query ABI. No disk or mode mutation.
 */
#ifndef SHIZUKU_GOP_LIVE_CONTRACT_H
#define SHIZUKU_GOP_LIVE_CONTRACT_H
#include "gop_contract.h"
#define OP_SHZGOP_CURRENT_BOOT 0x4f10
#define OP_SHZGOP_GUARDIAN_EPOCH 0x4f11
#define SHZGOP_EPOCH_BYTES 160u
#define SHZGOP_PM16_DEVICE 0x4353
#define SHZGOP_PROBE_BYTES 288u
#define SHZGOP_HDA_BYTES 280u
#define SHZGOP_HDA_VERSION 20260213UL
#define SHZGOP_HDA_FLAGS (8192UL|256UL)
static int shzgop_slot_admit(const unsigned char *p,uint32_t address,shzgop_locator *out) {
    static const unsigned char magic[8]={'S','H','Z','L','O','C','1',0};
    uint32_t i,sum=0,target;
    if(!p || !out || address<SHZGOP_LOCATOR_BASE ||
       address>SHZGOP_LOCATOR_BASE+SHZGOP_LOCATOR_REGION_BYTES-SHZGOP_LOCATOR_BYTES ||
       (address&(SHZGOP_LOCATOR_ALIGN-1u))) return 0;
    for(i=0;i<8;i++) if(p[i]!=magic[i]) return 0;
    if(shzgop_u16(p+8)!=1 || shzgop_u16(p+10) || shzgop_u32(p+12)!=48 ||
       shzgop_u32(p+20)!=address || shzgop_u32(p+28) || shzgop_u32(p+32)!=96 ||
       shzgop_u32(p+40)!=1 || shzgop_u32(p+44)) return 0;
    for(i=0;i<48;i+=4) sum+=shzgop_u32(p+i);
    target=shzgop_u32(p+24);
    if(sum || target<=0x100000UL || target>0xfffff000UL || (target&4095u)) return 0;
    out->address=address;out->descriptor_address=target;
    out->descriptor_checksum=shzgop_u32(p+36);return 1;
}
static int shzgop_probe_admit(const unsigned char *p,size_t n,
                             const unsigned char *provider,shzgop_mode *mode) {
    static const unsigned char magic[8]={'S','H','Z','G','P','B','1',0};
    static const unsigned char name[16]={'S','H','Z','G','O','P','.','V','X','D',0,0,0,0,0,0};
    shzgop_locator locator;uint32_t i,nonzero=0;const unsigned char *h;
    if(!p || !provider || !mode || n!=SHZGOP_PROBE_BYTES) return 0;
    for(i=0;i<8;i++) if(p[i]!=magic[i]) return 0;
    if(shzgop_u16(p+8)!=1 || shzgop_u16(p+10) || shzgop_u32(p+12)!=SHZGOP_PROBE_BYTES ||
       shzgop_u32(p+60)) return 0; /* Existing ABI has no Supervisor epoch. */
    for(i=0;i<32;i++) {if(p[16+i]!=provider[i]) return 0;nonzero|=provider[i];}
    if(!nonzero) return 0;
    if(!shzgop_slot_admit(p+64,shzgop_u32(p+48),&locator) ||
       locator.descriptor_address!=shzgop_u32(p+52) ||
       locator.descriptor_checksum!=shzgop_u32(p+56) ||
       !shzgop_locator_bind(&locator,p+112,96,mode)) return 0;
    h=p+208;
    if(shzgop_u32(h)!=SHZGOP_HDA_BYTES || shzgop_u32(h+4)!=SHZGOP_HDA_FLAGS ||
       shzgop_u32(h+8)!=SHZGOP_HDA_VERSION || shzgop_u32(h+12)!=mode->width ||
       shzgop_u32(h+16)!=mode->height || shzgop_u32(h+20)!=32 ||
       shzgop_u32(h+24)!=mode->pitch || shzgop_u32(h+32)!=mode->visible ||
       !shzgop_u32(h+40) || !shzgop_u32(h+48) || shzgop_u32(h+52)!=mode->visible ||
       shzgop_u32(h+56)!=mode->aperture || shzgop_u32(h+60)!=mode->visible) return 0;
    for(i=0;i<16;i++) if(h[64+i]!=name[i]) return 0;
    return 1;
}
/* Additive separate160B readonly HC14 observation. Existing288B probe unchanged.
 * Nonce is independently held from the current owned guardian, not an INI flag. */
static int shzgop_epoch_admit(const unsigned char *e,size_t n,
                             const unsigned char *nonce,const unsigned char *probe) {
    unsigned i;uint32_t nonzero=0,config=0,rom=0;shzgop_mode m;
    if(!e || !nonce || !probe || n!=SHZGOP_EPOCH_BYTES ||
       shzgop_u32(e)!=0x31455047UL || shzgop_u32(e+4)!=1 || shzgop_u32(e+8)!=40 ||
       shzgop_u32(e+12)!=5 || !shzgop_u32(e+16) || shzgop_u32(e+20)>=256 ||
       shzgop_u32(e+24)!=3 || shzgop_u32(e+28)>=256 ||
       shzgop_u32(e+32)!=0x11111234UL || shzgop_u32(e+36)!=0x030000UL ||
       !shzgop_parse(probe+112,96,&m) || m.bus || m.devfn!=shzgop_u32(e+28) ||
       ((uint32_t)m.vendor|((uint32_t)m.device<<16))!=shzgop_u32(e+32) ||
       (shzgop_u32(e+40)&15u)!=8 || (shzgop_u32(e+40)&~15UL)!=m.base) return 0;
    for(i=0;i<32;i++) {if(e[64+i]!=nonce[i]) return 0;nonzero|=nonce[i];config|=e[96+i];rom|=e[128+i];}
    return nonzero && config && rom;
}
#endif
