/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only 13px Noto caption cache. Wire integers are little-endian; no
 * unaligned struct casts, allocation, I/O or mutable glyph state in painting.
 * Glyph bitmap derivatives retain the source fonts' OFL-1.1 licenses. */
#ifndef SHZ_CAPTION_CACHE_H
#define SHZ_CAPTION_CACHE_H
#include <stddef.h>
#include <stdint.h>
#include "noto_asset_pins.h"
#define SHZ_CAP_MAX_BYTES (2u * 1024u * 1024u)
#define SHZ_CAP_MAX_GLYPHS 20000u
#define SHZ_CAP_GLYPHS 11618u
#define SHZ_CAP_HEADER 128u
#define SHZ_CAP_ENTRY 24u
#define SHZ_CAP_EM 13u
#define SHZ_CAP_BASELINE 12u
#define SHZ_CAP_LINE 17u
/* Actual whole-file digest from NAS cache-r03, generated from compiled Noto
 * source pins using native FreeType 2.13.2. No runtime hash can replace it. */
static const uint8_t shz_caption_cache_pin[32] = {
    0x8a, 0x9f, 0x81, 0x56, 0x27, 0x70, 0x62, 0x72, 0x94, 0x5c, 0xa9, 0x82, 0x5d, 0x83, 0x17, 0xec, 0x48, 0x12, 0x4a, 0x8e, 0x1d, 0xa3, 0x34, 0x30, 0x1d, 0x19, 0xc5, 0xc6, 0x5e, 0xaf, 0x6d, 0x72
};
typedef struct shz_caption_cache { const uint8_t *data; uint32_t bytes, count; } shz_caption_cache;
static inline uint32_t shz_cap_u32(const uint8_t *p)
{ return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static inline uint32_t shz_cap_u16(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1]<<8); }
static inline int32_t shz_cap_i16(const uint8_t *p)
{ uint32_t x=shz_cap_u16(p); return x<32768u?(int32_t)x:(int32_t)x-65536; }
static inline int shz_cap_zero(const uint8_t *p, unsigned n)
{ unsigned i; for(i=0;i<n;i++) if(p[i]) return 0; return 1; }
static inline int shz_cap_hex(const uint8_t *p, const char *h)
{
    unsigned i; for(i=0;i<32;i++) {
        unsigned a=(unsigned)(h[i*2]>='a'?h[i*2]-'a'+10:h[i*2]-'0');
        unsigned b=(unsigned)(h[i*2+1]>='a'?h[i*2+1]-'a'+10:h[i*2+1]-'0');
        if(p[i]!=(uint8_t)((a<<4)|b)) return 0;
    } return 1;
}
static inline uint32_t shz_cap_codepoint(unsigned i)
{
    if(i<95u) return 0x20u+i;
    i-=95u; if(i<256u) return 0x1100u+i;
    i-=256u; if(i<94u) return 0x3131u+i;
    i-=94u; if(i<11172u) return 0xac00u+i;
    return 0xfffdu;
}
/* Validate the complete immutable view before publication. The caller also
 * verifies its compiled whole-file SHA-256 pin; source hashes in this wire
 * header are provenance fields, not runtime-supplied trust anchors. */
static inline int shz_cap_validate(shz_caption_cache *out, const uint8_t *p, uint64_t bytes)
{
    static const uint8_t magic[8]={'S','H','Z','C','A','P','0','1'};
    uint32_t i,count,cursor; shz_caption_cache c;
    if(!out || !p || bytes<SHZ_CAP_HEADER || bytes>SHZ_CAP_MAX_BYTES) return -1;
    for(i=0;i<8;i++) if(p[i]!=magic[i]) return -1;
    count=shz_cap_u32(p+16);
    if(shz_cap_u32(p+8)!=1u || shz_cap_u32(p+12)!=bytes || !count || count>SHZ_CAP_MAX_GLYPHS || count!=SHZ_CAP_GLYPHS ||
       shz_cap_u32(p+20)!=SHZ_CAP_ENTRY || shz_cap_u32(p+24)!=SHZ_CAP_HEADER ||
       shz_cap_u32(p+28)!=SHZ_CAP_HEADER+count*SHZ_CAP_ENTRY || shz_cap_u32(p+32)!=SHZ_CAP_EM ||
       shz_cap_u32(p+36)!=SHZ_CAP_BASELINE || shz_cap_u32(p+40)!=SHZ_CAP_LINE || !shz_cap_zero(p+44,4) ||
       !shz_cap_zero(p+112,16) || !shz_cap_hex(p+48,NOTO_PIN_LATIN_HEX) || !shz_cap_hex(p+80,NOTO_PIN_KR_HEX)) return -1;
    cursor=SHZ_CAP_HEADER+count*SHZ_CAP_ENTRY;
    if(cursor>bytes) return -1;
    for(i=0;i<count;i++) {
        const uint8_t *e=p+SHZ_CAP_HEADER+i*SHZ_CAP_ENTRY;
        uint32_t w=shz_cap_u16(e+16),h=shz_cap_u16(e+18),advance=shz_cap_u32(e+8),len=(w*h+1u)/2u;
        int32_t left=shz_cap_i16(e+12),top=shz_cap_i16(e+14);
        if(shz_cap_u32(e)!=shz_cap_codepoint(i) || shz_cap_u32(e+4)!=cursor || !shz_cap_zero(e+20,4) ||
           w>32u || h>32u || (!w != !h) || !advance || advance>32u*64u || left < -32 || left>32 ||
           top < -32 || top>32 || (int32_t)SHZ_CAP_BASELINE-top<0 || (int32_t)SHZ_CAP_BASELINE-top+(int32_t)h>(int32_t)SHZ_CAP_LINE ||
           len>bytes-cursor) return -1;
        if((w*h)&1u) if(p[cursor+len-1u]&15u) return -1;
        cursor+=len;
    }
    if(cursor!=bytes) return -1;
    c.data=p; c.bytes=(uint32_t)bytes; c.count=count; *out=c; return 0;
}
static inline const uint8_t *shz_cap_find(const shz_caption_cache *c, uint32_t cp)
{
    uint32_t lo=0,hi=c->count;
    while(lo<hi) { uint32_t mid=lo+(hi-lo)/2; const uint8_t *e=c->data+SHZ_CAP_HEADER+mid*SHZ_CAP_ENTRY;
        uint32_t ch=shz_cap_u32(e); if(ch<cp) lo=mid+1; else hi=mid; }
    if(lo<c->count) { const uint8_t *e=c->data+SHZ_CAP_HEADER+lo*SHZ_CAP_ENTRY; if(shz_cap_u32(e)==cp) return e; }
    return c->data+SHZ_CAP_HEADER+(c->count-1u)*SHZ_CAP_ENTRY; /* U+FFFD, one cell per unsupported scalar */
}
static inline uint32_t shz_cap_blend(uint32_t dst, uint32_t src, uint32_t a)
{
    uint32_t r=((((src>>16)&255u)*a+((dst>>16)&255u)*(15u-a)+7u)/15u);
    uint32_t g=((((src>>8)&255u)*a+((dst>>8)&255u)*(15u-a)+7u)/15u);
    uint32_t b=(((src&255u)*a+(dst&255u)*(15u-a)+7u)/15u);
    return (dst&0xff000000u)|(r<<16)|(g<<8)|b;
}
static inline void shz_cap_draw(const shz_caption_cache *c, uint32_t *buf, int stride, int width, int height,
                               int x,int y,const uint16_t *s,unsigned n,uint32_t rgb,int cx0,int cy0,int cx1,int cy1)
{
    int64_t pen=(int64_t)x*64; unsigned i;
    if(!c || !c->data || !buf || !s || stride<=0 || width<=0 || height<=0 || stride<width ||
       (uint64_t)(height-1)*(uint32_t)stride+(uint32_t)width>SIZE_MAX/sizeof(uint32_t)) return;
    if(cx0<0) cx0=0;
    if(cy0<0) cy0=0;
    if(cx1>width) cx1=width;
    if(cy1>height) cy1=height;
    if(cx0>=cx1 || cy0>=cy1) return;
    if(n>255u) n=255u;
    for(i=0;i<n;i++) {
        uint32_t cp=s[i],row,col; const uint8_t *e,*pixels; int64_t gx,gy;
        if(cp>=0xd800u && cp<=0xdbffu) {
            if(i+1<n && s[i+1]>=0xdc00u && s[i+1]<=0xdfffu) { cp=0x10000u+((cp-0xd800u)<<10)+(s[++i]-0xdc00u); }
            else cp=0xfffdu;
        } else if(cp>=0xdc00u && cp<=0xdfffu) cp=0xfffdu;
        e=shz_cap_find(c,cp); pixels=c->data+shz_cap_u32(e+4);
        gx=(pen>=0?pen/64:-((-pen+63)/64))+shz_cap_i16(e+12);
        gy=(int64_t)y+SHZ_CAP_BASELINE-shz_cap_i16(e+14);
        for(row=0;row<shz_cap_u16(e+18);row++) {
            int64_t py=gy+row; if(py<cy0 || py>=cy1) continue;
            for(col=0;col<shz_cap_u16(e+16);col++) {
                uint32_t pixel=row*shz_cap_u16(e+16)+col,a; int64_t px=gx+col; uint32_t *dst;
                if(px<cx0 || px>=cx1) continue;
                a=(pixel&1u)?pixels[pixel/2]&15u:pixels[pixel/2]>>4;
                if(!a) continue;
                dst=buf+(size_t)py*(uint32_t)stride+(size_t)px; *dst=shz_cap_blend(*dst,rgb,a);
            }
        }
        pen+=shz_cap_u32(e+8);
    }
}
#endif
