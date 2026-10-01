/* SPDX-License-Identifier: GPL-2.0-only
 * Retained coverage of actual opaque client submissions. One bit per pixel,
 * allocated lazily; RGB/alpha values never determine whether a pixel exists.
 * Callers own masks of shz_written_bytes(width,height) bytes and serialize
 * mutation with gfx_lock. This helper allocates nothing and changes no pixels.
 */
#ifndef SHZ_GFX_WRITTEN_COVERAGE_H
#define SHZ_GFX_WRITTEN_COVERAGE_H
#include <stdint.h>
#include <stddef.h>
static inline uint64_t shz_written_bytes(int32_t width,int32_t height)
{
    uint64_t pixels,bytes;
    if(width<=0 || height<=0) return 0;
    pixels=(uint64_t)(uint32_t)width*(uint32_t)height;
    bytes=(pixels+7)/8;
    return bytes>SIZE_MAX ? 0 : bytes;
}
static inline int shz_written_has(const uint8_t *mask,int32_t width,int32_t height,int32_t x,int32_t y)
{
    uint64_t bit;
    if(!mask || !shz_written_bytes(width,height) || x<0 || y<0 || x>=width || y>=height) return 0;
    bit=(uint64_t)(uint32_t)y*(uint32_t)width+(uint32_t)x;
    return (mask[bit>>3]>>(bit&7))&1;
}
/* The rectangle is clipped independently of drawing geometry. Empty input
 * consumes no mask bytes. Endpoint masks preserve neighboring row/pixels. */
static inline void shz_written_mark(uint8_t *mask,int32_t width,int32_t height,
    int32_t left,int32_t top,int32_t right,int32_t bottom)
{
    int32_t y;
    if(!mask || !shz_written_bytes(width,height)) return;
    if(left<0) left=0;
    if(top<0) top=0;
    if(right>width) right=width;
    if(bottom>height) bottom=height;
    if(left>=right || top>=bottom) return;
    for(y=top;y<bottom;++y) {
        uint64_t first=(uint64_t)(uint32_t)y*(uint32_t)width+(uint32_t)left;
        uint64_t last=(uint64_t)(uint32_t)y*(uint32_t)width+(uint32_t)right-1;
        uint64_t a=first>>3,b=last>>3,i;
        uint8_t lo=(uint8_t)(0xffu<<(first&7)),hi=(uint8_t)(0xffu>>(7-(last&7)));
        if(a==b) { mask[a]|=(uint8_t)(lo&hi);continue; }
        mask[a]|=lo;
        for(i=a+1;i<b;++i) mask[i]=0xff;
        mask[b]|=hi;
    }
}
/* Destination starts clear. Copy only the actual client overlap on resize,
 * preserving holes and dropping coverage outside the resized client area. */
static inline void shz_written_copy(uint8_t *dst,int32_t dw,int32_t dh,
    const uint8_t *src,int32_t sw,int32_t sh)
{
    int32_t x,y,cw=dw<sw ? dw : sw,ch=dh<sh ? dh : sh;
    if(!dst || !src || !shz_written_bytes(dw,dh) || !shz_written_bytes(sw,sh)) return;
    for(y=0;y<ch;++y) for(x=0;x<cw;++x) {
        uint64_t from=(uint64_t)(uint32_t)y*(uint32_t)sw+(uint32_t)x;
        uint64_t to=(uint64_t)(uint32_t)y*(uint32_t)dw+(uint32_t)x;
        if(src[from>>3]&(1u<<(from&7))) dst[to>>3]|=(uint8_t)(1u<<(to&7));
    }
}
#endif
