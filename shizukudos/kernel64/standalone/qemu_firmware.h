/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only QEMU machine RAM attestation for SeaBIOS-reserved ACPI storage.
 * SeaBIOS1.17.0 b52ca86: malloc_preinit selects ZoneHigh from original RAM,
 * reserves it; fw/romfile_loader allocates ACPI there; prepboot returns unused
 * ZoneHigh RAM. QEMU10.1.0 f8b2f64: etc/e820 retains the original machine map.
 * Firmware reservations remain unavailable to PMM and heap under every result.
 */
#ifndef SHZ_QEMU_FIRMWARE_H
#define SHZ_QEMU_FIRMWARE_H
#include "native_firmware.h"
#define SHZ_QEMU_FIRMWARE_MAGIC 0x51464d52u
#define SHZ_QEMU_FIRMWARE_DIRECTORY_MAX 1024u
typedef int (*shz_qemu_fwcfg_read_fn)(void *, uint16_t, uint32_t, void *, uint32_t);
typedef struct {
    uint32_t magic, count, bridge, subsystem, check, reserved;
    uint64_t ram_top;
    shz_native_firmware_range_t range[SHZ_NATIVE_FIRMWARE_RANGES];
} shz_qemu_firmware_t;
static inline uint32_t shz_qemu_fw_le32(const uint8_t *p)
{ return p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24); }
static inline uint64_t shz_qemu_fw_le64(const uint8_t *p)
{ return shz_qemu_fw_le32(p) | ((uint64_t)shz_qemu_fw_le32(p+4)<<32); }
static inline uint32_t shz_qemu_fw_be32(const uint8_t *p)
{ return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3]; }
static inline void shz_qemu_firmware_clear(shz_qemu_firmware_t *q)
{
    uint32_t i; uint8_t *p=(uint8_t *)q;
    for(i=0;i<sizeof *q;i++) p[i]=0;
}
static inline int shz_qemu_firmware_platform(uint32_t bridge,uint32_t subsystem)
{ return (bridge==0x12378086u || bridge==0x29c08086u) && subsystem==0x11001af4u; }
static inline uint32_t shz_qemu_firmware_sum(const shz_qemu_firmware_t *q)
{
    uint32_t i,sum=q->magic+q->count+q->bridge+q->subsystem+q->reserved+
        (uint32_t)q->ram_top+(uint32_t)(q->ram_top>>32);
    for(i=0;i<q->count && i<SHZ_NATIVE_FIRMWARE_RANGES;i++) {
        const shz_native_firmware_range_t *r=&q->range[i];
        sum+=(uint32_t)r->base+(uint32_t)(r->base>>32)+(uint32_t)r->length+
             (uint32_t)(r->length>>32)+r->type+r->reserved;
    }
    return ~sum;
}
static inline int shz_qemu_firmware_valid(const shz_qemu_firmware_t *q)
{
    uint32_t i; uint64_t top=0;
    if(!q || q->magic!=SHZ_QEMU_FIRMWARE_MAGIC || !q->count || q->count>SHZ_NATIVE_FIRMWARE_RANGES ||
       q->reserved || !shz_qemu_firmware_platform(q->bridge,q->subsystem) ||
       q->check!=shz_qemu_firmware_sum(q)) return 0;
    for(i=0;i<q->count;i++) {
        const shz_native_firmware_range_t *r=&q->range[i];
        uint64_t end;
        if(r->reserved || r->length>UINT64_MAX-r->base) return 0;
        end=r->base+r->length;
        if(r->type==1 && r->length && r->base<UINT64_C(0x100000000)) {
            if(end>UINT64_C(0x100000000)) end=UINT64_C(0x100000000);
            if(end>top) top=end;
        }
    }
    return top>=0x4000000 && top==q->ram_top;
}
/* Select/read means an actual bounded fw_cfg transfer, not a header-only flag.
 * Success captures every original RAM and reservation row. Unsupported/missing
 * returns0; malformed returns-1; both remove any stale attestation.
 */
static inline int shz_qemu_firmware_capture(shz_qemu_firmware_t *q,uint32_t bridge,uint32_t subsystem,
        shz_qemu_fwcfg_read_fn read,void *ctx)
{
    uint8_t signature[4],id[4],word[4],dir[64],row[20];
    uint16_t selectors[SHZ_QEMU_FIRMWARE_DIRECTORY_MAX];
    uint32_t count,i,key=0,size=0;
    if(!q) return -1;
    shz_qemu_firmware_clear(q);
    if(!read || !shz_qemu_firmware_platform(bridge,subsystem)) return 0;
    if(!read(ctx,0,0,signature,4) || signature[0]!='Q' || signature[1]!='E' ||
       signature[2]!='M' || signature[3]!='U' || !read(ctx,1,0,id,4) || !(shz_qemu_fw_le32(id)&1)) return 0;
    if(!read(ctx,0x19,0,word,4)) return -1;
    count=shz_qemu_fw_be32(word);
    if(count>SHZ_QEMU_FIRMWARE_DIRECTORY_MAX) return -1;
    for(i=0;i<count;i++) {
        uint32_t j,selector;
        if(!read(ctx,0x19,4+i*64,dir,64) || dir[6] || dir[7]) return -1;
        for(j=8;j<64 && dir[j];j++) ;
        if(j==64) return -1;
        selector=((uint32_t)dir[4]<<8)|dir[5];
        if(selector<0x20 || selector>=0x8000) return -1;
        for(j=0;j<i;j++) if(selectors[j]==selector) return -1;
        selectors[i]=(uint16_t)selector;
        if(dir[8]=='e' && dir[9]=='t' && dir[10]=='c' && dir[11]=='/' &&
           dir[12]=='e' && dir[13]=='8' && dir[14]=='2' && dir[15]=='0' && !dir[16]) {
            if(key) return -1;
            key=selector; size=shz_qemu_fw_be32(dir);
        }
    }
    if(!key) return 0;
    if(!size || size%20 || size/20>SHZ_NATIVE_FIRMWARE_RANGES) return -1;
    count=size/20;
    for(i=0;i<count;i++) {
        shz_native_firmware_range_t *r=&q->range[i];
        uint64_t end;
        if(!read(ctx,(uint16_t)key,i*20,row,20)) goto malformed;
        r->base=shz_qemu_fw_le64(row); r->length=shz_qemu_fw_le64(row+8); r->type=shz_qemu_fw_le32(row+16);
        if(r->length>UINT64_MAX-r->base) goto malformed;
        end=r->base+r->length;
        if(r->type==1 && r->length && r->base<UINT64_C(0x100000000)) {
            if(end>UINT64_C(0x100000000)) end=UINT64_C(0x100000000);
            if(end>q->ram_top) q->ram_top=end;
        }
    }
    if(q->ram_top<0x4000000) goto malformed;
    q->magic=SHZ_QEMU_FIRMWARE_MAGIC; q->count=count; q->bridge=bridge; q->subsystem=subsystem;
    q->check=shz_qemu_firmware_sum(q);
    return 1;
malformed:
    shz_qemu_firmware_clear(q);
    return -1;
}
/* No PCI/MMIO/ROM read can be justified by BIOS type2 alone. The full requested
 * span must also have original machine RAM coverage, with original non-RAM
 * overlaps denied. Known VGA/BIOS ROM windows are excluded even if QEMU's
 * original map lists underlying RAM before SeaBIOS carves them out.
 */
static inline int shz_qemu_firmware_covers(const shz_qemu_firmware_t *q,const shz_native_firmware_t *h,
        uint64_t pa,uint32_t bytes)
{
    uint64_t end,cursor; uint32_t i,pass;
    if(!bytes || bytes>UINT64_MAX-pa || !shz_qemu_firmware_valid(q) ||
       !shz_native_firmware_valid(h,1)) return 0;
    end=pa+bytes;
    if(end>q->ram_top || (pa<0x100000 && end>0xa0000) ||
       (pa<UINT64_C(0x100000000) && end>0xff000000)) return 0;
    for(pass=0;pass<2;pass++) {
        const shz_native_firmware_range_t *ranges=pass?h->range:q->range;
        const uint32_t count=pass?h->count:q->count;
        for(i=0;i<count;i++) {
            const shz_native_firmware_range_t *r=&ranges[i];
            const int allowed=pass?(r->type>=1 && r->type<=4):r->type==1;
            if(!allowed && r->length && r->base<end && pa<r->base+r->length) return 0;
        }
        cursor=pa;
        while(cursor<end) {
            uint64_t next=cursor;
            for(i=0;i<count;i++) {
                const shz_native_firmware_range_t *r=&ranges[i];
                const int allowed=pass?(r->type>=1 && r->type<=4):r->type==1;
                if(allowed && r->base<=cursor && r->base+r->length>next) next=r->base+r->length;
            }
            if(next==cursor) return 0;
            cursor=next;
        }
    }
    return 1;
}
#endif
