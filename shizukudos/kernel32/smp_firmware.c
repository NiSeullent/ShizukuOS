/* SPDX-License-Identifier: GPL-2.0-only */
#include "smp_native.h"
/* Portable checked-byte parser compiled as ELF32; no K64 architecture code. */
#include "../kernel64/smp_acpi.c"
#ifdef SHZ_STANDALONE
static inline uint8_t inb(uint16_t p) { uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v; }
static inline void outw(uint16_t p,uint16_t v) { __asm__ volatile("outw %0,%1"::"a"(v),"Nd"(p)); }
static uint32_t pci_read(uint32_t off)
{
    uint32_t v;__asm__ volatile("outl %0,%1"::"a"(0x80000000u|off),"Nd"((uint16_t)0xcf8));
    __asm__ volatile("inl %1,%0":"=a"(v):"Nd"((uint16_t)0xcfc));return v;
}
struct fwport { unsigned key,off; };
static int fwread(void *ctx,uint16_t key,uint32_t off,void *dst,uint32_t n)
{
    struct fwport *p=ctx;uint8_t *d=dst;
    if(off>0x10004 || n>0x10004-off)return 0;
    if(p->key!=key || p->off>off) { outw(0x510,key);p->key=key;p->off=0; }
    while(p->off<off) { (void)inb(0x511);++p->off; }
    for(unsigned i=0;i<n;i++)d[i]=inb(0x511);
    p->off+=n;return 1;
}
#endif
int k32_ap_firmware_prepare(k32_ap_firmware_t *f)
{
#ifdef SHZ_STANDALONE
    if(!f || !shz_native_firmware_valid(&f->native,1))return -1;
    struct fwport p={0xffff,0};
    if(shz_qemu_firmware_capture(&f->qemu,pci_read(0),pci_read(0x2c),fwread,&p)<0)return -1;
    f->ready=f->discovery=1;
    if(shz_native_firmware_covers(&f->native,0x40e,2)) {
        uint16_t segment;memcpy(&segment,(const void *)0x40e,sizeof segment);
        const uint64_t ebda=(uint64_t)segment<<4;
        if(ebda>=0x80000 && ebda<=0x9fc00)f->ebda=ebda;
    }
    return 0;
#else
    (void)f;return -1;
#endif
}
int k32_ap_firmware_read(void *ctx,uint64_t pa,void *dst,size_t n)
{
    k32_ap_firmware_t *f=ctx;
    if(!f || !f->ready || !dst || !n || n>UINT32_MAX || pa>UINT32_MAX || n>UINT32_MAX-pa)return -1;
    const uint64_t end=pa+n;
    int allowed=shz_native_firmware_covers(&f->native,pa,(uint32_t)n) ||
        shz_qemu_firmware_covers(&f->qemu,&f->native,pa,(uint32_t)n);
    if(f->discovery && n<=128 && ((pa>=0xe0000 && end<=0x100000) ||
        (f->ebda && pa>=f->ebda && end<=f->ebda+1024)))allowed=1;
    if(!f->discovery && f->rsdp && pa>=f->rsdp && end<=f->rsdp+f->rsdp_bytes)allowed=1;
    if(!allowed)return -1;
    for(uint64_t p=pa&~4095ull;p<end;p+=4096) {
        if(p<f->ram)continue;
        if(k32_vm_native_map((uint32_t)p,0))return -1;
    }
    memcpy(dst,(const void *)(uintptr_t)pa,n);return 0;
}
int k32_ap_firmware_finish(k32_ap_firmware_t *f,uint64_t pa)
{
    uint8_t h[36];uint32_t bytes=20;
    if(!f || !f->discovery || k32_ap_firmware_read(f,pa,h,20) || memcmp(h,"RSD PTR ",8))return -1;
    if(h[15]>=2) {
        if(k32_ap_firmware_read(f,pa,h,36))return -1;
        bytes=shz_qemu_fw_le32(h+20);if(bytes<36 || bytes>4096)return -1;
    }
    if(pa>UINT32_MAX || bytes>UINT32_MAX-pa ||
       (!(pa>=0xe0000 && pa+bytes<=0x100000) &&
        !(f->ebda && pa>=f->ebda && pa+bytes<=f->ebda+1024) &&
        !shz_native_firmware_covers(&f->native,pa,bytes) &&
        !shz_qemu_firmware_covers(&f->qemu,&f->native,pa,bytes)))return -1;
    f->rsdp=pa;f->rsdp_bytes=bytes;f->discovery=0;return 0;
}
