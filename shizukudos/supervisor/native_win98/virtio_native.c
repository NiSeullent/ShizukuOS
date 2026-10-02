/* SPDX-License-Identifier: GPL-2.0-only
 * Actual x86 Supervisor operations. Host tests compile this file but execute
 * only rejection before privileged I/O; physical PCI/MMIO/DMA is unverified.
 * Entry is before guest/AP launch on the owned BSP. The W98PERS producer and
 * outer custody admission must bind the device/resource epoch to this blob.
 */
#include "virtio_blk.h"
#include "../src/cpu.h"
static uint8_t pci_lock;
static int span(uint64_t base,uint64_t bytes,uint64_t at,uint64_t size)
{return bytes && size && at>=base && at-base<bytes && size<=bytes-(at-base);}
static int overlaps(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{return n && m && a<b+m && b<a+n;}
static int info_valid(const shz_info_t *i)
{
    return i && i->magic==SHZ_INFO_MAGIC && i->version==SHZ_INFO_VERSION && i->size==sizeof *i && i->boot_path==1 && i->loader_flags&SHZ_LOADER_NATIVE_WIN98 && i->region_base==SHZ_REGION_BASE && i->region_size==SHZ_REGION_SIZE && i->tsc_hz>=1000000 && i->tsc_hz<=1000000000000ull && i->memmap_base && i->memmap_base<(64ull<<30) && i->memmap_bytes && i->memmap_bytes<=(1u<<20) && i->memmap_bytes<=(64ull<<30)-i->memmap_base && i->memmap_desc_size>=40 && i->memmap_desc_size<=256 && !(i->memmap_desc_size&7) && !(i->memmap_bytes%i->memmap_desc_size) && i->host_cr3;
}
/* Mirror the actual platform.c identity-map/2MiB caching rule. Reject MMIO
 * in any RAM-marked2MiB window, including the loader-owned regions. This
 * intentionally does not assume all memory below totalRAM is physical RAM. */
static int native_mmio_allowed(void *ctx,uint64_t at,uint64_t bytes)
{
    const shz_info_t *i=ctx;const uint8_t *map;uint64_t off,top=4ull<<30,lo,hi;
    if(!info_valid(i) || !bytes || at>UINT64_MAX-bytes || at+bytes>(64ull<<30))return 0;
    map=(const void *)(uintptr_t)i->memmap_base;lo=at&~((2ull<<20)-1);hi=(at+bytes-1)|((2ull<<20)-1);
    for(off=0;off<i->memmap_bytes;off+=i->memmap_desc_size){
        uint32_t type;uint64_t base,pages,end;int ram;
        memcpy(&type,map+off,4);memcpy(&base,map+off+8,8);memcpy(&pages,map+off+24,8);
        if(pages>UINT64_MAX/4096 || base>UINT64_MAX-pages*4096)return 0;
        end=base+pages*4096;ram=(type>=1 && type<=7) || type==9 || type==10 || type==14;
        if(ram){if(end>top)top=end;if(pages && lo<end && base<=hi)return 0;}
    }
    if(overlaps(lo,hi-lo+1,i->region_base,i->region_size) || i->guest_ram_base>UINT64_MAX-i->guest_ram_size || i->disk_base>UINT64_MAX-i->disk_size || overlaps(lo,hi-lo+1,i->guest_ram_base,i->guest_ram_size) || overlaps(lo,hi-lo+1,i->disk_base,i->disk_size))return 0;
    if(top>(64ull<<30))top=64ull<<30;
    top=(top+(1ull<<30)-1)&~((1ull<<30)-1);
    return at+bytes<=top;
}
static int pci_acquire(uint64_t *flags,uint32_t *address)
{
    unsigned n;__asm__ volatile("pushfq; popq %0; cli":"=r"(*flags)::"memory");
    for(n=0;n<1000000;n++)if(!__atomic_exchange_n(&pci_lock,1,__ATOMIC_ACQUIRE)){*address=inl(0xcf8);return 0;}else pause_cpu();
    if(*flags&(1ull<<9))__asm__ volatile("sti":::"memory");
    return -1;
}
static void pci_release(uint64_t flags,uint32_t address)
{outl(0xcf8,address);__atomic_store_n(&pci_lock,0,__ATOMIC_RELEASE);if(flags&(1ull<<9))__asm__ volatile("sti":::"memory");}
static int native_pci_read(void *ctx,uint16_t bdf,unsigned off,uint32_t *out)
{
    uint64_t flags;uint32_t address;(void)ctx;
    if(!out || off>=256 || off&3 || pci_acquire(&flags,&address))return -1;
    outl(0xcf8,0x80000000u|(uint32_t)bdf<<8|off);*out=inl(0xcfc);pci_release(flags,address);return 0;
}
static int native_pci_write(void *ctx,uint16_t bdf,unsigned off,uint32_t value)
{
    uint64_t flags;uint32_t address;(void)ctx;
    if(off>=256 || off&3 || pci_acquire(&flags,&address))return -1;
    outl(0xcf8,0x80000000u|(uint32_t)bdf<<8|off);outl(0xcfc,value);pci_release(flags,address);return 0;
}
static int native_mmio_read(void *ctx,uint64_t at,unsigned bytes,uint64_t *out)
{
    (void)ctx;if(!out || (bytes!=1 && bytes!=2 && bytes!=4) || at&(bytes-1))return -1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(bytes==1)*out=*(volatile uint8_t *)(uintptr_t)at;
    else if(bytes==2)*out=*(volatile uint16_t *)(uintptr_t)at;
    else *out=*(volatile uint32_t *)(uintptr_t)at;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);return 0;
}
static int native_mmio_write(void *ctx,uint64_t at,unsigned bytes,uint64_t value)
{
    (void)ctx;if((bytes!=1 && bytes!=2 && bytes!=4) || at&(bytes-1))return -1;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    if(bytes==1)*(volatile uint8_t *)(uintptr_t)at=(uint8_t)value;
    else if(bytes==2)*(volatile uint16_t *)(uintptr_t)at=(uint16_t)value;
    else *(volatile uint32_t *)(uintptr_t)at=(uint32_t)value;
    __atomic_thread_fence(__ATOMIC_SEQ_CST);return 0;
}
static int native_dma(void *ctx,const void *p,uint64_t bytes,uint64_t *pa)
{
    const shz_info_t *i=ctx;const uint64_t at=(uint64_t)(uintptr_t)p;
    if(!pa || !span(i->region_base+SHZ_INFO_BYTES,i->region_size-SHZ_INFO_BYTES,at,bytes))return -1;
    *pa=at;return 0;
}
static uint64_t native_ticks(void *ctx){(void)ctx;return rdtsc();}
static void native_pause(void *ctx){(void)ctx;pause_cpu();}
int w98_vblk_native_init(w98_vblk_t *v,const w98_persist_config_t *c,uint64_t bytes,const shz_info_t *i)
{
    w98_vblk_io_t io;uint64_t pa;
    if(!c || !info_valid(i) || !v || (uintptr_t)v&4095 || native_dma((void *)i,v,sizeof *v,&pa))return -1;
    /* Host tests never pass this boundary. Bootstrap already admitted and
     * mapped the retained memory-map pointer; require that actual CR3 epoch. */
    if(read_cr3()!=i->host_cr3)return -1;
    io=(w98_vblk_io_t){(void *)i,native_pci_read,native_pci_write,native_mmio_read,native_mmio_write,native_mmio_allowed,native_dma,native_ticks,native_pause,i->tsc_hz};
    return w98_vblk_init(v,c,bytes,&io);
}
