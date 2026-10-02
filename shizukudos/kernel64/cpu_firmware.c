/* SPDX-License-Identifier: GPL-2.0-only
 * Firmware reads for native AP topology; all parsed SDT bytes require retained
 * firmware ownership. BIOS RSDP search uses only the ACPI-defined BDA/EBDA and
 * E0000..FFFFF windows, then retains only the found RSDP's exact bounded span.
 */
#include "cpu_firmware.h"
#include "pci.h"
#ifdef SHZ_STANDALONE
struct fwcfg_port { unsigned key, offset; };
static int fwcfg_read(void *ctx,uint16_t key,uint32_t off,void *dst,uint32_t bytes)
{
    struct fwcfg_port *port=ctx;
    uint8_t *out=dst;
    uint32_t i;
    if(off>0x10004 || bytes>0x10004-off) return 0;
    if(port->key!=key || port->offset>off) {
        k_outw(0x510,key); port->key=key; port->offset=0;
    }
    while(port->offset<off) { (void)k_inb(0x511); ++port->offset; }
    for(i=0;i<bytes;i++) out[i]=k_inb(0x511);
    port->offset+=bytes;
    return 1;
}
#endif
int shz_cpu_firmware_prepare(const shz_bootinfo_t *bi,shz_cpu_firmware_t *f)
{
    if(!f) return -1;
    memset(f,0,sizeof *f);
#ifdef SHZ_STANDALONE
    pci_dev_t bridge={.bus=0,.dev=0,.fn=0};
    struct fwcfg_port port={.key=0xffff,.offset=0};
    int rc;
    if(!bi || (bi->flags&SHZ_BIF_UEFI_DIRECT) || bi->channel_count) return 0;
    memcpy(&f->native,(const void *)p2v(SHZ_NATIVE_FIRMWARE_GPA),sizeof f->native);
    if(!shz_native_firmware_valid(&f->native,1)) { memset(f,0,sizeof *f); return 0; }
    rc=shz_qemu_firmware_capture(&f->qemu,pci_cfg_read32(&bridge,0),pci_cfg_read32(&bridge,0x2c),fwcfg_read,&port);
    if(rc<0) { memset(f,0,sizeof *f); return -1; }
    f->ready=1; f->discovery=1;
    if(shz_native_firmware_covers(&f->native,0x40e,2)) {
        const volatile uint16_t *ebda=(const volatile uint16_t *)p2v(0x40e);
        const uint64_t pa=(uint64_t)*ebda<<4;
        if(pa>=0x80000 && pa<=0x9fc00) f->ebda=pa;
    }
    kprintf("SMP-FIRMWARE: retained=%u original=%u machine_ram=%llx managed_ram=%llx\n",
            f->native.count,f->qemu.count,f->qemu.ram_top,mem_ram_top());
    return 1;
#else
    (void)bi;
    return 0;
#endif
}
int shz_cpu_firmware_read(void *ctx,uint64_t pa,void *dst,size_t len)
{
    shz_cpu_firmware_t *f=ctx;
    uint64_t end;
    int allowed;
    if(!f || !f->ready || !dst || !len || len>UINT32_MAX || len>UINT64_MAX-pa ||
       pa+len>(64ull<<30)) return -1;
    end=pa+len;
    allowed=shz_native_firmware_covers(&f->native,pa,(uint32_t)len) ||
            shz_qemu_firmware_covers(&f->qemu,&f->native,pa,(uint32_t)len);
    if(f->discovery && len<=128 && ((pa>=0xe0000 && end<=0x100000) ||
       (f->ebda && pa>=f->ebda && end<=f->ebda+1024))) allowed=1;
    if(!f->discovery && f->rsdp && pa>=f->rsdp && end<=f->rsdp+f->rsdp_bytes) allowed=1;
    if(!allowed) return -1;
    if(end>mem_ram_top()) {
        uint64_t page;
        const uint64_t first=pa&~(uint64_t)(PAGE_SIZE-1),last=(end+PAGE_SIZE-1)&~(uint64_t)(PAGE_SIZE-1);
        for(page=first;page<last;page+=PAGE_SIZE) {
            /* Only firmware outside managed RAM needs new mappings. These are
             * supervisor read-only and NX; no MMIO or writable allocation grant. */
            if(page<mem_ram_top()) continue;
            if(vm_map(kernel_pml4(),p2v(page),page,PT_NX)) return -1;
        }
    }
    memcpy(dst,(const void *)p2v(pa),len);
    return 0;
}
int shz_cpu_firmware_finish_discovery(shz_cpu_firmware_t *f,uint64_t pa)
{
    uint8_t header[36];
    uint32_t bytes=20;
    if(!f || !f->ready || !f->discovery || !pa || shz_cpu_firmware_read(f,pa,header,20) ||
       memcmp(header,"RSD PTR ",8)) return -1;
    if(header[15]>=2) {
        if(shz_cpu_firmware_read(f,pa,header,36)) return -1;
        bytes=shz_qemu_fw_le32(header+20);
        if(bytes<36 || bytes>4096) return -1;
    }
    if(bytes>UINT64_MAX-pa ||
       (!(pa>=0xe0000 && pa+bytes<=0x100000) &&
        !(f->ebda && pa>=f->ebda && pa+bytes<=f->ebda+1024) &&
        !shz_native_firmware_covers(&f->native,pa,bytes) &&
        !shz_qemu_firmware_covers(&f->qemu,&f->native,pa,bytes))) return -1;
    f->rsdp=pa; f->rsdp_bytes=bytes; f->discovery=0;
    return 0;
}
