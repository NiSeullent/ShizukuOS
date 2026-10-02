/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if __has_include("../kernel64/standalone/qemu_firmware.h")
#include "../kernel64/standalone/qemu_firmware.h"
static unsigned checks, failures;
#define CHECK(name, condition) do { ++checks; if (!(condition)) { ++failures; fprintf(stderr, "FAIL %s\n", name); } } while (0)
struct files { uint8_t dir[132], map[65 * 20], signature[4], id[4]; uint32_t size, reads; };
static void be32(uint8_t *p,uint32_t n) { p[0]=n>>24; p[1]=n>>16; p[2]=n>>8; p[3]=n; }
static int read_file(void *ctx,uint16_t key,uint32_t off,void *dst,uint32_t n)
{
    struct files *f=ctx; const uint8_t *p; uint32_t size;
    ++f->reads;
    if(key==0) { p=f->signature; size=4; }
    else if(key==1) { p=f->id; size=4; }
    else if(key==0x19) { p=f->dir; size=sizeof f->dir; }
    else if(key==0x20) { p=f->map; size=f->size; }
    else return 0;
    if(off>size || n>size-off) return 0;
    memcpy(dst,p+off,n); return 1;
}
static void original(struct files *f,uint64_t base,uint64_t length,uint32_t type)
{
    memcpy(f->map+f->size,&base,8); memcpy(f->map+f->size+8,&length,8);
    memcpy(f->map+f->size+16,&type,4); f->size+=20; be32(f->dir+4,f->size);
}
static void setup(struct files *f)
{
    memset(f,0,sizeof *f); memcpy(f->signature,"QEMU",4); f->id[0]=1;
    be32(f->dir,1); f->dir[9]=0x20; memcpy(f->dir+12,"etc/e820",9);
    original(f,0,0x10000000,1); original(f,0xfffc0000,0x40000,2);
}
static int capture(shz_qemu_firmware_t *q,struct files *f)
{ return shz_qemu_firmware_capture(q,0x12378086,0x11001af4,read_file,f); }
static void bios(shz_native_firmware_t *h)
{
    memset(h,0,sizeof *h); h->magic=SHZ_NATIVE_FIRMWARE_MAGIC; h->version=SHZ_NATIVE_FIRMWARE_VERSION;
    h->bytes=sizeof *h; h->profile=SHZ_NATIVE_FIRMWARE_MULTIBOOT; h->count=4;
    h->range[0]=(shz_native_firmware_range_t){0x100000,0xfee0000,1,0};
    h->range[1]=(shz_native_firmware_range_t){0xffe0000,0x20000,2,0};
    h->range[2]=(shz_native_firmware_range_t){0xfec00000,0x1000,2,0};
    h->range[3]=(shz_native_firmware_range_t){0xe0000,0x20000,2,0};
    h->check=shz_native_firmware_sum(h);
}
static int empty(const shz_qemu_firmware_t *q)
{
    const uint8_t *p=(const uint8_t *)q;
    for(unsigned i=0;i<sizeof *q;i++) if(p[i]) return 0;
    return 1;
}
int main(void)
{
    struct files f; shz_qemu_firmware_t q,saved; shz_native_firmware_t h;
    setup(&f); bios(&h);
    CHECK("actual fw_cfg signature directory and full original map required",capture(&q,&f)==1 && f.reads>4);
    CHECK("original RAM extent is256MiB rather than rounded254MiB PMM",q.ram_top==0x10000000 && q.count==2);
    CHECK("QEMU SeaBIOS reserved ACPI tail read admitted",shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    CHECK("entire allocated firmware page read admitted",shz_qemu_firmware_covers(&q,&h,0xffe2000,4096));
    CHECK("RAM still read admitted",shz_qemu_firmware_covers(&q,&h,0x100000,36));
    CHECK("LAPIC/IOAPIC MMIO outside original RAM refused",!shz_qemu_firmware_covers(&q,&h,0xfec00000,36));
    CHECK("BIOS ROM never admitted as SDT RAM",!shz_qemu_firmware_covers(&q,&h,0xe0000,36));
    CHECK("VGA aperture never admitted",!shz_qemu_firmware_covers(&q,&h,0xa0000,36));
    CHECK("firmware span exceeding machine RAM refused",!shz_qemu_firmware_covers(&q,&h,0xfffffff,36));
    CHECK("physical overflow refused",!shz_qemu_firmware_covers(&q,&h,UINT64_MAX-16,36));
    CHECK("zero read refused",!shz_qemu_firmware_covers(&q,&h,0xffe2270,0));
    saved=q;
    q.range[0].length--;
    CHECK("altered attestation refused",!shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    q=saved; q.count=65;
    CHECK("corrupt original count refused safely",!shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    q=saved; h.range[1].type=5; h.check=shz_native_firmware_sum(&h);
    CHECK("BIOS unusable conflicts defeat original RAM",!shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    bios(&h); h.range[1].base++; h.check=shz_native_firmware_sum(&h);
    CHECK("BIOS coverage gap refused",!shz_qemu_firmware_covers(&q,&h,0xffe0000,36));
    bios(&h); h.count=5; h.range[4]=(shz_native_firmware_range_t){0xffe2270,1,0,0};
    h.check=shz_native_firmware_sum(&h);
    CHECK("unknown BIOS overlap denies",!shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    bios(&h); setup(&f); original(&f,0xffe2200,4096,2);
    CHECK("original nonRAM overlap retained",capture(&q,&f)==1 && q.count==3);
    CHECK("original MMIO reservation wins over RAM",!shz_qemu_firmware_covers(&q,&h,0xffe2270,36));
    setup(&f); f.signature[0]='x';
    CHECK("bad fw_cfg signature clears stale proof",capture(&q,&f)==0 && empty(&q));
    setup(&f); f.id[0]=0;
    CHECK("unsupported fw_cfg version refused",capture(&q,&f)==0 && empty(&q));
    setup(&f);
    CHECK("unsupported bridge cannot probe fw_cfg",shz_qemu_firmware_capture(&q,0x99998086,0x11001af4,
          read_file,&f)==0 && f.reads==0 && empty(&q));
    CHECK("wrong subsystem cannot probe fw_cfg",shz_qemu_firmware_capture(&q,0x12378086,0,
          read_file,&f)==0 && f.reads==0 && empty(&q));
    CHECK("q35 exact platform supported",shz_qemu_firmware_capture(&q,0x29c08086,0x11001af4,read_file,&f)==1);
    setup(&f); be32(f.dir,1025);
    CHECK("unbounded directory count refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir,0);
    CHECK("absent original map clears proof",capture(&q,&f)==0 && empty(&q));
    setup(&f); f.dir[12]='x';
    CHECK("missing original map never guessed from PMM",capture(&q,&f)==0 && empty(&q));
    setup(&f); f.dir[10]=1;
    CHECK("directory reserved field refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); memset(f.dir+12,'x',56);
    CHECK("unterminated directory name refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); f.dir[9]=0x19;
    CHECK("nonfile selector refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir,2); memcpy(f.dir+68,f.dir+4,64);
    CHECK("duplicate original map refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir,2); memcpy(f.dir+68,f.dir+4,64); memcpy(f.dir+76,"etc/other",10);
    CHECK("same selector cannot attest two different directory files",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir+4,39);
    CHECK("fractional original record refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir+4,0);
    CHECK("empty original map refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir+4,65*20);
    CHECK("count overflow cannot hide original MMIO",capture(&q,&f)<0 && empty(&q));
    setup(&f); be32(f.dir+4,60);
    CHECK("unavailable map payload refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); uint64_t bad=UINT64_MAX-15; memcpy(f.map,&bad,8); bad=16; memcpy(f.map+8,&bad,8);
    CHECK("original range overflow refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); f.map[16]=2;
    CHECK("no actual RAM map refused",capture(&q,&f)<0 && empty(&q));
    setup(&f); f.map[16]=0;
    CHECK("unknown original type cannot attest RAM",capture(&q,&f)<0 && empty(&q));
    setup(&f); memset(f.map+8,0,8);
    CHECK("zero RAM length cannot attest",capture(&q,&f)<0 && empty(&q));
    printf("%s bounded QEMU firmware RAM: %u checks, %u failures\n",failures?"FAIL":"PASS",checks,failures);
    return failures?1:0;
}
#else
int main(void) { fputs("FAIL production QEMU original firmware RAM attestation is absent; legitimate reserved ACPI tail is unreadable\n",stderr); return 1; }
#endif
