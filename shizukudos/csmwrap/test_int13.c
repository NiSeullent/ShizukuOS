/* SPDX-License-Identifier: GPL-2.0-only
 * Host proof for the CSM INT 13h disk path. The RAM disk stores real
 * bytes. The AHCI hook is linked to ahci_read_sector and refuses I/O
 * when no AHCI_READY controller is bound.
 */
#include "bios/int13.h"
#include "storage/ahci_hook.h"
#include "storage/handoff.h"
#include "storage/ramdisk.h"
#include <stdio.h>
#include <string.h>

static int g_failed;

static void expect(int cond, const char *name)
{
    if (cond) {
        printf("  PASS %s\n", name);
        return;
    }
    printf("  FAIL %s\n", name);
    g_failed++;
}

static void pattern(uint8_t *dst, uint32_t bytes, uint64_t lba)
{
    uint32_t i;
    for (i = 0; i < bytes; ++i)
        dst[i] = (uint8_t)(i * 37u + 0x5au + (uint32_t)lba * 13u);
}

static void regs_clear(struct csmwrap_int13_regs *regs)
{
    memset(regs, 0, sizeof *regs);
}

static void put_dap(uint8_t *guest, uint16_t at, uint8_t size, uint16_t count,
                    uint16_t off, uint16_t seg, uint64_t lba, uint64_t flat)
{
    uint8_t *p = guest + at;
    unsigned i;
    memset(p, 0, 32);
    p[0] = size;
    p[2] = (uint8_t)count;
    p[3] = (uint8_t)(count >> 8);
    p[4] = (uint8_t)off;
    p[5] = (uint8_t)(off >> 8);
    p[6] = (uint8_t)seg;
    p[7] = (uint8_t)(seg >> 8);
    for (i = 0; i < 8; ++i) p[8 + i] = (uint8_t)(lba >> (8 * i));
    if (size >= 0x18) {
        for (i = 0; i < 8; ++i) p[16 + i] = (uint8_t)(flat >> (8 * i));
    }
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

int main(void)
{
    enum { GUEST = 256 * 1024 };
    static uint8_t guest[GUEST];
    static uint8_t hdd0_mem[2016u * 512u];
    static uint8_t hdd1_mem[1018u * 512u];
    static uint8_t floppy_mem[2880u * 512u];
    struct csmwrap_ramdisk raw0, raw1, rawf;
    CSMWRAP_BLOCK_DEVICE dev0, dev1, devf, ahci_dev;
    struct csmwrap_ahci_hook hook;
    struct ahci_device closed;
    struct csmwrap_disk_identity id, poisoned;
    struct csmwrap_geometry geo;
    struct csmwrap_int13_regs regs;
    uint8_t block[1024], back[1024], efi_buf[512];
    uint8_t marker[512];
    int rc;

    printf("block contract\n");
    rc = csmwrap_ramdisk_init(&raw0, &dev0, hdd0_mem, sizeof hdd0_mem,
                              CSMWRAP_SECTOR_BYTES, 0);
    expect(rc == CSMWRAP_BLK_OK, "ramdisk init 2016 sectors");
    expect(dev0.sector_size(&dev0) == 512u, "sector size 512");
    expect(dev0.sector_count(&dev0) == 2016u, "sector count 2016");
    expect(dev0.geometry(&dev0, &geo) == CSMWRAP_BLK_OK && geo.cylinders == 2 &&
               geo.heads == 16 && geo.sectors_per_track == 63,
           "geometry 2/16/63");
    pattern(block, 512, 7);
    memset(back, 0xa5, sizeof back);
    expect(dev0.write(&dev0, 2016, block, 1) == CSMWRAP_BLK_RANGE,
           "block write past end fails");
    expect(back[0] == 0xa5, "rejected write leaves caller buffer");
    expect(dev0.write(&dev0, 7, block, 1) == CSMWRAP_BLK_OK, "block write lba 7");
    pattern(block, 512, 11);
    expect(dev0.write(&dev0, 11, block, 1) == CSMWRAP_BLK_OK, "block write lba 11 pattern");
    memset(back, 0, 512);
    expect(dev0.read(&dev0, 7, back, 1) == CSMWRAP_BLK_OK, "block read lba 7");
    pattern(block, 512, 7);
    expect(memcmp(back, block, 512) == 0, "lba 7 bytes match");
    memset(back, 0, 512);
    expect(dev0.read(&dev0, 11, back, 1) == CSMWRAP_BLK_OK, "block read lba 11");
    pattern(block, 512, 11);
    expect(memcmp(back, block, 512) == 0, "lba 11 bytes match");
    expect(dev0.flush(&dev0) == CSMWRAP_BLK_OK && raw0.flushes == 1, "flush counted");
    expect(dev0.read(&dev0, 11, back, 1) == CSMWRAP_BLK_OK && memcmp(back, block, 512) == 0,
           "data still present after flush");
    expect(dev0.reset(&dev0) == CSMWRAP_BLK_OK && raw0.resets == 1, "reset counted");
    expect(dev0.read(&dev0, 7, back, 1) == CSMWRAP_BLK_OK, "data still present after reset");
    pattern(block, 512, 7);
    expect(memcmp(back, block, 512) == 0, "reset does not erase media");

    printf("ahci hook\n");
    memset(&closed, 0, sizeof closed);
    expect(csmwrap_ahci_hook_init(&hook, &ahci_dev) == CSMWRAP_BLK_OK, "ahci hook init");
    expect(ahci_dev.read(&ahci_dev, 0, back, 1) == CSMWRAP_BLK_NO_DEVICE,
           "unbound ahci read fails");
    expect(ahci_dev.write(&ahci_dev, 0, block, 1) == CSMWRAP_BLK_NO_DEVICE,
           "unbound ahci write fails");
    expect(ahci_dev.sector_count(&ahci_dev) == 0 && ahci_dev.sector_size(&ahci_dev) == 0,
           "unbound ahci reports no media");
    expect(csmwrap_ahci_hook_bind(&hook, 0) == CSMWRAP_BLK_NO_DEVICE, "bind null fails");
    expect(csmwrap_ahci_hook_bind(&hook, &closed) == CSMWRAP_BLK_NO_DEVICE,
           "bind closed controller fails");
    expect(ahci_dev.read(&ahci_dev, 0, back, 1) == CSMWRAP_BLK_NO_DEVICE,
           "read after failed bind still fails");

    printf("handoff\n");
    expect(csmwrap_capture_identity(&id, 0x80, CSMWRAP_MEDIUM_RAM, 512, 2016, 0,
                                    "RAM-HDD0") == CSMWRAP_BLK_OK,
           "capture identity before ExitBootServices");
    expect(id.magic == CSMWRAP_ID_MAGIC && id.sector_size == 512 &&
               id.sector_count == 2016 && id.cylinders == 2 && id.heads == 16 &&
               id.sectors_per_track == 63 && id.copied_while_boot_services == 1 &&
               strcmp(id.model, "RAM-HDD0") == 0,
           "snapshot holds copied geometry");
    memset(efi_buf, 0x3c, sizeof efi_buf);
    expect(csmwrap_efi_block_io_read((const void *)1, 7, efi_buf, 1) ==
               CSMWRAP_BLK_BOOT_SERVICES,
           "block io read is not invoked");
    expect(efi_buf[0] == 0x3c && efi_buf[511] == 0x3c, "block io read left buffer");

    printf("int 13h\n");
    expect(csmwrap_ramdisk_init(&raw1, &dev1, hdd1_mem, sizeof hdd1_mem,
                                CSMWRAP_SECTOR_BYTES, 0) == CSMWRAP_BLK_OK,
           "second ramdisk");
    expect(csmwrap_ramdisk_init(&rawf, &devf, floppy_mem, sizeof floppy_mem,
                                CSMWRAP_SECTOR_BYTES, 1) == CSMWRAP_BLK_OK,
           "floppy ramdisk");
    expect(devf.geometry(&devf, &geo) == CSMWRAP_BLK_OK && geo.cylinders == 80 &&
               geo.heads == 2 && geo.sectors_per_track == 18,
           "floppy geometry 80/2/18");
    expect(dev1.geometry(&dev1, &geo) == CSMWRAP_BLK_OK && geo.cylinders == 1 &&
               geo.heads == 16 && geo.sectors_per_track == 63,
           "partial CHS disk geometry");
    csmwrap_int13_detach_all();
    expect(csmwrap_int13_attach(0x00, &devf) == CSMWRAP_BLK_OK, "map 0x00");
    expect(csmwrap_int13_attach(0x80, &dev0) == CSMWRAP_BLK_OK, "map 0x80");
    expect(csmwrap_int13_attach(0x81, &dev1) == CSMWRAP_BLK_OK, "map 0x81");
    expect(csmwrap_int13_attach(0x82, &dev0) == CSMWRAP_BLK_INVALID, "reject unit 0x82");
    expect(csmwrap_int13_attach(0x01, &devf) == CSMWRAP_BLK_INVALID, "reject unit 0x01");

    memset(guest, 0, sizeof guest);
    regs_clear(&regs);
    regs.ax = 0x0000;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && regs.ax == 0 && raw0.resets == 2,
           "ah=00 reset drive 0x80");

    pattern(block, 1024, 7);
    memcpy(guest + 0x8000, block, 1024);
    regs_clear(&regs);
    regs.ax = 0x0302;
    regs.bx = 0x8000;
    regs.cx = 0x0008; /* cyl 0 sec 8 */
    regs.dx = 0x0080; /* head 0 */
    regs.es = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && regs.ax == 0x0002, "ah=03 chs write 2 sectors");
    memset(guest + 0x9000, 0xa5, 1024);
    regs_clear(&regs);
    regs.ax = 0x0202;
    regs.bx = 0x9000;
    regs.cx = 0x0008;
    regs.dx = 0x0080;
    regs.es = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && regs.ax == 0x0002 &&
               memcmp(guest + 0x9000, block, 1024) == 0,
           "ah=02 chs read matches");

    memset(guest + 0x9000, 0xa5, 512);
    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.bx = 0x0001;
    regs.cx = 0x0001;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BOUNDARY &&
               guest[0x9000] == 0xa5,
           "unaligned chs transfer sets ah=09");

    memset(guest + 0xfe00, 0x5a, 512);
    regs_clear(&regs);
    regs.ax = 0x0202;
    regs.bx = 0xfe00;
    regs.cx = 0x0001;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BOUNDARY &&
               guest[0xfe00] == 0x5a,
           "64k boundary chs transfer sets ah=09");

    regs_clear(&regs);
    regs.ax = 0x0800;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && (regs.cx & 0xff) == 63 &&
               ((regs.cx >> 8) & 0xff) == 1 && (regs.dx >> 8) == 15 &&
               (regs.dx & 0xff) == 2,
           "ah=08 hdd geometry and drive count");

    regs_clear(&regs);
    regs.ax = 0x0800;
    regs.dx = 0x0000;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && (regs.cx & 0xff) == 18 &&
               (regs.cx >> 8) == 79 && (regs.dx >> 8) == 1 && (regs.dx & 0xff) == 1 &&
               (regs.bx & 0xff) == 4 && guest[0x520] == 0xdf && guest[0x524] == 0x12,
           "ah=08 floppy geometry and dpt");

    regs_clear(&regs);
    regs.ax = 0x4100;
    regs.bx = 0x55aa;
    regs.dx = 0x0081;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && (regs.ax >> 8) == 0x30 &&
               regs.bx == 0xaa55 && (regs.cx & 0x0001) != 0,
           "ah=41 extensions present");

    pattern(block, 512, 1008);
    put_dap(guest, 0x7c00, 0x10, 1, 0x0000, 0x1000, 1008, 0);
    memcpy(guest + 0x10000, block, 512);
    regs_clear(&regs);
    regs.ax = 0x4300;
    regs.dx = 0x0081;
    regs.ds = 0x07c0;
    regs.si = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0, "ah=43 edd write lba 1008");
    memset(guest + 0x12000, 0, 512);
    put_dap(guest, 0x7c00, 0x10, 1, 0x2000, 0x1000, 1008, 0);
    regs_clear(&regs);
    regs.ax = 0x4200;
    regs.dx = 0x0081;
    regs.ds = 0x07c0;
    regs.si = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && memcmp(guest + 0x12000, block, 512) == 0,
           "ah=42 edd read lba 1008");

    pattern(marker, 512, 3);
    memcpy(guest + 0x18000, marker, 512);
    put_dap(guest, 0x7c00, 0x18, 1, 0xffff, 0xffff, 3, 0x18000);
    regs_clear(&regs);
    regs.ax = 0x4301;
    regs.dx = 0x0080;
    regs.ds = 0x07c0;
    regs.si = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0, "ah=43 verify flat write");
    memset(back, 0, 512);
    expect(dev0.read(&dev0, 3, back, 1) == CSMWRAP_BLK_OK && memcmp(back, marker, 512) == 0,
           "flat verify write reached ram disk");

    memset(guest + 0xa000, 0xa5, 512);
    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.bx = 0xa000;
    regs.cx = (uint16_t)((2u << 8) | 1u); /* cylinder 2 is outside 2-cylinder disk */
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_SECTOR_NOT_FOUND &&
               guest[0xa000] == 0xa5,
           "chs cylinder past geometry fails");

    put_dap(guest, 0x7c00, 0x10, 1, 0x0000, 0x1000, 2016, 0);
    memset(guest + 0x10000, 0xa5, 512);
    regs_clear(&regs);
    regs.ax = 0x4200;
    regs.dx = 0x0080;
    regs.ds = 0x07c0;
    regs.si = 0;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_SECTOR_NOT_FOUND &&
               guest[0x10000] == 0xa5,
           "edd lba past sector count fails");

    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.bx = 0x8000;
    regs.cx = 0x0001;
    regs.dx = 0x0082;
    memset(guest + 0x8000, 0xa5, 512);
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BAD_PARAM &&
               guest[0x8000] == 0xa5,
           "missing hard disk 0x82 fails");

    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.dx = 0x0001;
    regs.bx = 0x8000;
    regs.cx = 0x0001;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BAD_PARAM,
           "missing floppy 0x01 fails");

    regs_clear(&regs);
    regs.ax = 0x4100;
    regs.bx = 0x55aa;
    regs.dx = 0x0082;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BAD_PARAM &&
               regs.bx == 0x55aa,
           "extensions check on missing drive does not report success");

    regs_clear(&regs);
    regs.ax = 0x9900;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) != 0 && (regs.ax >> 8) == INT13_BAD_PARAM,
           "unknown function fails");

    put_dap(guest, 0x6000, 0, 0, 0, 0, 0, 0);
    guest[0x6000] = 0x1a;
    regs_clear(&regs);
    regs.ax = 0x4800;
    regs.dx = 0x0081;
    regs.ds = 0;
    regs.si = 0x6000;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && rd32(guest + 0x6004) == 1 &&
               rd32(guest + 0x6008) == 16 && rd32(guest + 0x600c) == 63 &&
               rd32(guest + 0x6010) == 1018 && guest[0x6018] == 0x00 &&
               guest[0x6019] == 0x02,
           "ah=48 edd parameters");

    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.dx = 0x0100; /* cyl 0 head 1 sec 1 -> lba 18 on a floppy */
    regs.bx = 0x8000;
    pattern(block, 512, 18);
    memcpy(guest + 0x8000, block, 512);
    regs.ax = 0x0301;
    csmwrap_int13(&regs, guest, GUEST);
    memset(guest + 0x9000, 0, 512);
    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.cx = 0x0001;
    regs.dx = 0x0100;
    regs.bx = 0x9000;
    csmwrap_int13(&regs, guest, GUEST);
    expect((regs.flags & CSMWRAP_CF) == 0 && memcmp(guest + 0x9000, block, 512) == 0,
           "floppy chs head 1 matches lba 18");

    printf("after ExitBootServices\n");
    memset(&poisoned, 0x5a, sizeof poisoned);
    csmwrap_boot_services_exit();
    expect(csmwrap_boot_services_exited() != 0, "boot services marked exited");
    expect(csmwrap_capture_identity(&poisoned, 0x80, CSMWRAP_MEDIUM_RAM, 512, 2016, 0,
                                    "LATE") == CSMWRAP_BLK_BOOT_SERVICES,
           "capture refused after ExitBootServices");
    expect(poisoned.magic == 0x5a5a5a5au, "failed capture does not rewrite identity");
    memset(efi_buf, 0x11, sizeof efi_buf);
    expect(csmwrap_efi_block_io_read((const void *)0x1000, 0, efi_buf, 1) ==
                   CSMWRAP_BLK_BOOT_SERVICES &&
               csmwrap_efi_block_io_write((const void *)0x1000, 0, efi_buf, 1) ==
                   CSMWRAP_BLK_BOOT_SERVICES &&
               efi_buf[0] == 0x11,
           "block io transfer refused after ExitBootServices");
    expect(id.sector_count == 2016 && id.sector_size == 512,
           "handoff snapshot still holds pre-exit identity");
    memset(guest + 0x9000, 0, 512);
    regs_clear(&regs);
    regs.ax = 0x0201;
    regs.bx = 0x9000;
    regs.cx = 0x0008;
    regs.dx = 0x0080;
    csmwrap_int13(&regs, guest, GUEST);
    pattern(block, 512, 7);
    expect((regs.flags & CSMWRAP_CF) == 0 && memcmp(guest + 0x9000, block, 512) == 0,
           "int 13h still reads the native ram disk after ExitBootServices");

    if (g_failed) {
        printf("%d failed\n", g_failed);
        return 1;
    }
    printf("ALL PASS\n");
    return 0;
}
