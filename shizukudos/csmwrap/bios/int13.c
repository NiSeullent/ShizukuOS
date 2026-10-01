/* SPDX-License-Identifier: GPL-2.0-only
 * AH=00h reset, 02h read CHS, 03h write CHS, 08h geometry,
 * 41h extensions, 42h extended read, 43h extended write, 48h EDD parameters.
 * Missing units, LBAs outside the copied sector count, and misaligned
 * transfers fail. No service returns success without checking the request.
 */
#include "int13.h"
#include <string.h>

#define INT13_MAX_SECTORS 128u

struct csmwrap_slot {
    CSMWRAP_BLOCK_DEVICE *dev;
};

static struct csmwrap_slot g_slots[3];

static int unit_index(uint8_t unit)
{
    if (unit == 0x00) return 0;
    if (unit == 0x80) return 1;
    if (unit == 0x81) return 2;
    return -1;
}

static int device_ok(const CSMWRAP_BLOCK_DEVICE *dev)
{
    return dev && dev->reset && dev->read && dev->write && dev->flush &&
           dev->geometry && dev->sector_size && dev->sector_count;
}

int csmwrap_int13_attach(uint8_t unit, CSMWRAP_BLOCK_DEVICE *dev)
{
    int index = unit_index(unit);
    if (index < 0 || !device_ok(dev)) return CSMWRAP_BLK_INVALID;
    if (dev->sector_size(dev) != CSMWRAP_SECTOR_BYTES || dev->sector_count(dev) == 0)
        return CSMWRAP_BLK_INVALID;
    g_slots[index].dev = dev;
    return CSMWRAP_BLK_OK;
}

void csmwrap_int13_detach(uint8_t unit)
{
    int index = unit_index(unit);
    if (index >= 0) g_slots[index].dev = 0;
}

void csmwrap_int13_detach_all(void)
{
    g_slots[0].dev = 0;
    g_slots[1].dev = 0;
    g_slots[2].dev = 0;
}

static CSMWRAP_BLOCK_DEVICE *unit_dev(uint8_t unit)
{
    int index = unit_index(unit);
    if (index < 0) return 0;
    return g_slots[index].dev;
}

static uint8_t class_count(uint8_t unit)
{
    if (unit & 0x80u)
        return (uint8_t)((g_slots[1].dev ? 1u : 0u) + (g_slots[2].dev ? 1u : 0u));
    return g_slots[0].dev ? 1u : 0u;
}

static void fail(struct csmwrap_int13_regs *regs, uint8_t ah)
{
    regs->ax = (uint16_t)((uint16_t)ah << 8);
    regs->flags = (uint16_t)(regs->flags | CSMWRAP_CF);
}

static void succeed(struct csmwrap_int13_regs *regs, uint16_t ax)
{
    regs->ax = ax;
    regs->flags = (uint16_t)(regs->flags & (uint16_t)~CSMWRAP_CF);
}

static int map_backend(int status)
{
    if (status == CSMWRAP_BLK_OK) return INT13_OK;
    if (status == CSMWRAP_BLK_RANGE) return INT13_SECTOR_NOT_FOUND;
    if (status == CSMWRAP_BLK_RO) return INT13_WRITE_PROTECT;
    if (status == CSMWRAP_BLK_NO_DEVICE) return INT13_NOT_READY;
    if (status == CSMWRAP_BLK_IO) return INT13_CONTROLLER;
    return INT13_BAD_PARAM;
}

static int load_geometry(CSMWRAP_BLOCK_DEVICE *dev, struct csmwrap_geometry *geo,
                         uint64_t *sectors_out)
{
    uint32_t sector_size;
    uint64_t sectors;
    uint64_t chs_sectors;
    if (!device_ok(dev)) return INT13_BAD_PARAM;
    sector_size = dev->sector_size(dev);
    sectors = dev->sector_count(dev);
    if (sector_size != CSMWRAP_SECTOR_BYTES || sectors == 0) return INT13_BAD_PARAM;
    if (dev->geometry(dev, geo) != CSMWRAP_BLK_OK) return INT13_BAD_PARAM;
    if (geo->cylinders == 0 || geo->cylinders > 1024u || geo->heads == 0 ||
        geo->heads > 255u || geo->sectors_per_track == 0 ||
        geo->sectors_per_track > 63u)
        return INT13_BAD_PARAM;
    chs_sectors = (uint64_t)geo->cylinders * geo->heads * geo->sectors_per_track;
    if (chs_sectors == 0 || chs_sectors > sectors) return INT13_BAD_PARAM;
    *sectors_out = sectors;
    return INT13_OK;
}

static uint32_t rd16(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}

static uint64_t rd64(const uint8_t *p)
{
    uint64_t lo = (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) |
                  ((uint64_t)p[3] << 24);
    uint64_t hi = (uint64_t)p[4] | ((uint64_t)p[5] << 8) | ((uint64_t)p[6] << 16) |
                  ((uint64_t)p[7] << 24);
    return lo | (hi << 32);
}

static void wr16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void wr32(uint8_t *p, uint32_t value)
{
    unsigned i;
    for (i = 0; i < 4u; ++i) p[i] = (uint8_t)(value >> (8u * i));
}

static int resolve_buffer(uint32_t linear, uint32_t bytes, uint32_t guest_bytes,
                          int check_64k, uint32_t *out)
{
    if (bytes == 0 || bytes > guest_bytes || linear > guest_bytes - bytes)
        return INT13_BAD_PARAM;
    if (linear & (CSMWRAP_SECTOR_BYTES - 1u)) return INT13_BOUNDARY;
    if (check_64k) {
        uint32_t last = linear + bytes - 1u;
        if ((linear & ~0xffffu) != (last & ~0xffffu)) return INT13_BOUNDARY;
    }
    *out = linear;
    return INT13_OK;
}

static int seg_buffer(uint16_t seg, uint16_t off, uint32_t bytes, uint32_t guest_bytes,
                      uint32_t *linear)
{
    uint32_t base;
    if ((uint32_t)off + bytes < (uint32_t)off) return INT13_BOUNDARY;
    if ((uint32_t)off + bytes > 0x10000u) return INT13_BOUNDARY;
    base = ((uint32_t)seg << 4) + off;
    return resolve_buffer(base, bytes, guest_bytes, 1, linear);
}

static void chs_transfer(struct csmwrap_int13_regs *regs, uint8_t *guest,
                         uint32_t guest_bytes, int write)
{
    CSMWRAP_BLOCK_DEVICE *dev;
    struct csmwrap_geometry geo;
    uint64_t sectors, lba, chs_limit;
    uint32_t count, bytes, linear, status;
    uint16_t cyl;
    uint8_t head, sec, unit;
    int backend;
    unit = (uint8_t)regs->dx;
    count = (uint32_t)(regs->ax & 0xffu);
    dev = unit_dev(unit);
    if (!dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (count == 0 || count > INT13_MAX_SECTORS) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    status = (uint32_t)load_geometry(dev, &geo, &sectors);
    if (status != INT13_OK) {
        fail(regs, (uint8_t)status);
        return;
    }
    cyl = (uint16_t)(((regs->cx >> 8) & 0xffu) | ((regs->cx & 0xc0u) << 2));
    sec = (uint8_t)(regs->cx & 0x3fu);
    head = (uint8_t)(regs->dx >> 8);
    if (sec == 0 || sec > geo.sectors_per_track || head >= geo.heads ||
        cyl >= geo.cylinders) {
        fail(regs, INT13_SECTOR_NOT_FOUND);
        return;
    }
    lba = ((uint64_t)cyl * geo.heads + head) * geo.sectors_per_track +
          ((uint64_t)sec - 1u);
    chs_limit = (uint64_t)geo.cylinders * geo.heads * geo.sectors_per_track;
    if (lba >= chs_limit || (uint64_t)count > chs_limit - lba || lba >= sectors ||
        (uint64_t)count > sectors - lba) {
        fail(regs, INT13_SECTOR_NOT_FOUND);
        return;
    }
    bytes = count * CSMWRAP_SECTOR_BYTES;
    status = (uint32_t)seg_buffer(regs->es, regs->bx, bytes, guest_bytes, &linear);
    if (status != INT13_OK) {
        fail(regs, (uint8_t)status);
        return;
    }
    backend = write ? dev->write(dev, lba, guest + linear, count)
                    : dev->read(dev, lba, guest + linear, count);
    if (backend != CSMWRAP_BLK_OK) {
        fail(regs, (uint8_t)map_backend(backend));
        return;
    }
    succeed(regs, (uint16_t)count);
}

static void service_geometry(struct csmwrap_int13_regs *regs, uint8_t *guest,
                             uint32_t guest_bytes)
{
    CSMWRAP_BLOCK_DEVICE *dev;
    struct csmwrap_geometry geo;
    uint64_t sectors;
    uint8_t unit = (uint8_t)regs->dx;
    uint16_t max_cyl;
    static const uint8_t floppy_dpt[11] = {
        0xdf, 0x02, 0x25, 0x02, 0x12, 0x1b, 0xff, 0x6c, 0xf6, 0x0f, 0x08
    };
    dev = unit_dev(unit);
    regs->dx = (uint16_t)((regs->dx & 0xff00u) | class_count(unit));
    if (!dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (load_geometry(dev, &geo, &sectors) != INT13_OK) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    max_cyl = (uint16_t)(geo.cylinders - 1u);
    regs->cx = (uint16_t)(((max_cyl & 0xffu) << 8) |
                          ((max_cyl >> 2) & 0xc0u) |
                          (geo.sectors_per_track & 0x3fu));
    regs->dx = (uint16_t)(((uint16_t)(geo.heads - 1u) << 8) | class_count(unit));
    if ((unit & 0x80u) == 0) {
        if (guest_bytes < 0x520u + sizeof floppy_dpt) {
            fail(regs, INT13_BAD_PARAM);
            return;
        }
        memcpy(guest + 0x520u, floppy_dpt, sizeof floppy_dpt);
        regs->es = 0;
        regs->di = 0x0520u;
        regs->bx = (uint16_t)((regs->bx & 0xff00u) | 0x04u);
    }
    succeed(regs, 0);
}

static void service_extensions(struct csmwrap_int13_regs *regs)
{
    uint8_t unit = (uint8_t)regs->dx;
    CSMWRAP_BLOCK_DEVICE *dev = unit_dev(unit);
    uint16_t al = (uint16_t)(regs->ax & 0xffu);
    if (regs->bx != 0x55aau || !dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    /* CX bit0 packet access, bit2 EDD, bit3 64-bit flat buffer. */
    regs->bx = 0xaa55u;
    regs->cx = 0x000du;
    succeed(regs, (uint16_t)(0x3000u | al));
}

static int packet_buffer(const uint8_t *packet, uint8_t packet_size,
                         uint32_t count, uint32_t guest_bytes, uint32_t *linear)
{
    uint32_t bytes = count * CSMWRAP_SECTOR_BYTES;
    uint16_t off = (uint16_t)rd16(packet + 4);
    uint16_t seg = (uint16_t)rd16(packet + 6);
    if (seg == 0xffffu && off == 0xffffu) {
        uint64_t flat;
        if (packet_size < 0x18u) return INT13_BAD_PARAM;
        flat = rd64(packet + 16);
        if (flat > 0xffffffffull) return INT13_BAD_PARAM;
        return resolve_buffer((uint32_t)flat, bytes, guest_bytes, 1, linear);
    }
    return seg_buffer(seg, off, bytes, guest_bytes, linear);
}

static void edd_transfer(struct csmwrap_int13_regs *regs, uint8_t *guest,
                         uint32_t guest_bytes, int write)
{
    CSMWRAP_BLOCK_DEVICE *dev;
    struct csmwrap_geometry geo;
    uint64_t sectors, lba;
    uint32_t count, linear, status, pkt_lin;
    uint8_t packet_size, unit, verify;
    const uint8_t *packet;
    int backend;
    unit = (uint8_t)regs->dx;
    verify = (uint8_t)(regs->ax & 0xffu);
    dev = unit_dev(unit);
    if (!dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (write && verify > 1u) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (!write && verify != 0) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    /* The packet is not a sector transfer, so it is not sector-aligned. */
    if (((uint32_t)regs->si + 0x10u) > 0x10000u) {
        fail(regs, INT13_BOUNDARY);
        return;
    }
    pkt_lin = ((uint32_t)regs->ds << 4) + regs->si;
    if (pkt_lin > guest_bytes - 0x10u) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    packet = guest + pkt_lin;
    packet_size = packet[0];
    if (packet_size < 0x10u) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (packet_size >= 0x18u) {
        uint32_t need = packet_size;
        if (need > 32u) need = 32u;
        if (guest_bytes < need || ((uint32_t)regs->si + need) > 0x10000u ||
            pkt_lin > guest_bytes - need) {
            fail(regs, INT13_BAD_PARAM);
            return;
        }
    }
    count = rd16(packet + 2);
    if (count == 0 || count > INT13_MAX_SECTORS) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    lba = rd64(packet + 8);
    status = (uint32_t)load_geometry(dev, &geo, &sectors);
    if (status != INT13_OK) {
        fail(regs, (uint8_t)status);
        return;
    }
    if (lba >= sectors || (uint64_t)count > sectors - lba) {
        fail(regs, INT13_SECTOR_NOT_FOUND);
        return;
    }
    status = (uint32_t)packet_buffer(packet, packet_size, count, guest_bytes, &linear);
    if (status != INT13_OK) {
        fail(regs, (uint8_t)status);
        return;
    }
    backend = write ? dev->write(dev, lba, guest + linear, count)
                    : dev->read(dev, lba, guest + linear, count);
    if (backend != CSMWRAP_BLK_OK) {
        fail(regs, (uint8_t)map_backend(backend));
        return;
    }
    if (write && verify) {
        uint32_t i;
        uint8_t check[CSMWRAP_SECTOR_BYTES];
        for (i = 0; i < count; ++i) {
            if (dev->read(dev, lba + i, check, 1) != CSMWRAP_BLK_OK ||
                memcmp(check, guest + linear + i * CSMWRAP_SECTOR_BYTES,
                       CSMWRAP_SECTOR_BYTES) != 0) {
                fail(regs, INT13_BAD_SECTOR);
                return;
            }
        }
    }
    succeed(regs, (uint16_t)(regs->ax & 0xff00u));
}

static void edd_params(struct csmwrap_int13_regs *regs, uint8_t *guest,
                       uint32_t guest_bytes)
{
    CSMWRAP_BLOCK_DEVICE *dev;
    struct csmwrap_geometry geo;
    uint64_t sectors;
    uint32_t pkt_lin, given;
    uint8_t *buf;
    uint8_t unit = (uint8_t)regs->dx;
    uint16_t flags;
    dev = unit_dev(unit);
    if (!dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (((uint32_t)regs->si + 0x1au) > 0x10000u) {
        fail(regs, INT13_BOUNDARY);
        return;
    }
    pkt_lin = ((uint32_t)regs->ds << 4) + regs->si;
    if (guest_bytes < 0x1au || pkt_lin > guest_bytes - 0x1au) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    buf = guest + pkt_lin;
    given = rd16(buf);
    if (given < 0x1au) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    if (load_geometry(dev, &geo, &sectors) != INT13_OK) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    memset(buf, 0, 0x1au);
    wr16(buf, 0x001au);
    flags = 0x000au; /* geometry valid, write-with-verify */
    if ((unit & 0x80u) == 0) flags = (uint16_t)(flags | 0x0014u);
    wr16(buf + 2, flags);
    wr32(buf + 4, geo.cylinders);
    wr32(buf + 8, geo.heads);
    wr32(buf + 12, geo.sectors_per_track);
    wr32(buf + 16, (uint32_t)sectors);
    wr32(buf + 20, (uint32_t)(sectors >> 32));
    wr16(buf + 24, (uint16_t)CSMWRAP_SECTOR_BYTES);
    succeed(regs, 0);
}

static void service_reset(struct csmwrap_int13_regs *regs)
{
    uint8_t unit = (uint8_t)regs->dx;
    CSMWRAP_BLOCK_DEVICE *dev = unit_dev(unit);
    int status;
    if (!dev) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    status = dev->reset(dev);
    if (status != CSMWRAP_BLK_OK) {
        fail(regs, status == CSMWRAP_BLK_NO_DEVICE ? INT13_NOT_READY
                                                   : INT13_RESET_FAILED);
        return;
    }
    succeed(regs, 0);
}

void csmwrap_int13(struct csmwrap_int13_regs *regs, uint8_t *guest,
                   uint32_t guest_bytes)
{
    uint8_t ah;
    if (!regs) return;
    if (!guest || guest_bytes < 16u) {
        fail(regs, INT13_BAD_PARAM);
        return;
    }
    ah = (uint8_t)(regs->ax >> 8);
    switch (ah) {
    case 0x00: service_reset(regs); break;
    case 0x02: chs_transfer(regs, guest, guest_bytes, 0); break;
    case 0x03: chs_transfer(regs, guest, guest_bytes, 1); break;
    case 0x08: service_geometry(regs, guest, guest_bytes); break;
    case 0x41: service_extensions(regs); break;
    case 0x42: edd_transfer(regs, guest, guest_bytes, 0); break;
    case 0x43: edd_transfer(regs, guest, guest_bytes, 1); break;
    case 0x48: edd_params(regs, guest, guest_bytes); break;
    default: fail(regs, INT13_BAD_PARAM); break;
    }
}
