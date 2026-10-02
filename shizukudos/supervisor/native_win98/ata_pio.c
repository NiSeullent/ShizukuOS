/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine bounded primary-channel master ATA PIO backing. Advertises LBA28 and
 * synchronous sector writes only; DMA, LBA48 and multiple-sector DRQ are absent.
 * Unknown commands abort instead of reporting fictitious device completion.
 */
#include "ata_pio.h"
#include <string.h>
#define READY 0x50u
#define DRQ 0x08u
#define ERR 0x01u
#define ABRT 0x04u
#define IDNF 0x10u

static void interrupt(w98_ata_t *a)
{
    if (!a->irq) {
        a->irq = 1;
        if (!(a->control & 2) && a->raise_irq) a->raise_irq(a->opaque);
    }
}
static void abort_command(w98_ata_t *a, uint8_t error)
{
    a->error = error; a->status = READY | ERR;
    a->remaining = a->word = 0; a->writing = a->identify = 0;
    ++a->rejected_commands; interrupt(a);
}
static void reset(w98_ata_t *a)
{
    a->features = a->lba1 = a->lba2 = a->error = a->irq = 0;
    a->lba0 = a->count = 1; a->device = 0xa0;
    a->status = READY; a->remaining = a->word = 0;
    a->writing = a->identify = a->command = 0;
    if (a->backend_failed) { a->status = READY | ERR; a->error = ABRT; }
}
int w98_ata_init(w98_ata_t *a, uint8_t *disk, uint64_t bytes,
                 void (*raise_irq)(void *), void *opaque)
{
    if (!a || !disk || bytes < 512 || bytes > (2ull << 30) || bytes % 512) return -1;
    memset(a, 0, sizeof *a); a->disk = disk; a->bytes = bytes;
    a->sectors = (uint32_t)(bytes / 512); a->raise_irq = raise_irq; a->opaque = opaque;
    reset(a); return 0;
}
int w98_ata_attach_backend(w98_ata_t *a, uint32_t optin, const w98_disk_backend_t *b)
{
    if (!a || !b || optin != W98_DISK_BACKEND_OPTIN || !a->disk || !a->bytes ||
        b->bytes != a->bytes || !b->read_sector || !b->write_sector || !b->flush ||
        a->backend_attached || a->backend_failed || a->status != READY ||
        a->remaining || a->word || a->writing || a->identify || (a->control & 4)) return -1;
    a->backend = *b; a->backend_attached = 1;
    return 0;
}
static void backend_failure(w98_ata_t *a)
{
    a->backend_failed = 1; ++a->backend_errors; abort_command(a, ABRT);
}
static void id_word(w98_ata_t *a, unsigned index, uint16_t value)
{
    a->buffer[2*index] = (uint8_t)value; a->buffer[2*index+1] = (uint8_t)(value >> 8);
}
static void id_string(w98_ata_t *a, unsigned first, unsigned words, const char *s)
{
    unsigned i; int ended = 0;
    for (i = 0; i < words*2; ++i) {
        uint8_t c = ' ';
        if (!ended) { if (*s) c = (uint8_t)*s++; else ended = 1; }
        a->buffer[first*2 + (i ^ 1)] = c;
    }
}
static void identify(w98_ata_t *a)
{
    uint32_t cylinders = a->sectors / (16*63);
    if (cylinders > 16383) cylinders = 16383;
    memset(a->buffer, 0, sizeof a->buffer);
    id_word(a, 0, 0x0040); id_word(a, 1, (uint16_t)cylinders);
    id_word(a, 3, 16); id_word(a, 6, 63);
    id_string(a, 10, 10, a->backend_attached ? "SHZ-OWNED-BLK-0001" : "SHZ-OWNED-RAM-0001");
    id_string(a, 23, 4, "0.1"); id_string(a, 27, 20, a->backend_attached ? "Shizuku owned block ATA PIO disk" : "Shizuku owned RAM ATA PIO disk");
    id_word(a, 49, 1u << 9); /* LBA supported; DMA deliberately absent. */
    id_word(a, 53, 1); id_word(a, 54, (uint16_t)cylinders);
    id_word(a, 55, 16); id_word(a, 56, 63);
    id_word(a, 57, (uint16_t)(cylinders*16*63)); id_word(a, 58, (uint16_t)((cylinders*16*63) >> 16));
    id_word(a, 60, (uint16_t)a->sectors); id_word(a, 61, (uint16_t)(a->sectors >> 16));
    id_word(a, 80, 0x0010); /* ATA-4 revision; no DMA/multiple/LBA48/cache claim. */
    if (a->backend_attached) { id_word(a, 83, 0x4000u | (1u << 12)); id_word(a, 86, 1u << 12); }
    a->remaining = 1; a->word = 0; a->writing = 0; a->identify = 1;
    a->status = READY | DRQ; interrupt(a);
}
static void update_taskfile(w98_ata_t *a)
{
    a->count = (uint8_t)a->remaining;
    if (a->device & 0x40) {
        a->lba0 = (uint8_t)a->lba; a->lba1 = (uint8_t)(a->lba >> 8); a->lba2 = (uint8_t)(a->lba >> 16);
        a->device = (uint8_t)((a->device & 0xf0) | ((a->lba >> 24) & 15));
    } else {
        uint32_t cylinder = a->lba / (16*63), remainder = a->lba % (16*63);
        a->lba0 = (uint8_t)(remainder % 63 + 1);
        a->lba1 = (uint8_t)cylinder; a->lba2 = (uint8_t)(cylinder >> 8);
        a->device = (uint8_t)((a->device & 0xf0) | (remainder / 63));
    }
}
static void next_sector(w98_ata_t *a)
{
    a->word = 0;
    if (!a->writing) {
        if (a->backend_attached) {
            if (a->backend.read_sector(a->backend.opaque, a->lba, a->buffer)) { backend_failure(a); return; }
        } else memcpy(a->buffer, a->disk + (uint64_t)a->lba*512, 512);
    }
    else memset(a->buffer, 0, 512);
    a->status = READY | DRQ;
    if (!a->writing) interrupt(a);
}
static void start_command(w98_ata_t *a, uint8_t command)
{
    uint32_t lba; unsigned count = a->count ? a->count : 256;
    a->command = command; a->error = a->irq = 0;
    a->remaining = a->word = 0; a->writing = a->identify = 0;
    if (a->device & 0x10) { a->status = 0; return; } /* No slave disk. */
    if (command == 0xec) { identify(a); return; }
    if (a->backend_failed) { abort_command(a, ABRT); return; }
    if (command == 0xe7) {
        if (a->backend_attached && a->backend.flush(a->backend.opaque)) { backend_failure(a); return; }
        a->status = READY; interrupt(a); return;
    }
    if (command == 0x91 || (command & 0xf0) == 0x10) {
        /* Fixed geometry accepts matching initialize parameters; recalibrate has no moving head. */
        if (command == 0x91 && (a->count != 63 || (a->device & 15) != 15)) { abort_command(a, ABRT); return; }
        a->status = READY; interrupt(a); return;
    }
    if (command != 0x20 && command != 0x21 && command != 0x30 && command != 0x31 && command != 0x40 && command != 0x41) {
        abort_command(a, ABRT); return;
    }
    if (a->device & 0x40) {
        lba = ((uint32_t)(a->device & 15) << 24) | ((uint32_t)a->lba2 << 16) | ((uint32_t)a->lba1 << 8) | a->lba0;
    } else {
        if (!a->lba0 || a->lba0 > 63) { abort_command(a, IDNF); return; }
        lba = (((uint32_t)a->lba2 << 8) | a->lba1)*16*63 + (uint32_t)(a->device & 15)*63 + a->lba0-1;
    }
    if (lba >= a->sectors || count > a->sectors-lba) { abort_command(a, IDNF); return; }
    a->lba = lba; a->remaining = (uint16_t)count;
    if (command == 0x40 || command == 0x41) {
        if (a->backend_attached) {
            unsigned i;
            for (i = 0; i < count; ++i)
                if (a->backend.read_sector(a->backend.opaque, lba+i, a->buffer)) { backend_failure(a); return; }
        }
        a->lba += count; a->remaining = 0; update_taskfile(a); a->status = READY; interrupt(a); return;
    }
    a->writing = command == 0x30 || command == 0x31;
    next_sector(a);
}
static int data_transfer(w98_ata_t *a, unsigned bytes, uint32_t *value, int writing)
{
    unsigned i;
    if ((bytes != 2 && bytes != 4) || !(a->status & DRQ) || a->writing != writing ||
        a->word + bytes/2 > 256 || !a->remaining) { abort_command(a, ABRT); return -1; }
    for (i = 0; i < bytes; ++i) {
        unsigned index = a->word*2 + i;
        if (writing) a->buffer[index] = (uint8_t)(*value >> (8*i));
        else *value = (*value & ~(0xffu << (8*i))) | ((uint32_t)a->buffer[index] << (8*i));
    }
    a->word = (uint16_t)(a->word + bytes/2);
    if (a->word == 256) {
        if (a->identify) { a->identify = 0; a->remaining = 0; a->status = READY; return 0; }
        if (writing) {
            if (a->backend_attached &&
                (a->backend.write_sector(a->backend.opaque, a->lba, a->buffer) ||
                 a->backend.flush(a->backend.opaque))) { backend_failure(a); return -1; }
            memcpy(a->disk + (uint64_t)a->lba*512, a->buffer, 512); ++a->sectors_written;
        }
        else ++a->sectors_read;
        ++a->lba; --a->remaining; update_taskfile(a);
        a->status = READY;
        if (writing) interrupt(a);
        if (a->remaining) next_sector(a);
    }
    return 0;
}
int w98_ata_in(w98_ata_t *a, uint16_t port, unsigned bytes, uint32_t *value)
{
    uint8_t v;
    if (!a || !value) return 0;
    if (port == 0x1f0) { *value = 0xffffffffu; (void)data_transfer(a, bytes, value, 0); return 1; }
    if (port != 0x3f6 && (port < 0x1f1 || port > 0x1f7)) return 0;
    if (bytes != 1) { abort_command(a, ABRT); *value = 0xffffffffu; return 1; }
    if (a->device & 0x10) { *value = 0; return 1; }
    switch (port) {
    case 0x1f1: v=a->error; break; case 0x1f2: v=a->count; break;
    case 0x1f3: v=a->lba0; break; case 0x1f4: v=a->lba1; break; case 0x1f5: v=a->lba2; break;
    case 0x1f6: v=a->device; break; default: v=a->status; if (port==0x1f7) a->irq=0; break;
    }
    *value=v; return 1;
}
int w98_ata_out(w98_ata_t *a, uint16_t port, unsigned bytes, uint32_t value)
{
    if (!a) return 0;
    if (port==0x1f0) { (void)data_transfer(a,bytes,&value,1); return 1; }
    if (port != 0x3f6 && (port < 0x1f1 || port > 0x1f7)) return 0;
    if (bytes != 1) { abort_command(a, ABRT); return 1; }
    switch(port) {
    case 0x1f1: a->features=(uint8_t)value; break; case 0x1f2: a->count=(uint8_t)value; break;
    case 0x1f3: a->lba0=(uint8_t)value; break; case 0x1f4: a->lba1=(uint8_t)value; break;
    case 0x1f5: a->lba2=(uint8_t)value; break; case 0x1f6: a->device=(uint8_t)value; break;
    case 0x1f7: if (!(a->control & 4)) start_command(a,(uint8_t)value); break;
    case 0x3f6: {
        uint8_t old=a->control; a->control=(uint8_t)value;
        if (value & 4) { a->status=0x80; a->remaining=a->word=0; a->irq=0; }
        else if (old & 4) reset(a);
        if ((old & 2) && !(value & 2) && a->irq && a->raise_irq) a->raise_irq(a->opaque);
        break;
    }
    }
    return 1;
}
