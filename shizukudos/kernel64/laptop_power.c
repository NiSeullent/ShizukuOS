/* SPDX-License-Identifier: GPL-2.0-only
 * Native ACPI fixed-feature power provider; see laptop_power.h for the authority model. */
#include "laptop_power.h"
#include "../../drivers/shz_laptop/internal.h"

#define LEDGER_MAX 8u
#define F_READ 1u
#define F_WRITE 2u
struct grant { uint16_t base, len; uint8_t flags; };
static struct {
    uint32_t busy, open, timeout_us, smi_ok, reset_ok;
    uint64_t generation, next_generation;
    struct grant ledger[LEDGER_MAX];
    unsigned ledger_n;
    struct k64_power_hw hw;
    struct shz_fixed_power fp;
} P;

/* Ports owned by other kernel drivers; a FADT register pointing here is refused. 0xCF9 (reset control) is not listed. */
static const struct { uint16_t lo, hi; } deny[] = {
    {0x0020, 0x0021}, {0x00a0, 0x00a1}, {0x0040, 0x0043}, {0x0060, 0x0060}, {0x0064, 0x0064},
    {0x0070, 0x0071}, {0x03f8, 0x03ff}, {0x0cf8, 0x0cf8}, {0x0cfc, 0x0cff}, {0x0061, 0x0061}
};
static int denied(uint32_t base, uint32_t len) {
    unsigned i;
    for (i = 0; i < sizeof(deny) / sizeof(deny[0]); i++)
        if (base <= deny[i].hi && base + len - 1u >= deny[i].lo) return 1;
    return 0;
}
static int grant_add(uint64_t address, unsigned len, unsigned flags) {
    unsigned i;
    if (address > 0xffffu || address + len > 0x10000u) return SHZ_UNSUPPORTED;
    if (denied((uint32_t)address, len)) return SHZ_BUSY;
    for (i = 0; i < P.ledger_n; i++)                         /* merge identical range */
        if (P.ledger[i].base == address && P.ledger[i].len == len) { P.ledger[i].flags |= (uint8_t)flags; return SHZ_DRIVER_OK; }
    if (P.ledger_n >= LEDGER_MAX) return SHZ_CAPACITY;
    P.ledger[P.ledger_n].base = (uint16_t)address; P.ledger[P.ledger_n].len = (uint16_t)len;
    P.ledger[P.ledger_n].flags = (uint8_t)flags; P.ledger_n++;
    return SHZ_DRIVER_OK;
}
static int op_validate(void *c, uint64_t owner, uint64_t gen, const struct shz_gas *g, unsigned bytes, int write) {
    unsigned i; (void)c;
    if (!P.open || owner != K64_POWER_OWNER || gen != P.generation || !P.busy) return SHZ_REVOKED;
    if (!g || g->space != 1 || g->address > 0xffffu) return SHZ_UNSUPPORTED;
    for (i = 0; i < P.ledger_n; i++)
        if (g->address >= P.ledger[i].base && g->address + bytes <= (uint32_t)P.ledger[i].base + P.ledger[i].len &&
            (P.ledger[i].flags & (write ? F_WRITE : F_READ))) return SHZ_DRIVER_OK;
    return SHZ_REVOKED;
}
static int op_read(void *c, const struct shz_gas *g, unsigned bytes, uint32_t *v) {
    (void)c; *v = P.hw.in(P.hw.context, (uint16_t)g->address, bytes); return SHZ_DRIVER_OK;
}
static int op_write(void *c, const struct shz_gas *g, unsigned bytes, uint32_t v) {
    (void)c; P.hw.out(P.hw.context, (uint16_t)g->address, bytes, v); return SHZ_DRIVER_OK;
}
static uint64_t op_now(void *c) { (void)c; return P.hw.now_us(P.hw.context); }
static void op_relax(void *c) { (void)c; if (P.hw.relax) P.hw.relax(P.hw.context); }

static int enter(void) {
    if (!P.open) return SHZ_NOT_FOUND;
    if (__atomic_exchange_n(&P.busy, 1u, __ATOMIC_ACQUIRE)) return SHZ_BUSY;
    if (!P.open) { __atomic_store_n(&P.busy, 0u, __ATOMIC_RELEASE); return SHZ_NOT_FOUND; }
    return SHZ_DRIVER_OK;
}
static int leave(int r) { __atomic_store_n(&P.busy, 0u, __ATOMIC_RELEASE); return r; }

static int acpi_mode(int *yes) {                              /* SCI_EN of PM1 control, same rule as shz_fixed_enable */
    uint32_t a, b = 1; int r = shz_reg_read(&P.fp.ops, P.fp.owner, P.fp.generation, &P.fp.table.control_a, 2, &a);
    if (r) return r;
    if (P.fp.table.control_b.address) {
        r = shz_reg_read(&P.fp.ops, P.fp.owner, P.fp.generation, &P.fp.table.control_b, 2, &b);
        if (r) return r;
    }
    *yes = (a & b & 1u) != 0; return SHZ_DRIVER_OK;
}

int k64_laptop_power_open_hw(const struct shz_laptop_firmware *fw, const struct k64_laptop_power_policy *policy,
                             const struct k64_power_hw *hw) {
    const struct shz_fixed *f; unsigned timeout; int r, yes;
    if (!fw || !policy || !hw || !hw->in || !hw->out || !hw->now_us) return SHZ_INVALID;
    if (!policy->allow_fixed_io) return SHZ_UNSUPPORTED;      /* table addresses are not a grant */
    timeout = policy->timeout_us ? policy->timeout_us : 100000u;
    if (timeout > 30000000u) return SHZ_INVALID;
    f = &fw->fixed;
    if (!f->event_a.address || !f->control_a.address) return SHZ_NOT_FOUND;
    if (f->event_a.space != 1 || f->control_a.space != 1 ||
        (f->event_b.address && f->event_b.space != 1) || (f->control_b.address && f->control_b.space != 1))
        return SHZ_UNSUPPORTED;                               /* MMIO needs a mapping owner we do not have */
    if (__atomic_exchange_n(&P.busy, 1u, __ATOMIC_ACQUIRE)) return SHZ_BUSY;
    if (P.open) return leave(SHZ_BUSY);
    shz_zero(&P.ledger, sizeof P.ledger); P.ledger_n = 0; P.smi_ok = P.reset_ok = 0;
    r = grant_add(f->event_a.address, 4, F_READ | F_WRITE);
    if (!r && f->event_b.address) r = grant_add(f->event_b.address, 4, F_READ | F_WRITE);
    if (!r) r = grant_add(f->control_a.address, 2, F_READ);
    if (!r && f->control_b.address) r = grant_add(f->control_b.address, 2, F_READ);
    if (r) { P.ledger_n = 0; return leave(r); }
    if (policy->allow_smi_enable && f->smi_command && f->enable && grant_add(f->smi_command, 1, F_WRITE) == 0) P.smi_ok = 1;
    if ((f->flags & (1u << 10)) && f->reset.space == 1 && grant_add(f->reset.address, 1, F_WRITE) == 0) P.reset_ok = 1;
    P.hw = *hw; P.timeout_us = timeout;
    P.fp.table = *f;
    if (!P.smi_ok) { P.fp.table.smi_command = 0; P.fp.table.enable = 0; }  /* no SMI authority: enable cannot write it */
    P.fp.ops.context = 0; P.fp.ops.validate = op_validate; P.fp.ops.read = op_read; P.fp.ops.write = op_write;
    P.fp.ops.now_us = op_now; P.fp.ops.relax = op_relax;
    P.fp.owner = K64_POWER_OWNER; P.fp.timeout_us = timeout;
    P.generation = P.fp.generation = ++P.next_generation;
    P.open = 1;
    r = acpi_mode(&yes);
    if (!r && !yes) r = shz_fixed_enable(&P.fp);              /* SHZ_UNSUPPORTED unless the SMI grant exists */
    if (r) { P.open = 0; P.generation = 0; P.ledger_n = 0; return leave(r); }
    return leave(SHZ_DRIVER_OK);
}

int k64_laptop_power_poll(uint16_t *events) {
    int r = enter(); if (r) return r;
    if (!events) return leave(SHZ_INVALID);
    return leave(shz_fixed_events(&P.fp, events));
}
int k64_laptop_power_ack(uint16_t events) {
    int r = enter(); if (r) return r;
    return leave(shz_fixed_ack(&P.fp, events));
}
int k64_laptop_power_arm_button(void) {
    uint32_t cur, now; int r = enter(); if (r) return r;
    r = shz_reg_read(&P.fp.ops, P.fp.owner, P.fp.generation, &P.fp.table.event_a, 4, &cur);
    if (r) return leave(r);
    if (P.fp.table.event_a.access && P.fp.table.event_a.access != 3) return leave(SHZ_UNSUPPORTED);
    r = shz_reg_write(&P.fp.ops, P.fp.owner, P.fp.generation, &P.fp.table.event_a, 4,
                      (cur & 0xffff0000u) | ((uint32_t)K64_POWER_BUTTON << 16));
    if (r) return leave(r);
    r = shz_reg_read(&P.fp.ops, P.fp.owner, P.fp.generation, &P.fp.table.event_a, 4, &now);
    if (r) return leave(r);
    return leave((now & ((uint32_t)K64_POWER_BUTTON << 16)) ? SHZ_DRIVER_OK : SHZ_IO);
}
int k64_laptop_power_button_pressed(int *pressed) {
    uint16_t ev; int r;
    if (!pressed) return SHZ_INVALID;
    *pressed = 0;
    r = k64_laptop_power_poll(&ev); if (r) return r;
    if (!(ev & K64_POWER_BUTTON)) return SHZ_DRIVER_OK;
    r = k64_laptop_power_ack(K64_POWER_BUTTON); if (r) return r;
    *pressed = 1; return SHZ_DRIVER_OK;
}
int k64_laptop_power_reset(void) {
    struct shz_budget b; int r = enter(); if (r) return r;
    if (!P.reset_ok) return leave(SHZ_UNSUPPORTED);
    r = shz_fixed_reset(&P.fp);
    if (r) return leave(r);
    shz_budget_start(&b, P.fp.ops.now_us(P.fp.ops.context), P.timeout_us);
    for (;;) {                                                /* a working reset never gets here */
        r = shz_budget_poll(&b, P.fp.ops.now_us(P.fp.ops.context));
        if (r) return leave(r == SHZ_TIMEOUT ? SHZ_TIMEOUT : r);
        P.fp.ops.relax(P.fp.ops.context);
    }
}
int k64_laptop_power_close(void) {
    int r = enter(); if (r) return r;
    P.open = 0; P.generation = 0; P.ledger_n = 0;             /* later callers/stale owners fail validation */
    return leave(SHZ_DRIVER_OK);
}
uint64_t k64_laptop_power_generation(void) { return P.open ? P.generation : 0; }

#ifndef K64_LAPTOP_POWER_HOST
#include "pci.h"
#include "blk.h"
#include "laptop_firmware.h"
#ifdef SHZ_STANDALONE
static uint32_t nat_in(void *c, uint16_t p, unsigned n) {
    (void)c; return n == 1 ? k_inb(p) : (n == 2 ? k_inw(p) : k_inl(p));
}
static void nat_out(void *c, uint16_t p, unsigned n, uint32_t v) {
    (void)c; if (n == 1) k_outb(p, (uint8_t)v); else if (n == 2) k_outw(p, (uint16_t)v); else k_outl(p, v);
}
static uint64_t nat_now(void *c) {
    uint32_t lo, hi; uint64_t tsc, per = blk_tsc_per_ms(); (void)c;
    if (!per) return 0;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    tsc = ((uint64_t)hi << 32) | lo;
    return (tsc / per) * 1000u + ((tsc % per) * 1000u) / per;
}
static void nat_relax(void *c) { (void)c; __asm__ volatile("pause"); }
int k64_laptop_power_init(const struct k64_laptop_power_policy *policy) {
    static const struct k64_power_hw hw = { 0, nat_in, nat_out, nat_now, nat_relax };
    const struct shz_laptop_firmware *fw = k64_laptop_firmware_snapshot();
    if (!fw) return SHZ_NOT_FOUND;
    return k64_laptop_power_open_hw(fw, policy, &hw);
}
#else
int k64_laptop_power_init(const struct k64_laptop_power_policy *policy) {
    (void)policy; return SHZ_UNSUPPORTED;                     /* Supervisor profile traps port I/O */
}
#endif
#endif
