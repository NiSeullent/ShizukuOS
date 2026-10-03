/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef K64_LAPTOP_POWER_H
#define K64_LAPTOP_POWER_H
/*
 * Native ACPI fixed-hardware power provider (PM1 events, power button, FADT reset).
 *
 * Scope: only what the FADT fixed-feature block describes and shz_fixed_* already implements. No AML, no EC,
 * no \_S5 sleep type, no UEFI runtime reset, no HW-reduced ACPI, no MMIO register blocks (no mapping owner).
 *
 * Authority: FADT addresses in the firmware snapshot are NOT a register grant. open() builds a private grant
 * ledger from the FADT only when the caller's policy explicitly allows fixed register I/O, only for I/O-port
 * registers, minus ports other kernel drivers own (PIC/PIT/i8042/CMOS/COM1/PCI config data). The ledger is a
 * kernel-local decision of the standalone profile; it is not Core/PMA authority and the Supervisor profile
 * (which traps port I/O) is refused. Every register access is revalidated against owner + generation before
 * and after the access (shz_reg_read/write), serialized by a single busy flag, and bounded by a monotonic clock.
 */
#include "../../drivers/shz_laptop/firmware.h"

#define K64_POWER_OWNER 0x4b36342d50575231ull   /* "K64-PWR1": fixed kernel-internal owner id */
#define K64_POWER_BUTTON 0x0100u                /* PM1 PWRBTN_STS / PWRBTN_EN bit 8 */

struct k64_laptop_power_policy {
    uint32_t allow_fixed_io;     /* must be 1: caller decided the kernel owns the PM1/reset ports */
    uint32_t allow_smi_enable;   /* 1: may write FADT SMI_CMD/ACPI_ENABLE when SCI_EN is clear */
    uint32_t timeout_us;         /* 1..30000000; 0 selects 100000 */
};
/* Hardware backend: port I/O (bytes 1/2/4) and a monotonic microsecond clock. */
struct k64_power_hw {
    void *context;
    uint32_t (*in)(void *, uint16_t port, unsigned bytes);
    void (*out)(void *, uint16_t port, unsigned bytes, uint32_t value);
    uint64_t (*now_us)(void *);
    void (*relax)(void *);
};

/* Explicit-backend open (host control and any future non-default owner). Refuses without a grant policy. */
int k64_laptop_power_open_hw(const struct shz_laptop_firmware *fw, const struct k64_laptop_power_policy *policy,
                             const struct k64_power_hw *hw);
/* Production open: uses k64_laptop_firmware_snapshot() and native port I/O. SHZ_UNSUPPORTED outside the
 * standalone profile or when no snapshot exists. */
int k64_laptop_power_init(const struct k64_laptop_power_policy *policy);
/* Enabled-and-active PM1 fixed events (status & enable). Does not clear them. */
int k64_laptop_power_poll(uint16_t *events);
int k64_laptop_power_ack(uint16_t events);
/* Sets PWRBTN_EN (status half written as zero, W1C untouched) and verifies the readback. */
int k64_laptop_power_arm_button(void);
/* 1 and acknowledged when a power-button press is latched; 0 otherwise. */
int k64_laptop_power_button_pressed(int *pressed);
/* FADT RESET_REG write. Returns SHZ_UNSUPPORTED if the FADT does not advertise it, SHZ_TIMEOUT if the platform
 * is still running after the bounded wait, SHZ_DRIVER_OK is never returned after a successful reset. */
int k64_laptop_power_reset(void);
int k64_laptop_power_close(void);
uint64_t k64_laptop_power_generation(void);
#endif
