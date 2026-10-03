/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 laptop/USB pointer input: xHCI USB HID interrupt-IN pointing devices (and the explicit state of the PS/2 and I2C
 * touchpad paths) feeding the existing gin input routing. Standalone profile only (the Supervisor passes no PCI devices).
 *
 * Authority: the thread is a Kernel64-internal trusted driver. It never accepts caller identity: the pointer-adapter owner
 * is the fixed kernel instance id below and the generation is bumped for every successful device open, so reports of a
 * replaced/unplugged device cannot be published (the sink validate callback compares both).
 */
#ifndef K64_LAPTOP_INPUT_NATIVE_H
#define K64_LAPTOP_INPUT_NATIVE_H
#include "k64.h"

#define K64_LIN_OWNER UINT64_C(0x4b36344c494e0001)   /* "K64LIN" + instance 1 */
enum k64_lin_state {
    K64_LIN_IDLE = 0, K64_LIN_SCANNING, K64_LIN_NO_CONTROLLER, K64_LIN_NO_DEVICE, K64_LIN_STREAMING, K64_LIN_FAILED
};
struct k64_lin_status {
    uint32_t state, reports, refused, opens, polls;
    int32_t last_error;
    uint8_t bus, dev, fn, have_controller;
    /* Truthful refusals for the paths that are not active (see laptop_input_native.c). */
    const char *ps2_touchpad, *i2c_touchpad;
    uint32_t ps2_state, ps2_reports, ps2_refused;     /* ps2_state: 0 not probed, 1 absolute route, 2 standard mouse, 3 failed/revoked */
};
/* gin_init: starts the "laptopin" thread (non-blocking). */
void k64_laptop_input_init(void);
void k64_laptop_input_status(struct k64_lin_status *out);
/* PS/2 Synaptics absolute route. The i8042 owner (gfx_input.c gin_ps2_touchpad_probe; its call site belongs to the core integrator)
 * supplies the aux transport; timeouts are elapsed microseconds, return 0 = ok, nonzero = timeout/failure.
 * k64_laptop_ps2_open: 0 = Synaptics absolute mode active and the route owns aux bytes; 1 = standard PS/2 device (route NOT taken,
 * caller keeps the relative path and must resend F6); negative = SHZ_* error, the device is in an unknown mode (caller: FF reset).
 * k64_laptop_ps2_feed: one aux byte (gfx_lock held); returns 1 only when the route consumed it, so the standard decoder never also
 * sees it. Reports go adapter -> gin_pointer_inject_locked with owner+generation revalidated on every frame. */
struct k64_lin_ps2_transport {
    void *context;
    int (*write_aux)(void *, uint8_t byte, uint32_t timeout_us);
    int (*read_aux)(void *, uint8_t *byte, uint32_t timeout_us);
    int (*drain)(void *, uint32_t timeout_us);
};
int k64_laptop_ps2_open(const struct k64_lin_ps2_transport *t);
int k64_laptop_ps2_feed(uint8_t byte);
void k64_laptop_ps2_revoke(void);
int gin_ps2_touchpad_probe(void);
/* gfx_input.c: relative pointer motion + MK button bits 0..2 (L,R,M) into the system input state; takes gfx_lock. */
int gin_pointer_inject(int32_t dx, int32_t dy, uint8_t buttons);
int gin_pointer_inject_locked(int32_t dx, int32_t dy, uint8_t buttons);   /* caller holds gfx_lock */
#endif
