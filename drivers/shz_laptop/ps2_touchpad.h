/* SPDX-License-Identifier: GPL-2.0-only -- independently authored protocols */
#ifndef SHZ_PS2_TOUCHPAD_H
#define SHZ_PS2_TOUCHPAD_H
#include "laptop.h"
/* i8042 auxiliary-port pointing devices: standard 3-byte PS/2 relative mouse
 * and Synaptics PS/2 TouchPad (identify/capability queries, absolute W mode,
 * 6-byte packets). Frames are published through the shared pointer adapter,
 * so the Win98 native pointer bridge and NTDRV consumers see one class path.
 *
 * The auxiliary transport is a TRUSTED provider owned by the real i8042
 * owner. write_aux sends one byte to the auxiliary device (D4 prefix is the
 * provider's job) and read_aux returns one auxiliary byte; both impose the
 * elapsed timeout themselves. drain discards pending auxiliary input. All
 * calls are serialized by the caller and must not run in IRQ context except
 * shz_ps2_feed, which performs no transport I/O.
 *
 * Not implemented (explicit errors, never guessed): RMI4/SMBus intertouch,
 * ALPS/Elantech/Focaltech protocols, pass-through (TrackPoint) packets,
 * multi-finger gestures, extended W/advanced-gesture packets and extra
 * buttons beyond left/right/middle. */
enum shz_ps2_kind { SHZ_PS2_NONE,SHZ_PS2_RELATIVE,SHZ_PS2_SYNAPTICS };
enum shz_ps2_state { SHZ_PS2_EMPTY,SHZ_PS2_STREAMING,SHZ_PS2_POISONED,SHZ_PS2_CLOSED };
struct shz_ps2_ops {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation);
    int (*write_aux)(void *,uint8_t byte,uint32_t timeout_us);
    int (*read_aux)(void *,uint8_t *byte,uint32_t timeout_us);
    int (*drain)(void *,uint32_t timeout_us);
};
struct shz_synaptics_info {
    uint32_t identity,capabilities,model,ext_cap,ext_cap_0c;
    uint8_t major,minor,x_res,y_res; /* res: units/mm, 0 when unreported */
    uint8_t w_mode,middle,clickpad,pass_through,extra_buttons;
};
struct shz_ps2_device {
    struct shz_ps2_ops ops;
    struct shz_synaptics_info info;
    uint64_t owner,generation;
    uint32_t timeout_us,resync;
    uint8_t packet[6],have,size,kind,state,touch_z;
    int last_error;
};
/* Synaptics special-command query results (pure decoders, exposed for tests
 * and for native owners that already collected status bytes). */
int shz_synaptics_decode_identity(const uint8_t status[3],uint32_t *identity,
                                  uint8_t *major,uint8_t *minor);
int shz_synaptics_decode_capabilities(const uint8_t status[3],uint32_t *caps);
/* Pure packet decoders; output unchanged on failure. */
int shz_ps2_decode_relative(const uint8_t packet[3],struct shz_pointer *);
int shz_synaptics_decode(const struct shz_synaptics_info *,uint8_t touch_z,
                         const uint8_t packet[6],struct shz_pointer *);
/* Probe disables streaming, identifies the device, selects Synaptics
 * absolute(+W) mode when present (major >= 4), otherwise relative PS/2,
 * then enables streaming. Any transport failure after the first command
 * poisons the device; only shz_ps2_close (FF reset) clears it. touch_z is
 * the contact pressure threshold (1..255) supplied by the caller. */
int shz_ps2_open(struct shz_ps2_device *,const struct shz_ps2_ops *,uint64_t owner,
                 uint64_t generation,uint32_t timeout_us,uint8_t touch_z);
/* Feed one received auxiliary byte. SHZ_NO_EVENT until a complete validated
 * frame; framing errors resynchronize and return SHZ_MALFORMED. */
int shz_ps2_feed(struct shz_ps2_device *,uint8_t byte,struct shz_pointer *out);
int shz_ps2_feed_adapter(struct shz_ps2_device *,struct shz_pointer_adapter *,uint8_t byte);
/* Sends FF reset (restores default relative mode for legacy drivers) and
 * requires AA 00. Failure retains the poisoned state. */
int shz_ps2_close(struct shz_ps2_device *);
#endif
