/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_DEVICE_GATE_H
#define SHZ_NATIVE_DEVICE_GATE_H
#include "native_device_epoch.h"
#include "../include/shz_info.h"
#include "../src/caps.h"
#define W98_GATE_POLICY_MAGIC 0x50454457u /* WDEP */
#define W98_GATE_POLICY_BYTES 256u
#define W98_GATE_POLICY_NAME "opt/shizuku/native-device-epoch"
#define W98_GATE_DIRECTORY_MAX 128u
#define W98_GATE_PORT_CALLS_MAX 32768u
#define W98_GATE_COM2 0x2f8u
#define W98_GATE_READY 4u /* wrapper-only48B WDE1/count0/nonce */
/* Canonical little-endian256B policy: magic0, version(u16)4=1, extent(u16)6,
 * role bits8 (VGA1/storage2), reserved12; nonce16, full config SHA48/80,
 * full ROM SHA112; host monotonic deadline(ns)144, gate budget(ms)152=10000,
 * COM2(u16)156, reserved158; BDF(u16)160/162, reserved164;
 * VGA BAR DWORDs168..191, storage BAR DWORDs192..215; zero216..255.
 * Host deadline is an outer ownership binding, NEVER a native TSC value.
 * Configs and raw BARs are expectations until the current owned host grant. */
typedef struct {
    void *opaque;
    int (*read)(void *,uint16_t,unsigned,uint32_t *);
    int (*write)(void *,uint16_t,unsigned,uint32_t);
    uint64_t (*now)(void *);
    void (*pause)(void *);
} w98_gate_port_io_t;
typedef struct {
    w98_epoch_gate_t protocol;
    w98_gate_port_io_t ports;
    uint64_t deadline,original_deadline,last_now,host_deadline_ns,hz;
    uint32_t attempted,port_calls;
    uint8_t admitted;
    shz_blob_t snapshots[3]; /* VGA config, ROM, persistence config */
    uint8_t config[2][192] __attribute__((aligned(8)));
    uint8_t rom[65536] __attribute__((aligned(4096)));
} w98_native_gate_t;
/* One immutable exclusive object for the Supervisor lifetime. Callback ports,
 * firmware/transport/clock and provenance are modeled in host controls. Only
 * root's future owned process/QMP/FD grant integration can admit real runtime. */
int w98_native_device_gate_with_io(w98_native_gate_t *,const shz_info_t *,
                                   const shz_caps_t *,const w98_gate_port_io_t *);
int w98_native_device_gate(const shz_info_t *,const shz_caps_t *);
/* Initializers consume retained Supervisor copies, never mutable original
 * loader buffers after grant. Returned only for an admitted selected blob. */
const shz_blob_t *w98_native_device_gate_blob(const char *);
/* Bounded generic SHA256 of0..65536B, used for complete config and ROM bytes. */
int w98_gate_sha256(const uint8_t *,uint64_t,uint8_t[32]);
/* Readonly actual production lifetime; rejects absent/storage-only admission.
 * Output is a40-word version1 guardian snapshot; no caller-supplied evidence. */
int w98_native_device_gate_gop_words(uint32_t[40]);
/* Pure extractor for modeled host controls; never itself admits hardware. */
int w98_native_gate_gop_words(const w98_native_gate_t *,uint32_t[40]);
#endif
