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
 * VGA BAR DWORDs168..191, storage BAR DWORDs192..215; input SHA216..247;
 * zero248..255. Input SHA = SHA-256 of the exact 96-byte W98INPT.BIN of THIS
 * attempt (explicit owned-machine input option, never a PCI role): nonzero iff
 * that blob is loaded, and only together with the VGA pair. Zero = no input.
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
    shz_blob_t snapshots[4]; /* VGA config, ROM, persistence config, W98INPT */
    uint8_t config[2][192] __attribute__((aligned(8)));
    uint8_t rom[65536] __attribute__((aligned(4096)));
    uint8_t input[96] __attribute__((aligned(8))); /* frozen policy-bound W98INPT.BIN */
    uint32_t refusal_stage; /* diagnostic only: first W98_GATE_REFUSED_* code, never authority */
} w98_native_gate_t;
/* Refusal stage codes (COM1 diagnostics only; carry no nonce/hash/blob bytes). */
#define W98_GATE_REFUSED_SHAPE 1u      /* blob shape/caps/loader-flag/io preflight */
#define W98_GATE_REFUSED_CLOCK 2u      /* TSC deadline overflow */
#define W98_GATE_REFUSED_FWCFG 3u      /* fw_cfg directory/policy read */
#define W98_GATE_REFUSED_INPUT_SHA 4u  /* W98INPT.BIN <-> policy input SHA */
#define W98_GATE_REFUSED_POLICY 5u     /* policy header/role field layout */
#define W98_GATE_REFUSED_VGA_BIND 6u   /* VGA config/ROM/BAR binding */
#define W98_GATE_REFUSED_STORAGE_BIND 7u /* persistence config/BAR binding */
#define W98_GATE_REFUSED_BIND_RECHECK 8u /* post-bind hash recheck or deadline */
#define W98_GATE_REFUSED_UART 9u       /* COM2 programming */
#define W98_GATE_REFUSED_READY 10u     /* READY send (deadline/budget/UART) */
#define W98_GATE_REFUSED_EPOCH_PRE 11u /* epoch preflight (no nonce consumed) */
#define W98_GATE_REFUSED_EPOCH_BUDGET 12u /* epoch exchange exhausted its I/O-call budget */
#define W98_GATE_REFUSED_EPOCH 13u     /* epoch exchange: deadline/frame/nonce/PCI snapshot */
#define W98_GATE_REFUSED_POST_GRANT 14u /* source/snapshot re-verify after grant */
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
/* Diagnostic-only read of the production lifetime's first refusal stage and
 * protocol/port call counts; returns 0 when nothing was refused. */
uint32_t w98_native_device_gate_refusal(uint32_t *epoch_io_calls,uint32_t *port_calls);
/* Pure extractor for modeled host controls; never itself admits hardware. */
int w98_native_gate_gop_words(const w98_native_gate_t *,uint32_t[40]);
#endif
