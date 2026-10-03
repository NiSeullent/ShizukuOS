/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit owned-machine input provider for the installed-Win98 domain.
 * Source: the actual outer (Q35/QEMU-emulated) i8042 at fixed ports 0x60/0x64,
 * polled from the Supervisor scheduler (dev_poll) with outer IRQ1/IRQ12
 * generation disabled. Raw outer set-2 key sequences and standard 3-byte
 * mouse packets go to the inner simulated KBC (devices.c), which owns guest
 * scan-set/translation state and raises the inner PIC IRQ1/IRQ12. Outer
 * ACK/BAT/ID/resend bytes are consumed here and never forwarded.
 * No provider exists unless W98INPT.BIN was admitted against the live gate.
 */
#ifndef SHZ_WIN98_NATIVE_INPUT_H
#define SHZ_WIN98_NATIVE_INPUT_H
#include <stdint.h>
#include "input_policy.h"
#define W98_I8042_DATA 0x60u
#define W98_I8042_STATUS 0x64u
#define W98_I8042_POLL_BYTES 32u   /* per dev_poll */
#define W98_I8042_FLUSH_BYTES 64u  /* stale bytes discarded at init */
#define W98_I8042_BAD_RUN 4u       /* consecutive misframed bytes before F4 resync */
#define W98_I8042_RESYNC_SKIP 8u   /* stale aux bytes skipped while waiting for the ACK */
#define W98_I8042_BAT_HOLD_MS 10u  /* a held 0xAA waits this long for the BAT's 0x00 before it is data */
#define W98_I8042_RESYNC_TRIES 3u  /* F4 re-issues (each waits STEP_MS for the ACK) before the stream is disabled */
#define W98_I8042_STEP_MS 50u      /* each command/response */
#define W98_I8042_RESET_MS 750u    /* mouse BAT */
#define W98_I8042_SPIN_MAX 2000000u /* frozen-clock bound per wait */
/* shz_info_t.native_input[8]; all zero when no opt-in was present. */
#define W98_INPUT_STATUS_MAGIC 0x31504e49u /* INP1 */
enum {
    W98_INPUT_STATE_ABSENT=0, W98_INPUT_STATE_ATTACHED=1, W98_INPUT_STATE_DETACHED=2,
    W98_INPUT_STATE_REVOKED=3, W98_INPUT_STATE_INIT_FAILED=4, W98_INPUT_STATE_REFUSED=5
};
/* w0 magic; w1 state | policy flags<<8 | outer config<<16 | ready<<24;
 * w2 domain generation; w3 key events accepted; w4 mouse packets accepted;
 * w5 dropped (queue full/overflow/refused/inner unsupported);
 * w1 bits 25..31 = mouse stream resyncs (saturating at 127);
 * w6 parity|timeout (lo16) | malformed (hi16); w7 outer responses (lo16) | last init error (hi16). */
typedef struct {
    void *opaque;
    uint8_t (*in)(void *,uint16_t);
    void (*out)(void *,uint16_t,uint8_t);
    uint64_t (*now)(void *);
} w98_i8042_io_t;
typedef struct {
    w98_i8042_io_t io;
    void *owner; /* devices.c keyboard/pointer provider context */
    uint64_t hz;
    uint32_t flags, ready;
    uint8_t outer_config, key_len, aux_len, bat_pending, bad_run;
    uint8_t ack_wait, tries, kbd_reinit, orig_config, quiesce_ok, orig_valid;
    uint8_t key[8], aux[3];
    uint64_t hold_start, ack_start;
    uint32_t key_events, mouse_packets, dropped, parity_timeout, malformed, responses, last_error, resyncs, resync_failed;
    uint32_t kbd_resets, kbd_reinit_failed;
} w98_i8042_t;
typedef struct { const void *domain; uint64_t vmcs; uint32_t generation, owner_cpu; } w98_input_binding_t;
/* Copies exactly 96 bytes and checks them against the admitted device-gate
 * snapshot words (16..23 nonce, 24..31 VGA config SHA-256). 0 or -1. */
int w98_input_policy_admit(const void *blob,uint64_t bytes,const uint32_t gate_words[40],w98_input_policy_t *out);
/* 0 only for the same non-null domain/generation/VMCS/CPU and a live runnable domain. */
int w98_input_binding_current(const w98_input_binding_t *expected,const w98_input_binding_t *live,int live_runnable);
/* Bounded known-state setup: outer IRQs+translation off, keyboard set 2 + F4,
 * mouse reset/ID0/F4. Failure quiesces the outer ports. 0 or -1. */
int w98_i8042_init(w98_i8042_t *,const w98_i8042_io_t *,void *owner,uint64_t hz,uint32_t flags);
/* Reads at most W98_I8042_POLL_BYTES; returns bytes read or -1 when not ready. */
int w98_i8042_poll(w98_i8042_t *);
/* Disables both outer ports, drains the outer output buffer and reads the config back (all bounded);
 * the provider is unusable afterwards. The outer config saved at init (orig_config) is deliberately
 * NOT restored: re-enabling the clocks/IRQ1/IRQ12 would reopen an input path no owner handles. */
void w98_i8042_quiesce(w98_i8042_t *);
void w98_input_status_words(const w98_i8042_t *,uint32_t state,uint32_t generation,uint32_t extra_dropped,uint32_t out[8]);
#endif
