/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the production kernel64/audio.c service (compiled unmodified, not a copy): modelled AC97 descriptor
 * engine (CIV/LVI/DCH semantics from the QEMU ac97.c reference), real stream/ownership/PCM/queue/completion logic.
 * This proves source-level behavior only; it is NOT evidence of audible sound or of a ShizukuOS guest run.
 *   gcc -O1 -Wall -Wextra -I.. -I../.. -DAUDIO_HOST test_audio.c ../audio.c -o out && out
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../proc_internal.h"
#include "../audio.h"
#include "../../abi/shz_audio.h"

static int fails, checks;
#define CHECK(c) do { ++checks; if (!(c)) { ++fails; printf("FAIL line %d: %s\n", __LINE__, #c); } } while (0)

/* ---- kernel service shims used by audio.c ---- */
void kpanic(const char *f, ...) { (void)f; printf("kpanic\n"); exit(2); }
void ob_ref(kobject_t *o) { ++o->refs; }
void ob_deref(kobject_t *o) { --o->refs; }
void mutex_lock(kmutex_t *m) { if (m->locked) { printf("mutex recursion\n"); exit(2); } m->locked = 1; }
void mutex_unlock(kmutex_t *m) { m->locked = 0; }
static uint64_t g_out_len, g_ret;
int64_t stack_arg(process_t *p, struct regs *r, unsigned n) { (void)p; (void)r; return (int64_t)(n == 5 ? g_out_len : g_ret); }
int copy_from_user(process_t *p, void *d, uint64_t u, uint64_t n) { (void)p; if (u < 0x10000 || u == 0xdead0000u) return -1; memcpy(d, (void *)(uintptr_t)u, n); return 0; }
int copy_to_user(process_t *p, uint64_t u, const void *s, uint64_t n) { (void)p; if (u < 0x10000 || u == 0xdead0000u) return -1; memcpy((void *)(uintptr_t)u, s, n); return 0; }

/* ---- modelled descriptor engine ---- */
static int start_fail, fin, hw_present, stop_fail, stop_calls, start_calls, ring_overrun;
static uint8_t pages[AUDIO_RING_SLOTS][AUDIO_SLOT_BYTES];
static uint32_t bd_samples[AUDIO_RING_SLOTS];
static unsigned civ, lvi, dch = 1, run, consumed_total;
static int m_probe(audio_hw_info *i) { if (!hw_present) return -1; i->vendor = 0x8086; i->device = 0x2415; i->irq_line = 0xffffffffu; return 0; }
static uint8_t *m_cpu(unsigned s) { return pages[s]; }
static void m_prog(unsigned s, uint32_t n) { bd_samples[s] = n; }
static int m_irq_attach(void) { return -1; }
static void m_irq_detach(void) {}
static int m_start(unsigned l) { ++start_calls; if (start_fail) { run = 1; dch = 0; return -1; } fin = 0; civ = 0; lvi = l; dch = 0; run = 1; return 0; }
static int m_extend(unsigned l) { lvi = l; if (dch && run) { civ = (civ + 1) % 32; dch = 0; fin = 0; } return 0; }
static void m_pos(audio_hw_pos *p) { p->sr = dch ? (fin ? 3 : 1) : 0; p->civ = civ; p->picb = fin ? 0 : bd_samples[civ]; }
static int m_pause(int p) { if (p) { run = 0; dch = 1; } else { run = 1; dch = 0; } return 0; }
static int m_stop(void) { ++stop_calls; if (stop_fail) return -1; run = 0; dch = 1; civ = lvi = 0; fin = 0; return 0; }
static uint32_t m_irqc(void) { return 0; }
static const audio_backend model = { m_probe, m_cpu, m_prog, m_irq_attach, m_irq_detach, m_start, m_extend, m_pos, m_pause, m_stop, m_irqc };
const audio_backend *audio_backend_get(void) { return hw_present ? &model : 0; }
/* hardware consumes the current descriptor */
static void hw_consume(void) { if (dch || !run) return; ++consumed_total; if (civ == lvi) { dch = 1; fin = 1; } else civ = (civ + 1) % 32; }

int32_t sys_ext_audio(process_t *, struct regs *, uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
void audio_process_teardown(process_t *);

static int32_t snd(process_t *p, uint32_t op, void *in, uint32_t il, void *out, uint32_t ol, uint32_t *ret)
{
    g_out_len = ol; g_ret = (uint64_t)(uintptr_t)ret;
    return sys_ext_audio(p, 0, SYS_NtShzSound, op, (uint64_t)(uintptr_t)in, il, (uint64_t)(uintptr_t)out);
}
static process_t *mkproc(int pid, uint64_t tick)
{
    process_t *p = calloc(1, sizeof *p);
    p->used = 1; p->pid = pid; p->create_tick = tick; p->object = calloc(1, sizeof(kobject_t)); p->object->refs = 1;
    return p;
}
static uint64_t do_open(process_t *p, uint32_t ch, uint32_t bits, uint32_t rate, int32_t *st)
{
    shz_snd_open_in in = { sizeof in, ch, bits, rate, 0xffff, 0xffff, 0 };
    shz_snd_open_out out;
    memset(&out, 0, sizeof out);
    *st = snd(p, SHZ_SND_OP_OPEN, &in, sizeof in, &out, sizeof out, 0);
    return out.handle;
}
static int32_t do_write(process_t *p, uint64_t h, const void *data, uint32_t len, uint64_t cookie, shz_snd_write_out *wo)
{
    shz_snd_write_in in = { sizeof in, 0, h, (uint64_t)(uintptr_t)data, len, 0, cookie };
    memset(wo, 0, sizeof *wo);
    return snd(p, SHZ_SND_OP_WRITE, &in, sizeof in, wo, sizeof *wo, 0);
}
static int32_t do_status(process_t *p, uint64_t h, shz_snd_status *s)
{
    shz_snd_handle_in in = { sizeof in, 0, h };
    memset(s, 0, sizeof *s);
    return snd(p, SHZ_SND_OP_STATUS, &in, sizeof in, s, sizeof *s, 0);
}
static int32_t do_simple(process_t *p, uint32_t op, uint64_t h)
{
    shz_snd_handle_in in = { sizeof in, 0, h };
    return snd(p, op, &in, sizeof in, 0, 0, 0);
}

int main(void)
{
    process_t *a = mkproc(10, 100), *b = mkproc(11, 101);
    static int16_t pcm[16384 * 2];
    static uint8_t u8[441];
    shz_snd_caps caps;
    shz_snd_write_out wo;
    shz_snd_status s;
    uint32_t i, ret = 0;
    int32_t st;
    uint64_t h;

    /* 1: no device never claims one */
    memset(&caps, 0xee, sizeof caps);
    st = snd(a, SHZ_SND_OP_QUERY, 0, 0, &caps, sizeof caps, &ret);
    CHECK(st == STATUS_DEVICE_NOT_READY && caps.present == 0 && caps.backend == SHZ_SND_BACKEND_NONE && ret == sizeof caps);
    do_open(a, 2, 16, 48000, &st); CHECK(st == STATUS_DEVICE_NOT_READY);
    CHECK(do_simple(a, SHZ_SND_OP_CLOSE, 1) == STATUS_DEVICE_NOT_READY);

    hw_present = 1;
    st = snd(a, SHZ_SND_OP_QUERY, 0, 0, &caps, sizeof caps, &ret);
    CHECK(st == STATUS_SUCCESS && caps.present == 1 && caps.hw_rate == 48000 && caps.ring_slots == 32);
    CHECK(snd(a, 99, 0, 0, 0, 0, 0) == STATUS_INVALID_PARAMETER);

    /* 2: ownership, exclusivity, bad parameters */
    { uint32_t bad; shz_snd_open_in in = { sizeof in, 3, 16, 48000, 0xffff, 0xffff, 0 }; (void)bad;
      CHECK(snd(a, SHZ_SND_OP_OPEN, &in, sizeof in, &caps, sizeof caps, 0) == STATUS_INVALID_PARAMETER);
      in.channels = 2; in.rate = 32000; CHECK(snd(a, SHZ_SND_OP_OPEN, &in, sizeof in, &caps, sizeof caps, 0) == STATUS_INVALID_PARAMETER); }
    { shz_snd_open_in in = { sizeof in, 2, 16, 48000, 0xffff, 0xffff, 0 };   /* output copy fault must undo the stream */
      CHECK(snd(a, SHZ_SND_OP_OPEN, &in, sizeof in, (void *)0xdead0000u, sizeof(shz_snd_open_out), 0) == STATUS_ACCESS_VIOLATION); }
    CHECK(a->object->refs == 1);
    h = do_open(a, 2, 16, 48000, &st); CHECK(st == STATUS_SUCCESS && h);
    CHECK(a->object->refs == 2);
    do_open(b, 2, 16, 48000, &st); CHECK(st == STATUS_DEVICE_BUSY);
    CHECK(do_write(b, h, pcm, 4, 1, &wo) == STATUS_INVALID_HANDLE);
    CHECK(do_status(b, h, &s) == STATUS_INVALID_HANDLE);
    CHECK(do_write(a, h + 0x100, pcm, 4, 1, &wo) == STATUS_INVALID_HANDLE);
    CHECK(do_write(a, h, pcm, 3, 1, &wo) == STATUS_INVALID_PARAMETER);      /* not whole frames */

    /* 3: completion only after DMA consumption; data bytes arrive intact */
    for (i = 0; i < 2048 * 2; ++i) pcm[i] = (int16_t)(i * 7 + 1);
    st = do_write(a, h, pcm, 8192, 77, &wo);
    CHECK(st == STATUS_SUCCESS && wo.accepted_bytes == 8192 && !wo.flags);
    CHECK(memcmp(pages[0], pcm, 4096) == 0 && memcmp(pages[1], (uint8_t *)pcm + 4096, 4096) == 0);
    CHECK(bd_samples[0] == 2048 && bd_samples[1] == 2048 && run && lvi == 1 && start_calls == 1);
    do_status(a, h, &s); CHECK(s.cookie_count == 0 && s.queued_slots == 2 && s.played_bytes == 0 && s.submitted_bytes == 8192);
    hw_consume(); do_status(a, h, &s); CHECK(s.cookie_count == 0 && s.queued_slots == 1 && s.played_bytes == 4096);
    hw_consume(); do_status(a, h, &s);
    CHECK(s.cookie_count == 1 && s.cookies[0].cookie == 77 && !s.cookies[0].flags && s.played_bytes == 8192 && s.queued_slots == 0);
    do_status(a, h, &s); CHECK(s.flags & SHZ_SND_STF_UNDERRUN);

    /* 4: resume after the engine halted at LVI, and 8-bit mono 11025 -> 48k stereo conversion */
    for (i = 0; i < 441; ++i) u8[i] = (uint8_t)(i & 1 ? 255 : 0);
    CHECK(do_open(a, 2, 16, 48000, &st) == 0 && st == STATUS_DEVICE_BUSY);
    CHECK(do_simple(a, SHZ_SND_OP_CLOSE, h) == STATUS_SUCCESS && a->object->refs == 1);
    h = do_open(a, 1, 8, 11025, &st); CHECK(st == STATUS_SUCCESS);
    st = do_write(a, h, u8, 441, 5, &wo);
    CHECK(st == STATUS_SUCCESS && wo.accepted_bytes == 441);
    do_status(a, h, &s); CHECK(s.submitted_bytes == 1920u * 4u);                 /* 441 * 48000 / 11025 = 1920 frames */
    { int16_t *o = (int16_t *)pages[0]; CHECK(o[0] == -32768 && o[1] == -32768); CHECK(o[2 * 4] == 32512 || o[2 * 5] == 32512); }
    hw_consume(); do_status(a, h, &s); CHECK(s.cookie_count == 0);
    hw_consume(); do_status(a, h, &s); CHECK(s.cookie_count == 1);
    st = do_write(a, h, u8, 441, 6, &wo);                                        /* engine halted: extend resumes at CIV+1 */
    CHECK(st == STATUS_SUCCESS && civ == 2 && lvi == 3 && !dch);
    hw_consume(); hw_consume(); do_status(a, h, &s); CHECK(s.cookie_count == 1 && s.cookies[0].cookie == 6);

    /* 5: truthful queue admission */
    for (i = 0; i < 16384 * 2; ++i) pcm[i] = 0x1111;
    CHECK(do_simple(a, SHZ_SND_OP_CLOSE, h) == STATUS_SUCCESS);
    h = do_open(a, 2, 16, 48000, &st);
    st = do_write(a, h, pcm, 65536, 1, &wo); CHECK(st == STATUS_SUCCESS && wo.accepted_bytes == 65536 && wo.free_slots == 15);
    st = do_write(a, h, pcm, 65536, 2, &wo);
    CHECK(st == STATUS_SUCCESS && wo.accepted_bytes == 15 * 4096 && (wo.flags & SHZ_SND_WRITEF_QUEUE_FULL) && wo.free_slots == 0);
    st = do_write(a, h, pcm, 4, 3, &wo); CHECK(st == STATUS_DEVICE_BUSY && wo.accepted_bytes == 0);
    do_status(a, h, &s); CHECK(s.queued_slots == 31 && s.free_slots == 0);
    for (i = 0; i < 16; ++i) hw_consume();
    do_status(a, h, &s); CHECK(s.cookie_count == 1 && s.cookies[0].cookie == 1 && s.queued_slots == 15);   /* wrap counted */
    st = do_write(a, h, pcm, 4096 * 3, 9, &wo); CHECK(st == STATUS_SUCCESS && wo.accepted_bytes == 12288);
    CHECK(lvi == 1);                                                   /* slots 31,0,1 */
    /* user fault leaves the queue untouched */
    do_status(a, h, &s); { uint32_t q = s.queued_slots; CHECK(do_write(a, h, (void *)0xdead0000u, 64, 4, &wo) == STATUS_ACCESS_VIOLATION); do_status(a, h, &s); CHECK(s.queued_slots == q); }

    /* 6: pause gates DMA, reset aborts outstanding cookies */
    { shz_snd_pause_in p = { sizeof p, 1, h }; CHECK(snd(a, SHZ_SND_OP_PAUSE, &p, sizeof p, 0, 0, 0) == STATUS_SUCCESS && !run);
      hw_consume(); do_status(a, h, &s); CHECK(s.flags & SHZ_SND_STF_PAUSED);
      p.pause = 0; CHECK(snd(a, SHZ_SND_OP_PAUSE, &p, sizeof p, 0, 0, 0) == STATUS_SUCCESS && run); }
    CHECK(do_simple(a, SHZ_SND_OP_RESET, h) == STATUS_SUCCESS);
    do_status(a, h, &s);
    { int ab = 0; uint32_t k; for (k = 0; k < s.cookie_count; ++k) ab += s.cookies[k].flags == SHZ_SND_COOKIEF_ABORTED; CHECK(ab >= 1); }
    CHECK(s.queued_slots == 0 && s.free_slots == 31);

    /* 7: process exit stops DMA before the owner is reused; no pinned leak */
    st = do_write(a, h, pcm, 4096, 11, &wo); CHECK(st == STATUS_SUCCESS && run);
    { int before = stop_calls; audio_process_teardown(b); CHECK(stop_calls == before); audio_process_teardown(a); CHECK(stop_calls == before + 1 && !run); }
    CHECK(a->object->refs == 1);
    CHECK(do_write(a, h, pcm, 4, 1, &wo) == STATUS_INVALID_HANDLE);
    { process_t *a2 = mkproc(10, 555);                                          /* slot/pid reuse with a new lifetime */
      CHECK(do_write(a2, h, pcm, 4, 1, &wo) == STATUS_INVALID_HANDLE);
      h = do_open(a2, 2, 16, 44100, &st); CHECK(st == STATUS_SUCCESS);
      a2->teardown = 1; CHECK(do_write(a2, h, pcm, 4, 1, &wo) == STATUS_PROCESS_IS_TERMINATING);
      audio_process_teardown(a2); CHECK(a2->object->refs == 1); }

    /* 7b: failed start is stopped/proven before reuse; STATUS short/copy-fault retry keeps cookies */
    { process_t *d = mkproc(13, 700); shz_snd_status s2; shz_snd_pause_in pz = { sizeof pz, 1, 0 };
      uint32_t ret2 = 0; shz_snd_handle_in hin;
      h = do_open(d, 2, 16, 48000, &st); CHECK(st == STATUS_SUCCESS);
      start_fail = 1; { int before = stop_calls; st = do_write(d, h, pcm, 4096, 21, &wo);
        CHECK(st == STATUS_UNSUCCESSFUL && stop_calls == before + 1 && !run); }
      start_fail = 0;
      CHECK(do_simple(d, SHZ_SND_OP_CLOSE, h) == STATUS_SUCCESS);
      h = do_open(d, 2, 16, 48000, &st); CHECK(st == STATUS_SUCCESS);     /* stop proven: device not quarantined */
      do_write(d, h, pcm, 4096, 22, &wo); do_write(d, h, pcm, 4096, 23, &wo);
      /* partial: paused mid-buffer is DCH without CELV/PICB==0, so not consumed */
      pz.handle = h; snd(d, SHZ_SND_OP_PAUSE, &pz, sizeof pz, 0, 0, 0);
      do_status(d, h, &s2); CHECK(s2.cookie_count == 0 && s2.queued_slots == 2);
      pz.pause = 0; snd(d, SHZ_SND_OP_PAUSE, &pz, sizeof pz, 0, 0, 0);
      hw_consume(); hw_consume();                                          /* EOF: DCH+CELV+PICB 0 */
      hin.size = sizeof hin; hin.reserved = 0; hin.handle = h;
      /* short buffer, then retlength copy fault: cookies stay queued */
      CHECK(snd(d, SHZ_SND_OP_STATUS, &hin, sizeof hin, &s2, 8, &ret2) == STATUS_BUFFER_TOO_SMALL);
      CHECK(snd(d, SHZ_SND_OP_STATUS, &hin, sizeof hin, &s2, sizeof s2, (uint32_t *)0xdead0000u) == STATUS_ACCESS_VIOLATION);
      CHECK(snd(d, SHZ_SND_OP_STATUS, &hin, sizeof hin, (void *)0xdead0000u, sizeof s2, &ret2) == STATUS_ACCESS_VIOLATION);
      do_status(d, h, &s2); CHECK(s2.cookie_count == 2 && s2.cookies[0].cookie == 22 && s2.cookies[1].cookie == 23 && s2.queued_slots == 0);
      /* EOF then restart: new write resumes at the next ring position */
      CHECK(do_write(d, h, pcm, 4096, 24, &wo) == STATUS_SUCCESS && run);
      hw_consume(); do_status(d, h, &s2); CHECK(s2.cookie_count == 1 && s2.cookies[0].cookie == 24);
      CHECK(do_simple(d, SHZ_SND_OP_CLOSE, h) == STATUS_SUCCESS); }

    /* 8: a stop that cannot be proven quarantines the device */
    { process_t *c = mkproc(12, 600); h = do_open(c, 2, 16, 48000, &st); CHECK(st == STATUS_SUCCESS);
      do_write(c, h, pcm, 4096, 1, &wo); stop_fail = 1;
      CHECK(do_simple(c, SHZ_SND_OP_CLOSE, h) == STATUS_UNSUCCESSFUL);
      do_open(c, 2, 16, 48000, &st); CHECK(st == STATUS_DEVICE_NOT_READY);
      snd(c, SHZ_SND_OP_QUERY, 0, 0, &caps, sizeof caps, 0); CHECK(caps.flags & SHZ_SND_CAPF_FAULTED); }
    (void)ring_overrun;
    printf("audio host control: %d checks, %d failed\n", checks, fails);
    return fails != 0;
}
