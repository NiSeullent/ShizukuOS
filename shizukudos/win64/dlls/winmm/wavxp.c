/* SPDX-License-Identifier: GPL-2.0-only
 * winmm -> Core audio transport; see wavxp.h. */
#include "wavxp.h"
#include <string.h>

NTSTATUS NTAPI NtShzSound(ULONG op, PVOID in, ULONG in_len, PVOID out, ULONG out_len, PULONG ret_len);

NTSTATUS xp_query(shz_snd_caps *caps)
{
    ULONG ret = 0;
    NTSTATUS st;
    memset(caps, 0, sizeof *caps);
    caps->size = sizeof *caps;
    st = NtShzSound(SHZ_SND_OP_QUERY, 0, 0, caps, sizeof *caps, &ret);
    if (NT_SUCCESS(st) && (ret < sizeof *caps || caps->size != sizeof *caps)) return STATUS_INFO_LENGTH_MISMATCH;
    return st;
}

int xp_present(shz_snd_caps *caps)
{
    NTSTATUS st = xp_query(caps);
    return NT_SUCCESS(st) && caps->present == 1 && caps->abi_version == SHZ_SND_ABI_VERSION;
}

NTSTATUS xp_open(unsigned ch, unsigned bits, unsigned rate, uint64_t *handle)
{
    shz_snd_open_in in;
    shz_snd_open_out out;
    ULONG ret = 0;
    NTSTATUS st;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.size = sizeof in; in.channels = ch; in.bits = bits; in.rate = rate;
    in.volume_left = in.volume_right = 0xffff;
    out.size = sizeof out;
    *handle = 0;
    st = NtShzSound(SHZ_SND_OP_OPEN, &in, sizeof in, &out, sizeof out, &ret);
    if (!NT_SUCCESS(st)) return st;
    if (ret < sizeof out || !out.handle) return STATUS_INFO_LENGTH_MISMATCH;
    *handle = out.handle;
    return st;
}

NTSTATUS xp_write(uint64_t h, const void *data, uint32_t len, uint64_t cookie, uint32_t *accepted, uint32_t *flags)
{
    shz_snd_write_in in;
    shz_snd_write_out out;
    ULONG ret = 0;
    NTSTATUS st;
    memset(&in, 0, sizeof in);
    memset(&out, 0, sizeof out);
    in.size = sizeof in; in.handle = h; in.data = (uint64_t)(ULONG_PTR)data; in.length = len; in.cookie = cookie;
    out.size = sizeof out;
    *accepted = 0; *flags = 0;
    st = NtShzSound(SHZ_SND_OP_WRITE, &in, sizeof in, &out, sizeof out, &ret);
    if (!NT_SUCCESS(st)) return st;
    if (ret < sizeof out || out.accepted_bytes > len) return STATUS_INFO_LENGTH_MISMATCH;
    *accepted = out.accepted_bytes; *flags = out.flags;
    return st;
}

NTSTATUS xp_status(uint64_t h, shz_snd_status *s)
{
    shz_snd_handle_in in;
    ULONG ret = 0;
    NTSTATUS st;
    memset(&in, 0, sizeof in);
    memset(s, 0, sizeof *s);
    in.size = sizeof in; in.handle = h;
    s->size = sizeof *s;
    st = NtShzSound(SHZ_SND_OP_STATUS, &in, sizeof in, s, sizeof *s, &ret);
    if (!NT_SUCCESS(st)) return st;
    if (ret < sizeof *s || s->cookie_count > SHZ_SND_MAX_COOKIES) return STATUS_INFO_LENGTH_MISMATCH;
    return st;
}

NTSTATUS xp_pause(uint64_t h, int pause)
{
    shz_snd_pause_in in;
    ULONG ret = 0;
    memset(&in, 0, sizeof in);
    in.size = sizeof in; in.handle = h; in.pause = pause ? 1 : 0;
    return NtShzSound(SHZ_SND_OP_PAUSE, &in, sizeof in, 0, 0, &ret);
}

static NTSTATUS handle_op(ULONG op, uint64_t h)
{
    shz_snd_handle_in in;
    ULONG ret = 0;
    memset(&in, 0, sizeof in);
    in.size = sizeof in; in.handle = h;
    return NtShzSound(op, &in, sizeof in, 0, 0, &ret);
}
NTSTATUS xp_reset(uint64_t h) { return handle_op(SHZ_SND_OP_RESET, h); }
NTSTATUS xp_close(uint64_t h) { return handle_op(SHZ_SND_OP_CLOSE, h); }

MMRESULT xp_mm(NTSTATUS st)
{
    if (NT_SUCCESS(st)) return MMSYSERR_NOERROR;
    switch (st) {
    case STATUS_DEVICE_NOT_READY: case STATUS_INVALID_SYSTEM_SERVICE: case STATUS_NOT_IMPLEMENTED: return MMSYSERR_NODRIVER;
    case STATUS_DEVICE_BUSY: case STATUS_SHARING_VIOLATION: return MMSYSERR_ALLOCATED;
    case STATUS_INVALID_HANDLE: return MMSYSERR_INVALHANDLE;
    case STATUS_INVALID_PARAMETER: case STATUS_ACCESS_VIOLATION: case STATUS_INVALID_USER_BUFFER: return MMSYSERR_INVALPARAM;
    case STATUS_NO_MEMORY: case STATUS_INSUFFICIENT_RESOURCES: return MMSYSERR_NOMEM;
    default: return MMSYSERR_ERROR;
    }
}

int xp_format_ok(unsigned ch, unsigned bits, unsigned rate, const shz_snd_caps *c)
{
    unsigned rm = rate == 11025 ? SHZ_SND_RATE_11025 : rate == 22050 ? SHZ_SND_RATE_22050 :
                  rate == 44100 ? SHZ_SND_RATE_44100 : rate == 48000 ? SHZ_SND_RATE_48000 : 0;
    unsigned bm = bits == 8 ? SHZ_SND_FMT_8BIT : bits == 16 ? SHZ_SND_FMT_16BIT : 0;
    return (ch == 1 || ch == 2) && ch <= c->max_channels && rm && bm && (c->rate_mask & rm) && (c->bits_mask & bm);
}

HMODULE xp_modref(void)
{
    HMODULE m = 0;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)(void *)xp_modref, &m)) return 0;
    return m;
}

void xp_modunref(HMODULE m) { if (m) FreeLibrary(m); }

void xp_modexit(HMODULE m) { FreeLibraryAndExitThread(m, 0); for (;;) ExitThread(0); }
