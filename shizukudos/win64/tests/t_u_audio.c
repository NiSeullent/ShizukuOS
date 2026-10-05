/* SPDX-License-Identifier: GPL-2.0-only
 * Native guest check of the real WinMM audio path: winmm.dll -> NtShzSound (ShizukuOS Core audio service) -> AC97 DMA.
 * It must run inside a ShizukuOS guest that exposes an AC97 function. With no audio hardware every "device present" check
 * FAILs (by design: no fake success). Completion is checked against the audio duration: a header that completes much
 * faster than its playing time would mean the data was not consumed by hardware.
 * Not run by the author: no guest was started in the authoring session.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include "u_check.h"

#define RATE 44100u
#define FRAMES 22050u                         /* 0.5 s per header */
#define BYTES (FRAMES * 4u)

static short tone[2][FRAMES * 2];
static BYTE wav[44 + BYTES];
static BYTE bad[44 + 400];

static void le32(BYTE *p, DWORD v) { p[0] = (BYTE)v; p[1] = (BYTE)(v >> 8); p[2] = (BYTE)(v >> 16); p[3] = (BYTE)(v >> 24); }

static void make_wav(BYTE *b, DWORD dlen, const short *pcm)
{
    memcpy(b, "RIFF", 4); le32(b + 4, 36 + dlen); memcpy(b + 8, "WAVEfmt ", 8); le32(b + 16, 16);
    b[20] = 1; b[21] = 0; b[22] = 2; b[23] = 0; le32(b + 24, RATE); le32(b + 28, RATE * 4); b[32] = 4; b[33] = 0; b[34] = 16; b[35] = 0;
    memcpy(b + 36, "data", 4); le32(b + 40, dlen); memcpy(b + 44, pcm, dlen);
}

int main(void)
{
    WAVEFORMATEX fmt, bad6;
    HWAVEOUT wo = 0, wo2 = 0;
    WAVEHDR h0, h1;
    WAVEOUTCAPSW caps;
    MMTIME mt;
    HANDLE ev;
    DWORD t0, el;
    UINT i, n;
    MMRESULT mr;

    for (i = 0; i < FRAMES; ++i) {                       /* 440 Hz-ish triangle, moderate amplitude */
        int ph = (int)((i * 440u) % RATE), v = ph < (int)(RATE / 2) ? ph * 4 - (int)RATE : 3 * (int)RATE - ph * 4;
        short s = (short)(v / 8);
        tone[0][2 * i] = tone[0][2 * i + 1] = s; tone[1][2 * i] = tone[1][2 * i + 1] = s;
    }
    make_wav(wav, BYTES, tone[0]);
    memset(&fmt, 0, sizeof fmt);
    fmt.wFormatTag = WAVE_FORMAT_PCM; fmt.nChannels = 2; fmt.nSamplesPerSec = RATE; fmt.wBitsPerSample = 16;
    fmt.nBlockAlign = 4; fmt.nAvgBytesPerSec = RATE * 4;
    bad6 = fmt; bad6.nChannels = 6; bad6.nBlockAlign = 12; bad6.nAvgBytesPerSec = RATE * 12;

    n = waveOutGetNumDevs();
    U_CHECKF("Core audio device present (waveOutGetNumDevs == 1)", n == 1, "n=%u", n);
    if (n != 1) {
        U_CHECK("no device: open device 0 is MMSYSERR_BADDEVICEID", waveOutOpen(&wo, 0, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_BADDEVICEID);
        U_CHECK("no device: mapper is MMSYSERR_NODRIVER", waveOutOpen(&wo, WAVE_MAPPER, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_NODRIVER);
        U_CHECK("no device: PlaySound memory is FALSE (no fake success)", !PlaySoundA((LPCSTR)wav, 0, SND_MEMORY | SND_SYNC));
        return u_failures ? u_failures : 1;
    }

    memset(&caps, 0, sizeof caps);
    U_CHECK("waveOutGetDevCapsW(0)", waveOutGetDevCapsW(0, &caps, sizeof caps) == MMSYSERR_NOERROR && caps.wChannels == 2 && (caps.dwFormats & WAVE_FORMAT_4S16));
    U_CHECK("QUERY 44.1k/16/stereo is NOERROR", waveOutOpen(0, WAVE_MAPPER, &fmt, 0, 0, WAVE_FORMAT_QUERY) == MMSYSERR_NOERROR);
    U_CHECK("QUERY 6 channels is WAVERR_BADFORMAT", waveOutOpen(0, WAVE_MAPPER, &bad6, 0, 0, WAVE_FORMAT_QUERY) == WAVERR_BADFORMAT);
    U_CHECK("QUERY did not open a stream (second QUERY and numdevs unchanged)", waveOutGetNumDevs() == 1 && waveOutOpen(0, 0, &fmt, 0, 0, WAVE_FORMAT_QUERY) == MMSYSERR_NOERROR);

    ev = CreateEventW(0, FALSE, FALSE, 0);
    mr = waveOutOpen(&wo, WAVE_MAPPER, &fmt, (DWORD_PTR)ev, 0, CALLBACK_EVENT);
    U_CHECKF("waveOutOpen(mapper, CALLBACK_EVENT)", mr == MMSYSERR_NOERROR && wo, "mr=%u", mr);
    if (mr != MMSYSERR_NOERROR) return u_failures + 1;
    U_CHECK("second open while exclusive stream is open fails MMSYSERR_ALLOCATED", waveOutOpen(&wo2, 0, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_ALLOCATED && !wo2);

    memset(&h0, 0, sizeof h0); memset(&h1, 0, sizeof h1);
    h0.lpData = (LPSTR)tone[0]; h0.dwBufferLength = BYTES;
    h1.lpData = (LPSTR)tone[1]; h1.dwBufferLength = BYTES;
    U_CHECK("waveOutWrite before Prepare is WAVERR_UNPREPARED", waveOutWrite(wo, &h0, sizeof h0) == WAVERR_UNPREPARED);
    U_CHECK("waveOutPrepareHeader x2", waveOutPrepareHeader(wo, &h0, sizeof h0) == MMSYSERR_NOERROR && waveOutPrepareHeader(wo, &h1, sizeof h1) == MMSYSERR_NOERROR && (h0.dwFlags & WHDR_PREPARED));
    t0 = GetTickCount();
    U_CHECK("waveOutWrite x2", waveOutWrite(wo, &h0, sizeof h0) == MMSYSERR_NOERROR && waveOutWrite(wo, &h1, sizeof h1) == MMSYSERR_NOERROR);
    U_CHECK("queued headers are INQUEUE and not DONE yet", (h0.dwFlags & WHDR_INQUEUE) && !(h0.dwFlags & WHDR_DONE) && (h1.dwFlags & WHDR_INQUEUE));
    U_CHECK("waveOutWrite of a queued header is WAVERR_STILLPLAYING", waveOutWrite(wo, &h0, sizeof h0) == WAVERR_STILLPLAYING);
    U_CHECK("waveOutUnprepareHeader of a queued header is WAVERR_STILLPLAYING", waveOutUnprepareHeader(wo, &h0, sizeof h0) == WAVERR_STILLPLAYING);
    U_CHECK("waveOutClose with queued headers is WAVERR_STILLPLAYING", waveOutClose(wo) == WAVERR_STILLPLAYING);
    U_CHECK("waveOutPause / Restart", waveOutPause(wo) == MMSYSERR_NOERROR && waveOutRestart(wo) == MMSYSERR_NOERROR);
    while (!(h1.dwFlags & WHDR_DONE) && GetTickCount() - t0 < 8000) WaitForSingleObject(ev, 50);
    el = GetTickCount() - t0;
    U_CHECKF("both headers completed from Core completion (WHDR_DONE, not INQUEUE)", (h0.dwFlags & WHDR_DONE) && (h1.dwFlags & WHDR_DONE) && !(h0.dwFlags & WHDR_INQUEUE) && !(h1.dwFlags & WHDR_INQUEUE), "elapsed=%lu ms", (unsigned long)el);
    U_CHECKF("completion took about the 1000 ms of audio (not instant)", el >= 800 && el < 6000, "elapsed=%lu ms", (unsigned long)el);
    memset(&mt, 0, sizeof mt); mt.wType = TIME_BYTES;
    U_CHECK("waveOutGetPosition(TIME_BYTES) >= bytes played", waveOutGetPosition(wo, &mt, sizeof mt) == MMSYSERR_NOERROR && mt.wType == TIME_BYTES && mt.u.cb >= BYTES * 2 - 4096);
    U_CHECK("waveOutUnprepareHeader after completion", waveOutUnprepareHeader(wo, &h0, sizeof h0) == MMSYSERR_NOERROR && waveOutUnprepareHeader(wo, &h1, sizeof h1) == MMSYSERR_NOERROR);

    /* Reset returns queued headers as done only after Core stopped */
    h0.dwFlags = 0;
    waveOutPrepareHeader(wo, &h0, sizeof h0);
    waveOutWrite(wo, &h0, sizeof h0);
    U_CHECK("waveOutReset", waveOutReset(wo) == MMSYSERR_NOERROR);
    U_CHECK("after Reset the header is DONE and not INQUEUE", (h0.dwFlags & WHDR_DONE) && !(h0.dwFlags & WHDR_INQUEUE));
    U_CHECK("Unprepare and Close after Reset", waveOutUnprepareHeader(wo, &h0, sizeof h0) == MMSYSERR_NOERROR && waveOutClose(wo) == MMSYSERR_NOERROR);
    U_CHECK("closed handle is invalid", waveOutClose(wo) == MMSYSERR_INVALHANDLE);
    CloseHandle(ev);

    /* PlaySound */
    t0 = GetTickCount();
    U_CHECK("PlaySoundA(SND_MEMORY|SND_SYNC) TRUE", PlaySoundA((LPCSTR)wav, 0, SND_MEMORY | SND_SYNC));
    el = GetTickCount() - t0;
    U_CHECKF("synchronous PlaySound lasted about 500 ms of audio", el >= 400 && el < 6000, "elapsed=%lu ms", (unsigned long)el);
    U_CHECK("PlaySoundA(SND_MEMORY|SND_ASYNC) TRUE", PlaySoundA((LPCSTR)wav, 0, SND_MEMORY | SND_ASYNC));
    U_CHECK("PlaySound(NULL) cancels async sound", PlaySoundA(0, 0, 0));
    U_CHECK("waveOut device free after cancel", waveOutOpen(&wo, 0, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_NOERROR && waveOutClose(wo) == MMSYSERR_NOERROR);
    U_CHECK("SND_ALIAS is FALSE (no alias table, no default beep)", !PlaySoundA("SystemAsterisk", 0, SND_ALIAS | SND_NODEFAULT | SND_SYNC));
    U_CHECK("SND_LOOP is FALSE (unsupported)", !PlaySoundA((LPCSTR)wav, 0, SND_MEMORY | SND_ASYNC | SND_LOOP));
    memcpy(bad, wav, sizeof bad); le32(bad + 40, 0x7fffffffu);
    U_CHECK("malformed WAV (data size overflow) is FALSE", !PlaySoundA((LPCSTR)bad, 0, SND_MEMORY | SND_SYNC));
    U_CHECK("missing file is FALSE", !PlaySoundA("C:\\no\\such.wav", 0, SND_FILENAME | SND_SYNC | SND_NODEFAULT));
    return u_failures;
}
