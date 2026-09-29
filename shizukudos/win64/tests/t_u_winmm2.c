/* SPDX-License-Identifier: GPL-2.0-only
 * winmm.dll wave and MIDI device APIs on a system without audio or MIDI drivers. The expectations are the documented results
 * for that situation (mmeapi.h): no devices are counted, an out-of-range device id is MMSYSERR_BADDEVICEID, the wave mapper
 * needs a driver (MMSYSERR_NODRIVER), the MIDI mapper reports MIDIERR_NODEVICE ("no MIDI port was found"), and a handle that no
 * open call returned is MMSYSERR_INVALHANDLE.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include "u_check.h"

int main(void)
{
    WAVEFORMATEX fmt;
    HWAVEOUT wo = (HWAVEOUT)(ULONG_PTR)0x1234;
    HMIDIOUT mo = (HMIDIOUT)(ULONG_PTR)0x1234;
    HMIDIIN mi = (HMIDIIN)(ULONG_PTR)0x1234;
    WAVEHDR wh;
    MIDIHDR mh;
    MIDIOUTCAPSW oc;
    MIDIINCAPSW ic;
    char data[16];

    U_CHECK("waveOutGetNumDevs is 0 (no audio driver)", waveOutGetNumDevs() == 0);
    U_CHECK("waveInGetNumDevs is 0", waveInGetNumDevs() == 0);
    U_CHECK("midiOutGetNumDevs is 0 (no MIDI driver)", midiOutGetNumDevs() == 0);
    U_CHECK("midiInGetNumDevs is 0", midiInGetNumDevs() == 0);

    memset(&fmt, 0, sizeof fmt);
    fmt.wFormatTag = WAVE_FORMAT_PCM; fmt.nChannels = 2; fmt.nSamplesPerSec = 44100; fmt.wBitsPerSample = 16;
    fmt.nBlockAlign = 4; fmt.nAvgBytesPerSec = 44100 * 4;
    U_CHECK("waveOutOpen(device 0) is MMSYSERR_BADDEVICEID", waveOutOpen(&wo, 0, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_BADDEVICEID && wo == 0);
    U_CHECK("waveOutOpen(WAVE_MAPPER) is MMSYSERR_NODRIVER", waveOutOpen(&wo, WAVE_MAPPER, &fmt, 0, 0, CALLBACK_NULL) == MMSYSERR_NODRIVER);
    U_CHECK("waveOutOpen(WAVE_FORMAT_QUERY, no handle) is answered the same way", waveOutOpen(0, 0, &fmt, 0, 0, WAVE_FORMAT_QUERY) == MMSYSERR_BADDEVICEID);
    U_CHECK("waveOutOpen without a format is MMSYSERR_INVALPARAM", waveOutOpen(&wo, 0, 0, 0, 0, CALLBACK_NULL) == MMSYSERR_INVALPARAM);
    U_CHECK("waveOutOpen with an unknown flag is MMSYSERR_INVALFLAG", waveOutOpen(&wo, 0, &fmt, 0, 0, 0x40000000) == MMSYSERR_INVALFLAG);
    wo = (HWAVEOUT)(ULONG_PTR)0x1234;
    memset(&wh, 0, sizeof wh);
    wh.lpData = data; wh.dwBufferLength = sizeof data;
    U_CHECK("waveOutPrepareHeader(unknown handle) is MMSYSERR_INVALHANDLE", waveOutPrepareHeader(wo, &wh, sizeof wh) == MMSYSERR_INVALHANDLE);
    U_CHECK("waveOutWrite(unknown handle)", waveOutWrite(wo, &wh, sizeof wh) == MMSYSERR_INVALHANDLE);
    U_CHECK("waveOutUnprepareHeader(unknown handle)", waveOutUnprepareHeader(wo, &wh, sizeof wh) == MMSYSERR_INVALHANDLE);
    U_CHECK("waveOutPause / Restart / Reset (unknown handle)",
            waveOutPause(wo) == MMSYSERR_INVALHANDLE && waveOutRestart(wo) == MMSYSERR_INVALHANDLE && waveOutReset(wo) == MMSYSERR_INVALHANDLE);
    U_CHECK("waveOutClose(unknown handle)", waveOutClose(wo) == MMSYSERR_INVALHANDLE);
    U_CHECK("waveOutClose(NULL)", waveOutClose(0) == MMSYSERR_INVALHANDLE);

    U_CHECK("midiOutOpen(device 0) is MMSYSERR_BADDEVICEID", midiOutOpen(&mo, 0, 0, 0, CALLBACK_NULL) == MMSYSERR_BADDEVICEID && mo == 0);
    U_CHECK("midiOutOpen(MIDI_MAPPER) is MIDIERR_NODEVICE", midiOutOpen(&mo, MIDI_MAPPER, 0, 0, CALLBACK_NULL) == MIDIERR_NODEVICE);
    U_CHECK("midiOutOpen(NULL handle pointer) is MMSYSERR_INVALPARAM", midiOutOpen(0, 0, 0, 0, CALLBACK_NULL) == MMSYSERR_INVALPARAM);
    U_CHECK("midiInOpen(device 0) is MMSYSERR_BADDEVICEID", midiInOpen(&mi, 0, 0, 0, CALLBACK_NULL) == MMSYSERR_BADDEVICEID && mi == 0);
    U_CHECK("midiOutGetDevCapsW(0) is MMSYSERR_BADDEVICEID", midiOutGetDevCapsW(0, &oc, sizeof oc) == MMSYSERR_BADDEVICEID);
    U_CHECK("midiOutGetDevCapsW(MIDI_MAPPER) is MMSYSERR_NODRIVER", midiOutGetDevCapsW(MIDI_MAPPER, &oc, sizeof oc) == MMSYSERR_NODRIVER);
    U_CHECK("midiOutGetDevCapsW(NULL caps) is MMSYSERR_INVALPARAM", midiOutGetDevCapsW(0, 0, sizeof oc) == MMSYSERR_INVALPARAM);
    U_CHECK("midiInGetDevCapsW(0) is MMSYSERR_BADDEVICEID", midiInGetDevCapsW(0, &ic, sizeof ic) == MMSYSERR_BADDEVICEID);
    mo = (HMIDIOUT)(ULONG_PTR)0x1234;
    mi = (HMIDIIN)(ULONG_PTR)0x1234;
    memset(&mh, 0, sizeof mh);
    mh.lpData = data; mh.dwBufferLength = sizeof data;
    U_CHECK("midiOutShortMsg(unknown handle)", midiOutShortMsg(mo, 0x00403c90) == MMSYSERR_INVALHANDLE);
    U_CHECK("midiOutLongMsg / Prepare / Unprepare (unknown handle)",
            midiOutLongMsg(mo, &mh, sizeof mh) == MMSYSERR_INVALHANDLE && midiOutPrepareHeader(mo, &mh, sizeof mh) == MMSYSERR_INVALHANDLE &&
            midiOutUnprepareHeader(mo, &mh, sizeof mh) == MMSYSERR_INVALHANDLE);
    U_CHECK("midiOutReset / Close (unknown handle)", midiOutReset(mo) == MMSYSERR_INVALHANDLE && midiOutClose(mo) == MMSYSERR_INVALHANDLE);
    U_CHECK("midiInStart / Reset / Close (unknown handle)",
            midiInStart(mi) == MMSYSERR_INVALHANDLE && midiInReset(mi) == MMSYSERR_INVALHANDLE && midiInClose(mi) == MMSYSERR_INVALHANDLE);
    U_CHECK("midiInAddBuffer / Prepare / Unprepare (unknown handle)",
            midiInAddBuffer(mi, &mh, sizeof mh) == MMSYSERR_INVALHANDLE && midiInPrepareHeader(mi, &mh, sizeof mh) == MMSYSERR_INVALHANDLE &&
            midiInUnprepareHeader(mi, &mh, sizeof mh) == MMSYSERR_INVALHANDLE);
    U_CHECK("the multimedia timer still works next to the device APIs", timeGetTime() != 0);
    return u_finish("t_u_winmm2");
}
