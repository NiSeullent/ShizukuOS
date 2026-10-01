/* SPDX-License-Identifier: GPL-2.0-only
 * Real Win98 WINMM endpoint/tone probe. No installation or host audio service.
 * A wave driver retains its header/data/event until completion and unprepare.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <mmsystem.h>
#include "native_audio_pcm.h"

static HANDLE report = INVALID_HANDLE_VALUE;
static int io_failed;
static WAVEHDR header;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static void text(const char *s) {
    DWORD done, bytes = length(s);
    if (!WriteFile(report, s, bytes, &done, NULL) || done != bytes) io_failed = 1;
}
static void number(const char *key, DWORD value) {
    char hex[9]; unsigned i;
    for (i = 0; i < 8; ++i) hex[i] = "0123456789ABCDEF"[(value >> (28 - i * 4)) & 15];
    hex[8] = 0; text(key); text(hex); text("\r\n");
}
static void escaped(const char *key, const char *value, unsigned maximum) {
    unsigned i; text(key);
    for (i = 0; i < maximum && value[i]; ++i) {
        unsigned c = (unsigned char)value[i]; char part[5];
        if (c >= 32 && c < 127 && c != '\\') { part[0] = (char)c; part[1] = 0; }
        else { part[0] = '\\'; part[1] = 'x'; part[2] = "0123456789ABCDEF"[c >> 4]; part[3] = "0123456789ABCDEF"[c & 15]; part[4] = 0; }
        text(part);
    }
    text("\r\n");
}
static int flush(void) {
    if (io_failed || !FlushFileBuffers(report)) { io_failed = 1; return 0; }
    return 1;
}
static int wait_done(HANDLE event, DWORD deadline) {
    DWORD start = GetTickCount();
    while (!(*(volatile DWORD *)&header.dwFlags & WHDR_DONE)) {
        DWORD result = WaitForSingleObject(event, 100);
        if (result != WAIT_OBJECT_0 && result != WAIT_TIMEOUT) {
            DWORD error = result == WAIT_FAILED ? GetLastError() : 0;
            number("BUFFER_WAIT_RESULT=", result); number("BUFFER_WAIT_ERROR=", error);
            return 0;
        }
        if (GetTickCount() - start >= deadline) return 0;
    }
    return 1;
}
void WINAPI entry(void) {
    UINT count, i; DWORD code = 3, start = 0;
    HWAVEOUT wave = NULL; HANDLE event = NULL; int16_t *samples = NULL;
    WAVEFORMATEX format = {0}; MMRESULT mm; int prepared = 0, wrote = 0, done = 0, clean = 1;
    OSVERSIONINFOA version = {0};
    report = CreateFileA("C:\\VXDLAB\\AUDTONE.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=NATIVE_WINMM_DEVICE_AND_GENERATED_PCM_ONLY\r\nNO_DRIVER_OR_REGISTRY_INSTALL=1\r\n");
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) { number("VERSION_QUERY_ERROR=", GetLastError()); goto cleanup; }
    number("OS_PLATFORM=", version.dwPlatformId); number("OS_MAJOR=", version.dwMajorVersion);
    number("OS_MINOR=", version.dwMinorVersion); number("OS_BUILD=", version.dwBuildNumber & 0xffff);
    if (version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion != 4 || version.dwMinorVersion != 10) goto cleanup;
    count = waveOutGetNumDevs(); number("ACTUAL_WAVEOUT_DEVICE_COUNT=", count);
    if (!count || count > 32) goto cleanup;
    for (i = 0; i < count; ++i) {
        WAVEOUTCAPSA caps = {0};
        mm = waveOutGetDevCapsA(i, &caps, sizeof(caps));
        number("DEVICE_INDEX=", i); number("DEVICE_CAPS_MMRESULT=", mm);
        if (mm != MMSYSERR_NOERROR) goto cleanup;
        number("DEVICE_MANUFACTURER_ID=", caps.wMid); number("DEVICE_PRODUCT_ID=", caps.wPid);
        number("DEVICE_DRIVER_VERSION=", caps.vDriverVersion); number("DEVICE_FORMATS=", caps.dwFormats);
        number("DEVICE_CHANNELS=", caps.wChannels); number("DEVICE_SUPPORT=", caps.dwSupport);
        escaped("DEVICE_NAME_BYTES=", caps.szPname, sizeof(caps.szPname));
    }
    number("SELECTED_ACTUAL_DEVICE_INDEX=", 0);
    format.wFormatTag = WAVE_FORMAT_PCM; format.nChannels = 1;
    format.nSamplesPerSec = AUDIO_RATE; format.wBitsPerSample = 16;
    format.nBlockAlign = 2; format.nAvgBytesPerSec = AUDIO_RATE * 2;
    mm = waveOutOpen(NULL, 0, &format, 0, 0, WAVE_FORMAT_QUERY);
    number("FORMAT_QUERY_MMRESULT=", mm); if (mm != MMSYSERR_NOERROR || !flush()) goto cleanup;
    samples = HeapAlloc(GetProcessHeap(), 0, AUDIO_FRAMES * sizeof(*samples));
    /* HeapAlloc does not set last-error; never present stale errno as cause. */
    if (!samples) { text("PCM_ALLOCATION_FAILED=1\r\n"); goto cleanup; }
    audio_pcm_fill(samples, AUDIO_FRAMES);
    number("GENERATED_PCM_RATE=", AUDIO_RATE); number("GENERATED_PCM_FRAMES=", AUDIO_FRAMES);
    number("GENERATED_PCM_HZ=", AUDIO_HZ); number("GENERATED_PCM_BYTES=", AUDIO_FRAMES * sizeof(*samples));
    event = CreateEventA(NULL, FALSE, FALSE, NULL);
    if (!event) { number("EVENT_CREATE_ERROR=", GetLastError()); goto cleanup; }
    mm = waveOutOpen(&wave, 0, &format, (DWORD_PTR)event, 0, CALLBACK_EVENT);
    number("ACTUAL_OPEN_MMRESULT=", mm); number("ACTUAL_OPEN_HANDLE=", (DWORD)(ULONG_PTR)wave);
    if (mm != MMSYSERR_NOERROR || !wave) goto cleanup;
    header.lpData = (LPSTR)samples; header.dwBufferLength = AUDIO_FRAMES * sizeof(*samples);
    mm = waveOutPrepareHeader(wave, &header, sizeof(header));
    number("PREPARE_HEADER_MMRESULT=", mm); if (mm != MMSYSERR_NOERROR) goto cleanup;
    prepared = 1;
    number("ACTUAL_PREPARED_FLAG=", (header.dwFlags & WHDR_PREPARED) != 0);
    if (!(header.dwFlags & WHDR_PREPARED)) goto cleanup;
    if (!ResetEvent(event)) { number("EVENT_RESET_ERROR=", GetLastError()); goto cleanup; }
    if (!flush()) goto cleanup;
    start = GetTickCount(); mm = waveOutWrite(wave, &header, sizeof(header));
    number("ACTUAL_WRITE_MMRESULT=", mm); if (mm != MMSYSERR_NOERROR) goto cleanup;
    wrote = 1; done = wait_done(event, 15000);
    number("ACTUAL_HEADER_DONE=", done); number("ACTUAL_HEADER_FLAGS=", header.dwFlags);
    number("PLAYBACK_WAIT_ELAPSED_MS=", GetTickCount() - start);
cleanup:
    if (wave && prepared && wrote && !(*(volatile DWORD *)&header.dwFlags & WHDR_DONE)) {
        mm = waveOutReset(wave); number("CLEANUP_RESET_MMRESULT=", mm);
        if (mm != MMSYSERR_NOERROR || !wait_done(event, 5000)) clean = 0;
    }
    if (wave && prepared && (!wrote || (*(volatile DWORD *)&header.dwFlags & WHDR_DONE))) {
        mm = waveOutUnprepareHeader(wave, &header, sizeof(header));
        number("ACTUAL_UNPREPARE_MMRESULT=", mm);
        if (mm == MMSYSERR_NOERROR) prepared = 0; else clean = 0;
    }
    if (wave && !prepared) {
        mm = waveOutClose(wave); number("ACTUAL_CLOSE_MMRESULT=", mm);
        if (mm == MMSYSERR_NOERROR) wave = NULL; else clean = 0;
    }
    if (!wave && !prepared) {
        if (event && !CloseHandle(event)) { number("EVENT_CLOSE_ERROR=", GetLastError()); clean = 0; }
        if (samples && !HeapFree(GetProcessHeap(), 0, samples)) { number("PCM_FREE_ERROR=", GetLastError()); clean = 0; }
    } else {
        /* Never free memory/events still borrowed by a native driver. Failed
         * ownership remains until native process teardown and cannot pass. */
        text("DRIVER_OWNED_BUFFER_EVENT_RETAINED_UNTIL_PROCESS_TEARDOWN=1\r\n"); clean = 0;
    }
    if (done && clean && !io_failed) code = 0;
    number("ACTUAL_BUFFER_AND_HANDLE_CLEANUP_COMPLETE=", clean);
    number("SELECTED_PROBE_EXIT=", code);
    text(code || io_failed ? "STATUS=NATIVE_WAVEOUT_SCOPE_FAIL\r\n" : "STATUS=NATIVE_WAVEOUT_HEADER_DONE_AND_CLEANUP\r\n");
    text("BACKEND_WAV_AND_EXTERNAL_ACTUAL_PROCESS_EXIT_REQUIRE_INDEPENDENT_PROOF=1\r\n");
    if (!flush()) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed ? 31 : code);
}
