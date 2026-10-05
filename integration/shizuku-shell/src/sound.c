/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Existing WINMM PlaySound filename consumer; no new audio service or synthetic provider.
 * Configured WAV references resolve below the actual Windows MEDIA directory.
 * Existing WINMM filename loading and kernel file access remain the authority.
 * Async TRUE means submission accepted, never audible/completed playback. No SND_LOOP.
 * Only default gain (theme 100) or mute (0) is supported; percentages are not implemented.
 */
#include "sound.h"
static int same(const char *a, const char *b)
{
    unsigned i;
    for (i=0; a[i] && b[i]; ++i) {
        unsigned x=(unsigned char)a[i], y=(unsigned char)b[i];
        if (x>='A' && x<='Z') x+=32;
        if (y>='A' && y<='Z') y+=32;
        if (x!=y) return 0;
    }
    return !a[i] && !b[i];
}
int ShzSoundPolicy(const SHZ_THEME *t, enum SHZ_SOUND_EVENT event, const char **alias)
{
    const char *ref;
    if (!alias) return -2;
    *alias=0;
    if (!t || !t->sound_enabled || t->sound_volume==0) return 0;
    if (t->sound_volume!=100) return -1;
    switch (event) {
    case SHZ_SOUND_STARTUP: ref=t->sound_startup;break;
    case SHZ_SOUND_NOTIFICATION: ref=t->sound_notification;break;
    case SHZ_SOUND_ERROR: ref=t->sound_error;break;
    case SHZ_SOUND_THEME: ref=t->sound_navigation;break;
    default: return -2;
    }
    if (same(ref,"none")) { *alias=0;return 0; }
    if (!ShzThemeValidateSoundRef(ref)) return -2;
    *alias=ref;
    return 1;
}
#ifndef SHZ_SOUND_POLICY_ONLY
#include "shell.h"
#include "shzcrt.h"
#include <mmsystem.h>
static int active;
static DWORD last_tick;
static int have_tick;
/* These public flags are supported by the actual current playsnd.c validation. */
#define SHELL_SOUND_FLAGS (SND_FILENAME | SND_ASYNC | SND_NODEFAULT | SND_NOSTOP)
_Static_assert((SHELL_SOUND_FLAGS & (SND_LOOP | SND_MEMORY | SND_ALIAS | SND_RESOURCE))==0,"No desktop loop/resource/alias flags");
void ShzSoundEvent(enum SHZ_SOUND_EVENT event)
{
    const char *alias;
    WCHAR wide[MAX_PATH];
    unsigned i;
    DWORD saved, hint, now;
    int planned;
    BOOL accepted;
    if (!active) return;
    saved=GetLastError();
    now=GetTickCount();
    if (event!=SHZ_SOUND_STARTUP && have_tick && (DWORD)(now-last_tick)<250) { SetLastError(saved);return; }
    planned=ShzSoundPolicy(TH(),event,&alias);
    if (!planned) { SetLastError(saved);return; }
    last_tick=now;have_tick=1;
    if (planned<0) {
        printf("SHZ-SHELL SOUND refused event=%d reason=%s guest=unverified\n",(int)event,
               planned==-1 ? "volume-control-unavailable" : "reference-provider-unavailable");SetLastError(saved);return;
    }
    {
        UINT n=GetWindowsDirectoryW(wide,MAX_PATH);
        unsigned at;
        if (!n || n>=MAX_PATH) {
            printf("SHZ-SHELL SOUND refused event=%d reason=windows-directory-unavailable guest=unverified\n",(int)event);
            SetLastError(saved);return;
        }
        if (n && wide[n-1]=='\\') wide[--n]=0;
        if (!ShzWcsCat(wide,MAX_PATH,L"\\MEDIA\\")) { SetLastError(saved);return; }
        for (at=0; wide[at]; ++at) { }
        for (i=0; alias[i] && at+1<MAX_PATH; ++i) wide[at++]=alias[i]=='/' ? '\\' : (WCHAR)(unsigned char)alias[i];
        if (alias[i]) { SetLastError(saved);return; }
        wide[at]=0;
        /* Refuse any reported reparse component. This is a preflight check only;
         * actual WINMM CreateFile / Core file authority remains decisive. A missing
         * file is submitted and its actual FALSE result is reported below. */
        for (i=3; i<=at; ++i) if (wide[i]=='\\' || !wide[i]) {
            WCHAR delimiter=wide[i];DWORD attributes;
            wide[i]=0;attributes=GetFileAttributesW(wide);wide[i]=delimiter;
            if (attributes!=INVALID_FILE_ATTRIBUTES && (attributes&FILE_ATTRIBUTE_REPARSE_POINT)) {
                printf("SHZ-SHELL SOUND refused event=%d reason=reparse-reference guest=unverified\n",(int)event);
                SetLastError(saved);return;
            }
        }
    }
    SetLastError(ERROR_SUCCESS);
    accepted=PlaySoundW(wide,NULL,SHELL_SOUND_FLAGS);hint=GetLastError();SetLastError(saved);
    printf("SHZ-SHELL SOUND %s event=%d reference=%s flags=0x%lx gain=default win32_hint=%lu guest=unverified\n",
           accepted ? "accepted" : "refused",(int)event,alias,(unsigned long)SHELL_SOUND_FLAGS,(unsigned long)hint);
    SetLastError(saved);
}
void ShzSoundStartup(void) { active=1;ShzSoundEvent(SHZ_SOUND_STARTUP); }
void ShzSoundShutdown(void)
{
    DWORD saved;BOOL stopped;
    if (!active) return;
    active=0;
    saved=GetLastError();stopped=PlaySoundW(NULL,NULL,0);SetLastError(saved);
    printf("SHZ-SHELL SOUND stop=%d guest=unverified\n",(int)stopped);
    SetLastError(saved);
    /* Existing WINMM stop_current owns its worker and bounds its wait at 10000ms.
     * No shutdown WAV is started and immediately cancelled; playback-on-exit remains unsupported. */
}
#endif
