/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Win32/RTL coherence, error retention and overlapping native threads.
 * Tests the narrow TEB field contract. Kernel64's zero initial thread field is
 * explicitly distinguished from missing effective process-mode inheritance.
 */
#include "k32test.h"
#include <stdint.h>

__declspec(dllimport) ULONG NTAPI RtlGetThreadErrorMode(void);
__declspec(dllimport) LONG NTAPI RtlSetThreadErrorMode(ULONG, PULONG);

static const DWORD win_modes[8] = {0,1,2,3,0x8000,0x8001,0x8002,0x8003};
static const ULONG rtl_modes[8] = {0,0x10,0x20,0x30,0x40,0x50,0x60,0x70};
typedef struct { HANDLE ready, leave; unsigned index; } worker_context;

static DWORD WINAPI worker(void *opaque)
{
    worker_context *c = opaque;
    DWORD old = 0xdeadbeef, error = 0x12530000u + c->index;
    ULONG previous = 0xdeadbeef;
    if (GetThreadErrorMode() || RtlGetThreadErrorMode()) return 1;
    SetLastError(error);
    if (!SetThreadErrorMode(win_modes[c->index], &old) || old || GetLastError()!=error) return 2;
    if (RtlGetThreadErrorMode()!=rtl_modes[c->index] || GetThreadErrorMode()!=win_modes[c->index]) return 3;
    if (!SetEvent(c->ready) || WaitForSingleObject(c->leave,10000)!=WAIT_OBJECT_0) return 4;
    if (RtlGetThreadErrorMode()!=rtl_modes[c->index] || GetThreadErrorMode()!=win_modes[c->index]) return 5;
    SetLastError(error);
    if (RtlSetThreadErrorMode(rtl_modes[7-c->index],&previous) || previous!=rtl_modes[c->index]) return 6;
    if (GetThreadErrorMode()!=win_modes[7-c->index] || GetLastError()!=error) return 7;
    return 0;
}

int main(void)
{
    ULONG saved_rtl = RtlGetThreadErrorMode(), previous;
    UINT saved_process = GetErrorMode();
    DWORD old, expected = GetThreadErrorMode(), code;
    unsigned i, bit; worker_context workers[8] = {{0}}; HANDLE threads[8] = {0}, gate;
    CHECK(saved_rtl==0 && expected==0,"Kernel64 zeroed TEB begins with zero thread field; process fallback is separate");
    for (i=0;i<8;++i) {
        old=0xdeadbeef;SetLastError(0x12531000u+i);
        CHECK(SetThreadErrorMode(win_modes[i],&old) && old==expected,"Win32 mode setter returns the actual previous Win32 bits");
        CHECK(GetLastError()==0x12531000u+i && GetThreadErrorMode()==win_modes[i] && RtlGetThreadErrorMode()==rtl_modes[i],
              "all accepted Win32 mask combinations share the RTL field and preserve LastError");
        expected=win_modes[i];previous=0xdeadbeef;
        CHECK(RtlSetThreadErrorMode(rtl_modes[7-i],&previous)==0 && previous==rtl_modes[i],"native setter returns the actual previous RTL bits");
        CHECK(GetThreadErrorMode()==win_modes[7-i] && RtlGetThreadErrorMode()==rtl_modes[7-i] && GetLastError()==0x12531000u+i,
              "native updates are visible to Win32 without changing LastError");
        expected=win_modes[7-i];
        CHECK(SetThreadErrorMode(win_modes[i],NULL) && GetThreadErrorMode()==win_modes[i],"Win32 previous-mode output is optional");
        CHECK(RtlSetThreadErrorMode(rtl_modes[i],NULL)==0,"native previous-mode output is optional");
        expected=win_modes[i];
    }
    for (bit=0;bit<32;++bit) {
        DWORD flag=(DWORD)1u<<bit;
        if (!(flag & 0x8003u)) {
            old=0xdeadbeef;SetLastError(0x12532000);
            CHECK(!SetThreadErrorMode(flag|expected,&old) && GetLastError()==ERROR_INVALID_PARAMETER && old==0xdeadbeef,
                  "each unknown Win32 bit fails with error87 and preserves the output");
            CHECK(GetThreadErrorMode()==expected && RtlGetThreadErrorMode()==0x70,"invalid Win32 bits preserve the thread state");
        }
        if (!(flag & 0x70u)) {
            previous=0xdeadbeef;SetLastError(0x12533000);
            CHECK((ULONG)RtlSetThreadErrorMode(flag|0x70u,&previous)==0xc00000efu && previous==0xdeadbeef,
                  "each unknown RTL bit returns invalidparameter1 and preserves the output");
            CHECK(RtlGetThreadErrorMode()==0x70 && GetThreadErrorMode()==expected && GetLastError()==0x12533000,
                  "invalid RTL bits preserve the mode and Win32 LastError");
        }
    }
    CHECK(!SetThreadErrorMode(4,(LPDWORD)(uintptr_t)1) && GetLastError()==ERROR_INVALID_PARAMETER,
          "Win32 validation precedes dereferencing an invalid previous-mode pointer");
    CHECK((ULONG)RtlSetThreadErrorMode(1,(PULONG)(uintptr_t)1)==0xc00000efu,
          "native mask validation precedes dereferencing an invalid previous-mode pointer");
    SetErrorMode(SEM_NOGPFAULTERRORBOX);
    CHECK(SetThreadErrorMode(SEM_FAILCRITICALERRORS,NULL) && GetErrorMode()==SEM_NOGPFAULTERRORBOX,
          "thread mode changes preserve the independent process mode");
    gate=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(gate!=NULL,"actual worker release event creates");
    for (i=0;i<8;++i) {
        workers[i].index=i;workers[i].leave=gate;workers[i].ready=CreateEventW(NULL,TRUE,FALSE,NULL);
        if (workers[i].ready && gate) threads[i]=CreateThread(NULL,0,worker,&workers[i],0,NULL);
        CHECK(threads[i]!=NULL,"actual overlapping mode worker starts");
    }
    for (i=0;i<8;++i)
        CHECK(threads[i] && WaitForSingleObject(workers[i].ready,10000)==WAIT_OBJECT_0,"worker publishes its independent thread mode");
    CHECK(GetThreadErrorMode()==SEM_FAILCRITICALERRORS && RtlGetThreadErrorMode()==0x10 && GetErrorMode()==SEM_NOGPFAULTERRORBOX,
          "eight worker updates do not overwrite the main thread or process state");
    CHECK(gate && SetEvent(gate),"actual workers are released together");
    for (i=0;i<8;++i) {
        code=0xffffffffu;
        CHECK(threads[i] && WaitForSingleObject(threads[i],10000)==WAIT_OBJECT_0,"real worker thread exits and joins");
        CHECK(threads[i] && GetExitCodeThread(threads[i],&code) && code==0,"worker retained its own mode while other threads changed theirs");
        if(threads[i])CloseHandle(threads[i]);
        if(workers[i].ready)CloseHandle(workers[i].ready);
    }
    if(gate)CloseHandle(gate);
    CHECK(GetThreadErrorMode()==SEM_FAILCRITICALERRORS,"worker exits preserve the main thread mode");
    SetErrorMode(saved_process);RtlSetThreadErrorMode(saved_rtl,NULL);
    return k32t_finish("T_THREAD_ERROR_MODE");
}
