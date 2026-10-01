// Diagnostic copy of the exact genuine WTF v5 caller; engine behavior is retained.
// Direct checkpoint writes close every handle; explicit GNU abort wrapping adds
// an actual return PC. No JSC evaluation or document rendering is certified.
// Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
#include "config.h"
#include <wtf/MainThread.h>
#include <wtf/MemoryPressureHandler.h>
#include <wtf/RunLoop.h>
#include <wtf/Seconds.h>
#include <wtf/Threading.h>
#include <windows.h>
#include <wincrypt.h>
#include <cstdio>
#include <cstring>
#include <utility>
#include "src/core_Win9xDiagnosticLog.h"

// MinGW GNU ld --wrap=abort applies the target's leading underscore itself.
// Ordinary C names emit ___wrap_abort/___real_abort and route raw _abort.
extern "C" [[noreturn]] void __real_abort();
extern "C" [[noreturn]] void __wrap_abort();
extern "C" [[noreturn]] __attribute__((noinline)) void __wrap_abort()
{
    iewkDiagnosticAbortRecord(__builtin_extract_return_addr(__builtin_return_address(0)));
    __real_abort();
}

static WTF::RunLoop* mainLoop;
static volatile LONG dispatched;
static volatile LONG workerDone;
static DWORD callbackThread;
static bool timerFired;
static bool timedOut;

static WTF::Thread* probeMainThread;
static volatile LONG workerContext;
static volatile LONG workerTLSCleanup;
static volatile LONG workerTLSGrowth;
static volatile LONG workerTLSChained;

template<size_t index> static unsigned& growthSlot()
{
    static thread_local unsigned value;
    return value;
}

template<size_t... indices> static bool growTLS(std::index_sequence<indices...>)
{
    // More than the genuine emutls array's initial 32 spare slots. This makes
    // destructor-time TLS creation grow its array, then checks every old cell.
    ((growthSlot<indices>() = 0x83bd0000u + indices), ...);
    return ((growthSlot<indices>() == 0x83bd0000u + indices) && ...);
}

struct ChainedCleanupProbe {
    unsigned magic { 0x83bd1234 };
    ~ChainedCleanupProbe()
    {
        InterlockedExchange(&workerTLSChained, magic == 0x83bd1234 ? 1 : -1);
    }
};

static bool registerChainedCleanup()
{
    // Function-scope TLS is constructed during the first destructor itself,
    // so it registers a genuinely new cxa chain during cleanup.
    static thread_local ChainedCleanupProbe probe;
    return probe.magic == 0x83bd1234;
}

struct WorkerCleanupProbe {
    unsigned magic { 0x83bd4321 };
    ~WorkerCleanupProbe()
    {
        // A C++ destructor must still see the original, live WTF TLS cell.
        // This fails if emutls frees/clears cells before invoking the chain.
        InterlockedExchange(&iewkDiagnosticWorkerPhase, 3);
        auto* current = WTF::Thread::currentMayBeNull();
        bool grown = growTLS(std::make_index_sequence<64> { });
        InterlockedExchange(&workerTLSGrowth, grown ? 1 : -1);
        InterlockedExchange(&iewkDiagnosticWorkerPhase, 4);
        bool chained = registerChainedCleanup();
        InterlockedExchange(&iewkDiagnosticWorkerPhase, 5);
        InterlockedExchange(&workerTLSCleanup,
            magic == 0x83bd4321 && current && current != probeMainThread && grown && chained ? 1 : -1);
    }
};
static thread_local WorkerCleanupProbe workerCleanupProbe;

static DWORD WINAPI dispatchWorker(void*)
{
    InterlockedExchange(&iewkDiagnosticWorkerPhase, 1);
    auto& current = WTF::Thread::currentSingleton();
    InterlockedExchange(&iewkDiagnosticWorkerPhase, 2);
    bool context = &current != probeMainThread && &current == &WTF::Thread::currentSingleton();
    context = context && workerCleanupProbe.magic == 0x83bd4321;
    InterlockedExchange(&workerContext, context ? 1 : -1);
    for (unsigned index = 0; index < 96; ++index) {
        mainLoop->dispatch([] {
            if (GetCurrentThreadId() != callbackThread)
                InterlockedExchange(&dispatched, -10000);
            else
                InterlockedIncrement(&dispatched);
        });
    }
    InterlockedExchange(&workerDone, 1);
    return 0;
}

int main(int argc, char** argv)
{
    if (argc != 3 || !std::strlen(argv[2]) || std::strlen(argv[2]) > 80
        || std::strspn(argv[2], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != std::strlen(argv[2]))
        return 10;
    std::memcpy(iewkDiagnosticNonce, argv[2], std::strlen(argv[2]) + 1);
    IEWKDiagnosticLog log(argv[1]);
    if (!log.good())
        return 2;
    // Persist the fresh nonce before real engine initialization can abort.
    log.printf("scope=actual-pinned-WTF-archive-runtime\r\nnonce=%s\r\n", argv[2]);
    if (!log.good())
        return 11;
    log.printf("diagnostic.closed-checkpoints=1\r\ndiagnostic.abort-scope=direct-COFF-_abort-references\r\n");
    if (!log.good()) return 11;
    OSVERSIONINFOA version { };
    version.dwOSVersionInfoSize = sizeof(version);
    bool target = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS
        && version.dwMajorVersion == 4 && version.dwMinorVersion == 10 && LOWORD(version.dwBuildNumber) == 2222;
    log.printf("os.major=%lu\r\nos.minor=%lu\r\nos.build=%lu\r\nos.exact-target=%u\r\n",
        version.dwMajorVersion, version.dwMinorVersion, static_cast<unsigned long>(LOWORD(version.dwBuildNumber)), target);
    if (!log.good())
        return 11;
    if (!target) {
        log.printf("exit=3\r\n");
        if (!log.good())
            return 11;
        return 3;
    }
    // An exported Unicode function may still be a legacy stub. Measure both
    // exact provider acquisitions before entering the real WTF initializer.
    HCRYPTPROV provider = 0;
    SetLastError(0);
    BOOL acquiredW = CryptAcquireContextW(&provider, nullptr, MS_DEF_PROV_W, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    DWORD errorW = GetLastError();
    unsigned char randomBytes[16] { };
    BOOL generatedW = acquiredW && CryptGenRandom(provider, sizeof(randomBytes), randomBytes);
    if (acquiredW)
        CryptReleaseContext(provider, 0);
    provider = 0;
    SetLastError(0);
    BOOL acquiredA = CryptAcquireContextA(&provider, nullptr, MS_DEF_PROV_A, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    DWORD errorA = GetLastError();
    BOOL generatedA = acquiredA && CryptGenRandom(provider, sizeof(randomBytes), randomBytes);
    if (acquiredA)
        CryptReleaseContext(provider, 0);
    log.printf("rng.original-W.acquired=%u\r\nrng.original-W.error=%lu\r\nrng.original-W.generated=%u\r\nrng.A.acquired=%u\r\nrng.A.error=%lu\r\nrng.A.generated=%u\r\n",
        !!acquiredW, errorW, !!generatedW, !!acquiredA, errorA, !!generatedA);
    if (!log.good())
        return 11;
    InterlockedExchange(&iewkDiagnosticMainPhase, 1);
    log.printf("phase.before-initialize-main-thread=1\r\n");
    if (!log.good()) return 11;
    WTF::initializeMainThread();
    InterlockedExchange(&iewkDiagnosticMainPhase, 2);
    log.printf("phase.after-initialize-main-thread=1\r\n");
    if (!log.good()) return 11;
    InterlockedExchange(&iewkDiagnosticMainPhase, 3);
    log.printf("phase.before-current-thread=1\r\n");
    if (!log.good()) return 11;
    probeMainThread = &WTF::Thread::currentSingleton();
    InterlockedExchange(&iewkDiagnosticMainPhase, 4);
    log.printf("phase.after-current-thread=1\r\n");
    if (!log.good()) return 11;
    InterlockedExchange(&iewkDiagnosticMainPhase, 5);
    log.printf("phase.before-main-runloop=1\r\n");
    if (!log.good()) return 11;
    mainLoop = &WTF::RunLoop::mainSingleton();
    InterlockedExchange(&iewkDiagnosticMainPhase, 6);
    log.printf("phase.after-main-runloop=1\r\n");
    if (!log.good()) return 11;
    callbackThread = GetCurrentThreadId();
    log.printf("wtf.initialize=1\r\nrunloop.main-current=%u\r\n", mainLoop->isCurrent());
    if (!log.good())
        return 11;
    InterlockedExchange(&iewkDiagnosticMainPhase, 7);
    log.printf("phase.before-pressure-singleton=1\r\n");
    if (!log.good()) return 11;
    auto& pressure = WTF::MemoryPressureHandler::singleton();
    InterlockedExchange(&iewkDiagnosticMainPhase, 8);
    log.printf("phase.after-pressure-singleton=1\r\n");
    if (!log.good()) return 11;
    InterlockedExchange(&iewkDiagnosticMainPhase, 9);
    log.printf("phase.before-pressure-install=1\r\n");
    if (!log.good()) return 11;
    pressure.install();
    InterlockedExchange(&iewkDiagnosticMainPhase, 10);
    log.printf("phase.after-pressure-install=1\r\n");
    if (!log.good()) return 11;
    pressure.install();
    InterlockedExchange(&iewkDiagnosticMainPhase, 11);
    log.printf("phase.after-pressure-install-repeat=1\r\n");
    if (!log.good()) return 11;
    pressure.setMemoryFootprintPollIntervalForTesting(WTF::Seconds(0.05));
    InterlockedExchange(&iewkDiagnosticMainPhase, 12);
    log.printf("phase.before-periodic-monitor=1\r\n");
    if (!log.good()) return 11;
    pressure.setShouldUsePeriodicMemoryMonitor(true);
    InterlockedExchange(&iewkDiagnosticMainPhase, 13);
    log.printf("phase.after-periodic-monitor=1\r\n");
    if (!log.good()) return 11;
    log.printf("memory-pressure.install-repeat=1\r\n");
    if (!log.good())
        return 11;
    WTF::RunLoop::Timer pulse(WTF::Ref { *mainLoop }, "actual-wtf-pulse"_s, [] {
        timerFired = true;
        if (InterlockedCompareExchange(&dispatched, 0, 0) >= 96
            && InterlockedCompareExchange(&workerDone, 0, 0))
            mainLoop->stop();
    });
    WTF::RunLoop::Timer deadline(WTF::Ref { *mainLoop }, "actual-wtf-deadline"_s, [] {
        timedOut = true;
        mainLoop->stop();
    });
    pulse.startRepeating(WTF::Seconds(0.05));
    deadline.startOneShot(WTF::Seconds(5));
    HANDLE worker = CreateThread(nullptr, 0, dispatchWorker, nullptr, 0, nullptr);
    if (!worker) {
        pulse.stop();
        deadline.stop();
        log.printf("worker.created=0\r\nexit=4\r\n");
        if (!log.good())
            return 11;
        return 4;
    }
    // Once the worker exists, a sticky logging failure must still complete
    // the normal deadline-bounded loop and owned monitor/worker cleanup.
    // Report that failure only at the final log.good() check below.
    InterlockedExchange(&iewkDiagnosticMainPhase, 14);
    log.printf("phase.before-runloop-run=1\r\n");
    WTF::RunLoop::run();
    InterlockedExchange(&iewkDiagnosticMainPhase, 15);
    log.printf("phase.after-runloop-run=1\r\n");
    pulse.stop();
    deadline.stop();
    InterlockedExchange(&iewkDiagnosticMainPhase, 16);
    log.printf("phase.before-monitor-stop=1\r\n");
    pressure.setShouldUsePeriodicMemoryMonitor(false);
    InterlockedExchange(&iewkDiagnosticMainPhase, 17);
    log.printf("phase.after-monitor-stop=1\r\n");
    DWORD joined = WaitForSingleObject(worker, 1000);
    CloseHandle(worker);
    bool success = mainLoop->isCurrent() && timerFired && !timedOut
        && joined == WAIT_OBJECT_0 && dispatched == 96 && workerDone == 1
        && workerContext == 1 && workerTLSCleanup == 1
        && workerTLSGrowth == 1 && workerTLSChained == 1;
    log.printf("memory-pressure.periodic-monitor-stopped=1\r\nworker.joined=%u\r\nworker.done=%ld\r\ndispatch.count=%ld\r\ntimer.fired=%u\r\ntimer.deadline-fired=%u\r\nexit=%u\r\n",
        joined == WAIT_OBJECT_0, workerDone, dispatched, timerFired, timedOut, success ? 0 : 5);
    log.printf("worker.wtf-context=%ld\r\nworker.cpp-tls-cleanup=%ld\r\nworker.cpp-tls-growth=%ld\r\nworker.cpp-tls-chained=%ld\r\n",
        workerContext, workerTLSCleanup, workerTLSGrowth, workerTLSChained);
    if (!log.good())
            return 11;
    return log.good() ? (success ? 0 : 5) : 11;
}
