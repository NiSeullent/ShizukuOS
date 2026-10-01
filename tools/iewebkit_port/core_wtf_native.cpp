// Actual pinned WTF archive caller; no JSC evaluation or document rendering.
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
        auto* current = WTF::Thread::currentMayBeNull();
        bool grown = growTLS(std::make_index_sequence<64> { });
        InterlockedExchange(&workerTLSGrowth, grown ? 1 : -1);
        bool chained = registerChainedCleanup();
        InterlockedExchange(&workerTLSCleanup,
            magic == 0x83bd4321 && current && current != probeMainThread && grown && chained ? 1 : -1);
    }
};
static thread_local WorkerCleanupProbe workerCleanupProbe;

static DWORD WINAPI dispatchWorker(void*)
{
    auto& current = WTF::Thread::currentSingleton();
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
    FILE* log = std::fopen(argv[1], "wb");
    if (!log)
        return 2;
    // Persist the fresh nonce before real engine initialization can abort.
    std::fprintf(log, "scope=actual-pinned-WTF-archive-runtime\r\nnonce=%s\r\n", argv[2]);
    std::fflush(log);
    OSVERSIONINFOA version { };
    version.dwOSVersionInfoSize = sizeof(version);
    bool target = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS
        && version.dwMajorVersion == 4 && version.dwMinorVersion == 10 && LOWORD(version.dwBuildNumber) == 2222;
    std::fprintf(log, "os.major=%lu\r\nos.minor=%lu\r\nos.build=%lu\r\nos.exact-target=%u\r\n",
        version.dwMajorVersion, version.dwMinorVersion, static_cast<unsigned long>(LOWORD(version.dwBuildNumber)), target);
    std::fflush(log);
    if (!target) {
        std::fprintf(log, "exit=3\r\n");
        std::fclose(log);
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
    std::fprintf(log, "rng.original-W.acquired=%u\r\nrng.original-W.error=%lu\r\nrng.original-W.generated=%u\r\nrng.A.acquired=%u\r\nrng.A.error=%lu\r\nrng.A.generated=%u\r\n",
        !!acquiredW, errorW, !!generatedW, !!acquiredA, errorA, !!generatedA);
    std::fflush(log);
    WTF::initializeMainThread();
    probeMainThread = &WTF::Thread::currentSingleton();
    mainLoop = &WTF::RunLoop::mainSingleton();
    callbackThread = GetCurrentThreadId();
    std::fprintf(log, "wtf.initialize=1\r\nrunloop.main-current=%u\r\n", mainLoop->isCurrent());
    std::fflush(log);
    auto& pressure = WTF::MemoryPressureHandler::singleton();
    pressure.install();
    pressure.install();
    pressure.setMemoryFootprintPollIntervalForTesting(WTF::Seconds(0.05));
    pressure.setShouldUsePeriodicMemoryMonitor(true);
    std::fprintf(log, "memory-pressure.install-repeat=1\r\n");
    std::fflush(log);
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
        std::fprintf(log, "worker.created=0\r\nexit=4\r\n");
        std::fclose(log);
        return 4;
    }
    WTF::RunLoop::run();
    pulse.stop();
    deadline.stop();
    pressure.setShouldUsePeriodicMemoryMonitor(false);
    DWORD joined = WaitForSingleObject(worker, 1000);
    CloseHandle(worker);
    bool success = mainLoop->isCurrent() && timerFired && !timedOut
        && joined == WAIT_OBJECT_0 && dispatched == 96 && workerDone == 1
        && workerContext == 1 && workerTLSCleanup == 1
        && workerTLSGrowth == 1 && workerTLSChained == 1;
    std::fprintf(log, "memory-pressure.periodic-monitor-stopped=1\r\nworker.joined=%u\r\nworker.done=%ld\r\ndispatch.count=%ld\r\ntimer.fired=%u\r\ntimer.deadline-fired=%u\r\nexit=%u\r\n",
        joined == WAIT_OBJECT_0, workerDone, dispatched, timerFired, timedOut, success ? 0 : 5);
    std::fprintf(log, "worker.wtf-context=%ld\r\nworker.cpp-tls-cleanup=%ld\r\nworker.cpp-tls-growth=%ld\r\nworker.cpp-tls-chained=%ld\r\n",
        workerContext, workerTLSCleanup, workerTLSGrowth, workerTLSChained);
    std::fclose(log);
    return success ? 0 : 5;
}
