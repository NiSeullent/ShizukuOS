# Browser address wait and exact API contracts

This additive candidate implements process-local address waits with real
Win98 critical sections and auto-reset events. `WakeByAddressSingle` chooses
the first registered un-signaled waiter. Wait publication, wake and removal
share a lock; the event retains a wake between registration and the OS wait.
Each waiter owns its event until removal. Failed closes retain the event in a
non-reusable slot and require explicit quiescent cleanup. No VM, application,
provider registration or existing runtime profile is changed by the builder.

The implementation has 128 simultaneous/retained slots and reports resource
failures explicitly. This differs from the Windows8 implementation's low-memory
behavior and remains a bounded port candidate. Caller addresses must remain
valid, backend callbacks must not reenter, and every caller must join before
cleanup or unloading. A wake may succeed while the compared value is unchanged;
the caller must recheck its condition, as allowed by the documented
[WaitOnAddress contract](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress).
The oldest waiter rule follows [WakeByAddressSingle](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-wakebyaddresssingle).
Invalid caller memory access is not caught; Win98 exception integration remains
separate work. Forced termination of a waiter is unsupported.

`api_contract.c` hashes immutable original Chromium157 x86 `chrome.exe` bytes
against SHA256 `7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823`.
Only its three `API-MS-WIN-CORE-SYNCH-L1-2-0.DLL` address functions and
`API-MS-WIN-POWER-BASE-L1-1-0.DLL!CallNtPowerInformation` get candidate routes.
Contract versions, symbols and ordinals never fall back to broader aliases.
The latter export exists in the preserved Win98 OEM `POWRPROF.DLL` inventory;
its runtime behavior has not been tested. Route selection does not load code,
pin a provider binary, validate executable addresses or install an alias.
Those loader ownership/path/hash gates remain required before any target use.

`M98ADDR.DLL` exposes exact stdcall names, using only classic native Kernel32
services. `CHADDR.EXE` tests the privately loaded provider with actual Win98
worker threads/events/timeouts, logs fresh `C:\VXDLAB\CHADDR.LOG`, and requires
joined workers before unloading. `CHASUIT.EXE` observes that child's real exit.
They are compiled artifacts until an actual private Win98 run with readback;
their controls cannot establish Chromium startup, rendering, TLS or input.

Publisher facts checked on 2026-09-30:

- [Legcord v1.3.0](https://github.com/Legcord/Legcord/releases/tag/v1.3.0)
  uses **Electron43.2.0** in its [release-tag package](https://raw.githubusercontent.com/Legcord/Legcord/v1.3.0/package.json).
  Electron44.2.0 belongs to development main. Release Windows ia32/x64/ARM64
  assets exist; their full application has not been downloaded or run here.
- [LibreOffice26.8.0](https://www.libreoffice.org/download/) is published for
  Windows x86-64/ARM64. No Office document workflow has run.
- The [current Steam win64 manifest](https://client-update.steamstatic.com/steam_client_win64)
  has version1788652215. Its small publisher-pinned platform archive's actual
  `steam.exe` is AMD64 PE32+, independently inspected without executing it.
  This is not a complete client/dependency installation or GUI test.

The existing WIN64 bridge is console-only. Its host ABI and standalone Kernel64
tests do not establish Win98-to-Kernel64 execution. The VxD has a recorded guest
loader failure and the Supervisor has no live Win98 VMX domain yet. Office and
Steam require these joins plus a guest-owned GUI bridge: generation-tagged
surface/process identities, bounded surface dimensions/stride, explicit shared
buffer ownership, Win98 USER/GDI presentation, focus/input/clipboard routing,
and normal-exit/fault cleanup. No raw 64-bit pointer or foreign process handle
may cross the existing fixed-width IPC boundary. A created process acknowledgement
does not establish executed code or a visible application window.
