# Native provider-table bridge

NTWPROV.DLL lets a native Windows98 loader use five source-built project API
providers through their published 32-bit get_api_table ABI. The adapter loads
only explicit M98WRAP/M98SHELL/M98AD2/M98USR1/M98CTL3 files from the caller's
absolute private directory. An additional ANSI SECUR32 profile binds the
project's native x86 M98SSPI.DLL from that same directory. It does not install KernelEx core or change routes,
registry keys, or application bytes. KernelEx installation is a separate trial.

Before returning any address it validates the complete sorted name/ordinal
table, its zero terminator, every readable string and every executable function
inside the actual loaded DLL's PE sections. Missing functions remain missing;
table presence is not API behavior or application execution proof. It never
returns unsupported modules or arbitrary native stubs as implementations.

The SSPI profile uses typed WINAPI InitSecurityInterfaceA once per loaded
module and validates the project's version1 108-byte x86 table prefix through
DecryptMessage. Its13 populated slots must match their executable DLL exports;
the other13 prefix slots must be NULL. InitSecurityInterfaceA and M98SspiEndInput
are separately validated executable exports. Unicode, unknown names and
ordinals are refused before loading. Export/ImportSecurityContext remain the
native provider's unsupported operations; finding them does not enable context
migration. This profile does not register an OS provider or route Kernel64 SSPI.

Every cached lookup checks the full table again without reinitializing it.
Initial validation failure unloads and leaves a fresh retry possible. Later
corruption refuses new pointers while retaining the loaded module until close,
so a prior pointer's lifetime is not cut short by another lookup.

The caller owns a context and must keep it alive until all returned pointers
and threads stop using it. This includes threads started by a provider. Joining
and callback teardown, plus release of all provider-owned SSPI contexts,
credentials and buffers, are prerequisites to closing the context. The caller
must prevent simultaneous close and use. The bridge cannot count these native
objects or prove the caller's join. Lookups use a process-local Windows critical
section and may block in the Windows loader; do not invoke them from interrupts
or VMM callbacks. Missing or
malformed providers return an actual loader/validation error. GDI's preserved
provider requires a specific KernelEx MSIMG32 backend and is deliberately not
part of this independent adapter. Native Unicode/runtime/TLS and the full app
dependency closure remain separate requirements. Windows98 remains the product
OS; ShizukuDOS replaces MS-DOS beneath it and Kernel32/64 serve that system.

Build and host/parser tests do not establish native load or latest-app success.
The bridge is a new extension stage, not a complete Windows API implementation.
