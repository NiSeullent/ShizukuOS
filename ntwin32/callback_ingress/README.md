# Provider worker admission for mapped PE32 TLS

This original GPL-2.0-only component calls the existing `ntw_tls_attach` and
`ntw_tls_detach` implementation. It admits an explicit actual provider worker
once, keeps its compiler TLS across repeated/idle/nested callbacks, and retires
that same worker after its last callback. It does not create threads or pretend
that each pool callback starts and ends an OS thread.

The caller owns one logical loader lock, the prepared immutable module set,
mapped images, and provider references. Every lifecycle operation runs under
that lock. Target code runs outside it, between a successful callback enter
and matching leave. Notification hooks run under the lock with published TLS;
the real graph adapter must run DLL TLS callbacks before DllMain in the proper
dependency order. Reentry into ingress lifecycle from notification hooks fails
explicitly. Abandoned callbacks/exceptions and abrupt/fiber exits require other
adapters; their storage must stay retained rather than be reported retired.

There are64 workers and32 nested frames per worker. Handles bind the stable
manager address, slot and non-wrapping generation. Frame serials cannot wrap;
leaves require exact LIFO ownership. Distinct managers cannot consume each
other's handles or frames, even on the same native thread. Before target entry
or detach, actual TLS slot values must still equal the worker's owned storage.
Foreign/fiber-replaced values are refused without clearing them. Publication
rollback and partial detach failures keep a recovery handle and all remaining
owned storage; retries do not repeat notifications. Closing prevents new
workers/callbacks and waits for logical retirement. `ni_finish` does not establish
that OS threads have returned; providers must retain/join their real handles
before unloading anything. Never perform that join from DllMain.

An integrator's persistent provider worker uses the interface as follows:

```c
lock_loader();
status = ni_worker_start(manager, &worker);
unlock_loader();
/* If retained/failure: run same-thread recovery; enter no target code. */
while (status == NI_OK && obtain_work()) {
    lock_loader();
    status = ni_callback_enter(manager, &worker, &frame);
    unlock_loader();
    if (status != NI_OK) break;
    call_real_target(); /* exact provider-specific ABI; normal return */
    lock_loader();
    status = ni_callback_leave(manager, &frame);
    unlock_loader();
}
lock_loader();
status = ni_worker_stop(manager, &worker); /* same actual worker */
unlock_loader();
/* Stop failure pins ownership and forbids ordinary worker retirement. */
```

The example illustrates ordering, not an exception-safe public Win32 wrapper.
The actual provider must finish active frames before stop, react to lifecycle
failure without target entry/freeing, retain worker handles, and unregister
external ingress before joining. Joining occurs outside the logical loader
lock so final notifications and TLS clear can acquire it.

Current `src/m98_threadpool.c` starts its workers through ordinary native
CreateThread, closes their thread handles, and does not expose per-worker
admission/retirement hooks or a quiescent join API. The existing native loader's
worker accounting covers only its direct CreateThread trampoline. Its provider
execution gate remains unchanged. Wiring this component requires coordinated
provider hook/handle ownership and loader graph notification adapters; merely
wrapping each work callback would not solve persistent TLS/thread lifetime.
RegisterWait, timers, COM/USER/WinMM callbacks, FLS destructor ingress, exception
handlers, threads already inside target code and fibers still need their own
actual ingress contracts. No Chromium/Legcord/Steam/Office acceptance follows.

The separate native fixture maps one own zero-import PE DLL with an actual
Microsoft-ABI compiler TLS directory and FS:2c accesses. Two real provider-like
workers each reuse their template for128 mapped calls, including nested frames;
their real detach callbacks read their own final values. The observer requires
joined native thread handles/exit0 before logical closure, process detach,
TLS disposal and mapping release. A separate child supervisor observes the
probe's actual OS exit and complete fresh log. Its own exit still requires an
independent outer observer. Neither probe starts a browser or installs providers.

Build in a NEW private output, using installed compilers only:

```text
python3 -B ntwin32/callback_ingress/build.py --out build/callback-ingress-c009-20261001
```

The builder freezes and hashes all used sources, runs GCC and Clang host
controls (GCC UBSan traps; Clang ASan/UBSan) against the real existing TLS engine on eight pthread
workers, and compiles native i486 PE32/GUI4.10 artifacts. It gates every native
import against the preserved actual Win98 OEM inventory. It launches no VM,
downloads nothing, and changes no application or global configuration. Its
manifest is a handoff to the established guest owner; native execution remains
pending until a separate frozen actual Win98 trial and independent readback.

Source provenance: new ingress/probe/test code is original; this work reuses
unmodified GPL project `native_loader/tls_runtime.[ch]`, `pe.[ch]`, the own
`tls_compiler_fixture.c`, and freestanding compiler-support primitives. The TLS
backend's existing explicit Win98 FS/TDB checks remain authoritative. Lifecycle
references are [Microsoft DLL thread notifications](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-entry-point-function)
and the previously pinned [Wine loader callback ordering](https://github.com/wine-mirror/wine/blob/master/dlls/ntdll/loader.c).
No new Wine implementation or proprietary code is copied. The public interface
fully specifies the narrower cooperative provider contract; host adapter results
do not validate native Windows ABI or arbitrary callback facilities.
