# Shared genuine engine for IE and Zetscape

The existing canonical IE host already defines the shared C ABI in
`/home/almalinux/workspace/iewebkit/include/engine.h`. Its loader loads the
adjacent `iewebkit-engine.dll` and resolves `IEWebKitGetEngineV1`, an x86
`__cdecl` function accepting ABI 1 and returning `const IEWKEngineV1*`.
That DLL/provider does not exist in the current compiled engine artifacts.

The table creates an opaque view under a supplied parent HWND, destroys it
with all tasks and callbacks quiesced, navigates a numbered request with
explicit UTF-8 URL/method/body lengths, and receives resize/focus/commands.
Host callbacks report committed canonical URL/origin, title, failures and
requested navigation on the owning apartment thread. The actual engine owns
canonical origins, cookies, TLS, subresources and navigation identity. IE and
the root-owned native Zetscape host can supply different UI callbacks to the
same real provider; neither should replace the provider with helper output.

Required capability bits cover genuine HTML, CSS, DOM, JavaScriptCore,
verified TLS and origin isolation. The table currently has no graphics-driver
interface or hardware acceleration capability. ShizukuEdition acceleration
therefore requires additional concrete renderer/driver integration and actual
submission/presentation evidence. Export presence, a bool, software drawing
or the original firmware GOP path cannot establish that requirement.

The immediate sequence is:

1. Diagnose the observed actual WTF v5 abnormal termination with closed-handle
   stage logs and an actual direct-abort return PC, then repair the identified
   genuine runtime source and repeat original Win98 SE native testing.
2. Regenerate the genuine JSCOnly graph with the current paired runtime,
   finish the real JSC build, and run the actual JavaScriptCore C API probe.
3. Restore the pinned real WebCore sources and build their Win32 view,
   painting/input, resource loader and network/TLS/origin platform backends.
4. Implement the existing provider export from actual WebCore/JSC objects,
   then verify IE and Zetscape loading, navigation, painting, input, history,
   origin/TLS behavior and complete lifecycle in the real guest.

The current C_LOOP/JIT_OFF/WASM_OFF JSCOnly profile is an interpreter
bring-up profile. It does not satisfy the mandatory modern-web target.
WebAssembly and all required full-browser execution/features still need real
implementation and tests. General Win98 SE and the driver-enabled
ShizukuEdition require separate platform acceptance. No Chromium full-source
build, remote browser, Trident renderer or substitute HTML engine is part of
this shared engine design.
