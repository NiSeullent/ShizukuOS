# Pinned WebKit Win9x RunLoop port

The pinned WTF Windows RunLoop creates a `HWND_MESSAGE` window and uses the
generic Windows text APIs. This patch adds an explicit `IEWEBKIT_WIN9X` branch
that creates a hidden, unowned ANSI popup and uses the ANSI message/context APIs.
The Windows NT branch retains its original message window and dispatch behavior.
The shared backend header is compiled into the native fixture and included by
the patched upstream source; this is actual engine port code.

**No WebKit document provider or JavaScriptCore engine has been built.** The
fixture does not render a page, expose `IEWebKitGetEngineV1`, claim engine
capabilities, or substitute for IE host/DOM/layout/TLS validation. The full WTF
archive remains pending. The subsequent [core continuation](core_README.md)
compiled both original and patched `RunLoopWin.cpp` against genuine WTF and ICU
headers. Its native Windows 98 comparison finds that `RegisterClassW` returns
error 120, while the shared ANSI backend registers and creates its window.
The earlier ANSI `HWND_MESSAGE` creation succeeds on that guest, so its parent
handle is not a demonstrated blocker.

The source pin is WebKit commit `5220e80b97a253c60ed899361654142ab5021998`.
`source-pin.json` records the exact upstream file, original and modified hashes,
archive provenance, patch hash and licenses. The original upstream Apple notice
remains unchanged. The new helper, fixture and builder use SPDX `MIT`.

## Build and inspect

Run from the Win98-Modern repository with Python 3 and MinGW x86 tools installed:

```sh
python3 tools/iewebkit_port/build.py \
  --output /absolute/external/runloop-build \
  --exports benchmarks/win98se-ko-oem-native-exports-v1.json
```

This writes `RUNLOOP.EXE`, `build.log`, its linked PE import listing, and
`RUNLOOP.receipt.json` to the requested directory. It starts no VM, service or
network connection. The receipt binds the executable, source/patch, export
manifest and exact compiler arguments. A passing import gate establishes export
presence only; stubbed APIs still require native runtime verification.

## Apply to the pinned engine source

Use an independent WebKit source tree; do not apply this patch to another
session's work. First verify the source file against `upstream_sha256` in
`source-pin.json`, then apply:

```sh
patch --batch -p1 -d /absolute/pinned/webkit-source \
  -i /absolute/Win98-Modern-boot/tools/iewebkit_port/patches/webkit-2.54.0-win9x-runloop-window.patch
```

Verify `RunLoopWin.cpp` against `modified_sha256` and the installed helper
against `src/RunLoopWin9x.h`. The existing IEWebKit source manifest is unchanged;
its owner must review and add this patch before using the canonical engine build.
This patch alone does not supply ICU, the remaining WTF/JSC objects, WebCore,
the IE provider ABI, network/TLS, or document rendering.

## Native Win98 verification

Copy the digest-bound executable into a disposable, isolated Windows 98 guest
and run `RUNLOOP.EXE`; its default log is `C:\GOPLAB\RL9X.LOG`. An optional first
argument supplies another log path. Create the parent log directory first.
The fixture refuses an OS version other than Win9x 4.10. The guest runner must
also establish that this is a real Windows 98 guest; version emulation in Wine
is not accepted as Windows 98 evidence.

The log records the original `HWND_MESSAGE` attempt, then checks the shared
hidden-window backend's visibility/context, one work message, 96 cross-thread
messages, a real Windows timer, worker exit, destruction and quit message. The
original API attempt is measured and is not itself a pass/fail assumption.
Acceptance requires fresh log readback with `exit=0`, the matching input SHA256,
actual guest OS evidence and the sealed-base/shutdown checks of the guest runner.
Record those results separately from the build receipt. Full browser integration
remains unverified even when this backend passes.
