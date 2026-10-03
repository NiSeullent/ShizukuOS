# Native Windows 98 Classic / ShizukuOS palette selector

This component changes the **actual Windows 98 USER32 system palette** through
`SetSysColors`, then verifies every requested color with `GetSysColor`. The
no-argument executable opens Classic and ShizukuOS buttons with separate saved,
current-session and result labels. It does not run or relabel the theme probe.
Public UI uses ShizukuOS; the existing app-local `M98_THEME_MODERN=2` ABI and
historical Classic/Modern probe evidence remain unchanged.

ShizukuDOS replaces MS-DOS for actual Windows 98. Kernel32 and Kernel64 support
that Windows 98 foundation. Running this selector on an OEM Windows 98 control
does not establish the ShizukuDOS-to-Windows integration or a separate OS product.

## Exact scope

Only legacy system-color indices **0 through 24** are changed: desktop, caption,
menu, window, selection and standard-control colors. Fonts, Korean charset,
non-client metrics, window geometry and other user settings are untouched.
Reserved index 25 is excluded. HOTLIGHT 26 and caption-gradient endpoints 27/28 are
also untouched in this initial lane; XP-only menu indices 29/30 are excluded.
Consequently, an enabled native caption gradient can retain its old second
endpoint. This is a system palette theme, not an XP visual-style service,
`.msstyles` loader or proof of completely modern non-client rendering.

Native USER32 color notifications/repainting reach windows that use those system
colors. Owner-drawn/custom controls and the separate M98THEME process-local
provider do not automatically adopt this profile. Their initialization, change
handling and full application functionality require separate integration and
actual tests. No hooks, DLL injection or dynamic startup DLL are installed.

The native executable refuses non-Windows98 platforms before registry or palette
operations. It accepts only no arguments or an exact, unquoted `/restore` token;
extra arguments, quoted options and trailing garbage are rejected. `/restore`
opens no UI, writes no registry values, and exits nonzero with an
`OutputDebugStringA` diagnostic on failure. An external guest observer/debugger
must capture that exit/diagnostic; HKCU Run alone is not an observed exit receipt.

## Saved profile and startup

The sole profile value is
`HKCU\Software\ShizukuOS\Theme\Profile` (`REG_BINARY`). Its v1 record is exactly
224 bytes, derived as a 24-byte header plus two 25-color arrays of 32-bit COLORREFs:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | `SHZCLR1` followed by NUL |
| 8 | 4 | Little-endian version 1 |
| 12 | 4 | Exact record length 224 |
| 16 | 4 | Style 0=Classic, 1=ShizukuOS |
| 20 | 4 | Exact color count 25 |
| 24 | 100 | Captured Classic baseline, indices 0..24 |
| 124 | 100 | Selected palette, same indices |

Every color must have a zero high byte. Classic selected colors must equal the
saved baseline; ShizukuOS selected colors must match the compiled palette.
Malformed length/type/header/style/count or out-of-range/inconsistent colors fail
validation. This is format validation, not cryptographic integrity or detection
of every otherwise-valid edit to a baseline RGB value.

Opening the UI with no stored record explicitly captures the current native
palette as the Classic baseline, without applying or saving anything. An invalid
or unreadable existing record disables selection without capturing a replacement
baseline or writing colors. Apply revalidates the actual stored profile; an
existing valid baseline takes precedence over the current session's palette.
Thus returning to Classic cannot silently save the ShizukuOS colors as Classic.
Missing or invalid profiles make `/restore` fail **before any palette writes**.

Successful selection also registers only
`HKCU\Software\Microsoft\Windows\CurrentVersion\Run\ShizukuOSTheme` as `REG_SZ`:
`"<actual executable path>" /restore`. `GetModuleFileNameA` must return a complete
local absolute path; quotes/control characters are refused. The entire command,
including NUL, is limited to 260 bytes. A 248-byte path fits; 249 or more does not.
Existing Run values are snapshotted completely up to 512 bytes, with their exact
`REG_SZ` or `REG_EXPAND_SZ` type; wrong types, missing/embedded NULs and oversized
values fail before mutations. Old expandable strings are never expanded or run
by this component.

These limits follow the documented
[Run command bound](https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).
[SetSysColors](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setsyscolors)
provides system color notifications and repainting but changes only the current
session, so saved-profile restoration is essential. Native Win98 API admission
comes from the pinned OEM export inventory, not the current documentation's
supported-platform table.

## Transaction and failure behavior

A named Win98 mutex without a `Global\` prefix serializes this component's
instances. UI reads/selections fail promptly if the mutex is busy; a windowless
startup restore may wait up to five seconds. UI threads never wait on the mutex
while a peer may be broadcasting to their windows. An abandoned mutex is refused
and disables that instance until it closes.
Synchronous `WM_SYSCOLORCHANGE` handling posts an asynchronous status refresh,
avoiding a second selector waiting for that mutex during `SetSysColors`' broadcast.
If a queued refresh arrives before the sender releases the mutex, the UI retries
the read every 250 ms without waiting. A successful read cancels the retry;
invalid or unreadable profiles disable selection without a retry loop. The
selector uses a window-owned timer, while personalization uses its existing
preview timer. Closing the window ends retries. No retry applies a palette or
writes a profile automatically.

Before writes, apply snapshots the complete old profile, old Run value and current
native palette. It applies/readbacks colors, writes/flushes/readbacks the whole
profile, then writes/flushes/readbacks the complete startup value. A failed call
is treated as potentially having already changed state. Rollback attempts Run,
profile and palette restoration independently, with exact readbacks; previously
missing values are deleted rather than replaced with invented defaults. Rollback
failure is distinct from a recovered failure and reports a color/profile/Run bit
mask plus the first rollback error. New empty registry keys may remain; unrelated
values and keys are never removed.

This is checked compensating rollback, not an atomic multi-resource or
power-loss transaction. `RegFlushKey`/readback success does not substitute for
real cold-boot persistence checks. Changes made by unrelated applications or a
registry editor are outside this component's mutex.

## Source, build and acceptance

`selector_core.c` is the shared production codec/transaction; its callbacks are
real OS side-effect boundaries. `native_backend.c` supplies native ANSI USER32,
ADVAPI32 and KERNEL32 calls, complete registry reads, platform/path admission,
baseline capture and mutex coordination. Both `selector_win98.c` and installed
personalization `SHZPERS.EXE` use that same backend. The latter has its own exact
`/restore` entry, so selecting its theme needs no separate installed executable.
The last successful explicit selection records the selecting executable's
actual path in the shared Run value.

A failed mutex release also disables that instance and reports failure even if
changes were already made; mutation flags remain available and the UI does not
call that situation a pre-write refusal. `selector_win98.c` retains its
freestanding `mainCRTStartup` entry. Link the
existing `platform/freestanding/memory.c` for compiler-emitted memory operations;
no native CRT, heap allocation or stdio is required. `selector_core_test.c` uses
host stdio only and never touches a host registry or system palette.

Run `python3 -B ntwddm/win98/theme_selector/build.py` from the repository root
with installed Clang, i686 MinGW and pefile. Its existing 20 GiB free-space
reserve and 8 MiB owned output bound remain in effect. The build runs normal
and ASan/UBSan tests for the real shared transaction and native backend,
then compiles the actual i486 Win98 GUI executable and checks its OEM named
imports and relocations. A source-bound receipt records the observed scope;
none of these host or compiler results proves native Windows execution.
Tests cover the real shared codec, unsafe commands and full Run boundary,
unreadable/invalid snapshots with no writes, baseline retention, every mutation
phase including partially effective failures, previous absent/present registry
values, separate rollback failures, and restore without registry writes.

Required later acceptance:

1. Fresh source-bound normal and ASan/UBSan host tests; a complete i486 PE32,
   Win98-only named-import/relocation gate against the pinned native inventory.
2. A fresh owned Windows98 guest: select both buttons manually; independently
   read every actual system color, complete profile bytes/type and quoted Run
   bytes/type. Observe Explorer/desktop and a second native process's caption,
   menu and standard controls, including repaint after closing the selector.
3. Prove failed snapshot/invalid-profile cases perform no color writes, and
   inject actual palette/profile/Run failures to check all rollback results.
   Mocked OS callbacks do not prove native registry failure semantics.
4. Two cold boots with the selected saved profile and external observation of
   `/restore`'s actual exit, then Classic restoration and another exact readback.
5. Keep complete-raster, process-local-provider integration, requested modern
   applications and ShizukuDOS-based actual Win98 boot as separate acceptance
   gates. A system palette switch does not satisfy all of them.

All guest execution remains subject to the unchanged 20 GiB free-space reserve,
256 MiB private-COW growth and combined 16 MiB host-output guards. Preserve historical
native theme results and rebuild any newly changed provider from its actual source;
do not rebind cached historical binaries to a new commit.
