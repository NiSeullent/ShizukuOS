# Latest Office and Steam on Windows 98: source and acceptance lane

This lane changes one genuine LibreOffice prerequisite and supplies bounded
application inventory and saved-artifact checks. It has not built or launched
LibreOffice or Steam on Windows 98. A helper, imported address, version string,
host Wine run or standalone Kernel64 boot is insufficient application evidence.

## Exact LibreOffice source port

On 2026-09-30 the [official download page](https://www.libreoffice.org/download/)
identifies LibreOffice 26.8.0 as its latest stable release and offers Windows
x86-64 and ARM64 downloads. Its [Windows requirements](https://www.libreoffice.org/system-requirements/)
start at Windows Server 2012 / Windows 10. The selected source is the actual
`libreoffice-26.8.0.3` tag, annotated object
`cf55f45554a356e77e7977c6a28679069017157f`, commit
`bce0998afefdbc355585ca324285661a2170ba77`.
The [official LibreOffice GitHub mirror tag metadata](https://api.github.com/repos/LibreOffice/core/git/tags/cf55f45554a356e77e7977c6a28679069017157f)
reports an unknown signing key. This lane pins commit and source bytes; it does
not claim independent signature verification.

`office_steam_upstream_time.cxx` preserves the exact 5,739-byte
[SAL source](https://raw.githubusercontent.com/LibreOffice/core/bce0998afefdbc355585ca324285661a2170ba77/sal/osl/w32/time.cxx),
including its MPL 2.0 and Apache 2.0 notices. SHA-256:
`ac98127a763ab1214b606ea29e0ec842e3529c2e39392c1d7025533a4bbcf851`.

`office_steam_sal_clock.patch` adds `LIBO_WIN98=1` around the actual wall-clock
call. That branch uses real `GetSystemTimeAsFileTime`; the ordinary Windows
branch retains the original `GetSystemTimePreciseAsFileTime` call. It keeps SAL's
UTC FILETIME epoch and conversion code. The resolution is the native operating
system's resolution, with no claim of microsecond accuracy on Windows 98. Wall
clock adjustments can move this value backward, so it must not replace a
monotonic timeout clock. The [Microsoft contract](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimeasfiletime)
defines UTC FILETIME semantics; its current minimum-support table alone is not
evidence of an API's native Win98 behavior. A separate genuine SAL build and
Win98 execution must establish that behavior.

The exact modified source SHA-256 is
`7c0e2c3b28bacbb3a21a1e0447a8ee1571676725d3e4063132c7909f61d8375e`.
Apply only in a private source tree:

```text
python3 -B tools/modern_apps/office_steam_sal_clock.py PRIVATE_LIBREOFFICE_TREE --check
python3 -B tools/modern_apps/office_steam_sal_clock.py PRIVATE_LIBREOFFICE_TREE
```

The tool validates preserved original, reviewed diff and replacement hashes,
refuses different source revisions, symlink ancestors and hardlinks, preserves
permissions and atomically replaces only `sal/osl/w32/time.cxx`. Repeating it
does not rewrite the file. Activating the branch on the actual SAL compile rule,
auditing its imports, and compiling ordinary-Windows controls remain required.
The whole suite still needs real Unicode, process, security, C++ lifetime,
UNO/VCL, rendering and dependency work. The source patch alone cannot establish
Writer or Calc compatibility.

## Steam source and existing runtime boundary

[Valve's current support statement](https://help.steampowered.com/en/faqs/view/49A1-B944-48B8-FF00)
ends 32-bit Windows support on 2026-01-01 and states that future clients require
64-bit Windows. A retained old 32-bit client without updates cannot establish
that the current client operates. An exact current Windows build has not been
downloaded or inspected in this lane; its version is intentionally unpinned.

The public [Steam Runtime](https://github.com/ValveSoftware/steam-runtime) is a
Linux library/container stack. [steam-for-linux](https://github.com/ValveSoftware/steam-for-linux)
is an issue tracker. Neither supplies the actual Windows client source or a
replacement Windows client. [Valve's Steamworks documentation](https://partner.steamgames.com/doc/sdk/api)
requires the real Steam client to supply its interfaces and describes its
client-engine IPC and backend connection. An SDK sample alone cannot substitute
for a client login, library, download and game-launch trial.

Read-only inspection of the existing repository found these prerequisites:

| Existing code | Observed boundary | Consequence for an actual trial |
| --- | --- | --- |
| `shizukudos/kernel64/gfx_wm.c:8`, `gfx_fb.c:198` | Display initialization is gated by `SHZ_STANDALONE`; other profiles return `STATUS_NO_SUCH_DEVICE`. | Standalone GUI results do not prove a GUI hosted by Windows 98. |
| `shizukudos/kernel64/subsys64.c`, `handle_query` | Bridge capabilities advertise create, console input/output, kill and pool arguments. | Native Win98 window/surface/input lifetime requires additional transport and integration. |
| `ntwrapper/vxd/bridge.c`, `w64_open` | Requires a real Supervisor and Kernel64 peer channel; refuses unavailable hypervisor/channel. | The native bridge and its lifecycle must succeed in the actual Win98 boot path. |
| `shizukudos/win64/dlls/winhttp/winhttp.c` | Request send/receive/read/write lack an HTTP engine and fail explicitly. | If actual selected client imports use those services, real implementations are required. |
| `shizukudos/win64/dlls/secur32/secur32.c` | Authentication packages / LSA are unavailable. | Actual client use and bundled TLS alternatives must be measured from the real payload. |

These are inspected source boundaries, not observed Steam crashes. Which APIs
the current client actually requires remains subject to original-binary
inventory and execution. Existing TCP/DNS/DHCP code is not complete client TLS,
authentication or Steam IPC proof. This lane does not edit those owned modules.

## Application inventory and Office acceptance artifacts

```text
python3 -B tools/modern_apps/office_steam_preflight.py --app libreoffice --root ACTUAL_SUITE
python3 -B tools/modern_apps/office_steam_preflight.py --app steam --root ACTUAL_CLIENT
```

The read-only inventory requires the real launcher/application components,
including Steam's web helper. It hashes each immutable snapshot and reports
ordinary **and delay** imports for PE32 and PE32+. It refuses malformed bounded
tables, escaping/symlink paths and ambiguous component locations. Use explicit
`--component ROLE=relative/path` when the real deployment contains alternatives.
It reports structural stock-loader blockers while leaving import semantics,
complete dependency closure and native execution unverified.

```text
python3 -B tools/modern_apps/office_steam_acceptance.py inputs --out NEW_INPUT_DIRECTORY --nonce FRESH_16_TO_96_CHARACTER_NONCE
python3 -B tools/modern_apps/office_steam_acceptance.py office-artifacts --writer SAVED.ODT --calc SAVED.ODS --nonce SAME_FRESH_NONCE
```

Open the generated FODT and FODS in actual Writer and Calc. In Writer, replace
the instructed paragraph with exactly `EDIT-SAVED`, save as ODT and reopen it.
In Calc, recalculate the preserved SUM formula to 42, save as ODS and reopen it.
The checker inspects nonce, Unicode, the requested edit, the exact retained
formula/result and pinned-version generator metadata without extracting ZIP
members. The input formula deliberately caches zero so stale unchanged input
does not pass. Metadata is explicitly self-reported, and even a consistent
saved artifact reports `native_application_passed=false`: files cannot prove
their generating process, operating system, GUI, reopen operation or clean
exit. Parent-owned native process/GOP evidence must establish those separately.

The Steam acceptance operations in `office_steam_profiles.json` require actual
current-client update/server connection, real user login/library, a user's
owned test game and genuine Steamworks callbacks. No credentials, login tokens,
network services or account state are created or changed by these tools.

Host rejection controls:

```text
python3 -B tools/modern_apps/office_steam_test.py
```

The controls use temporary synthetic PE/ODF inputs and exact copies of the
genuine SAL file. They prove the tools' bounded behavior and refusal to promote
fixtures into application success; they are not native application tests.
