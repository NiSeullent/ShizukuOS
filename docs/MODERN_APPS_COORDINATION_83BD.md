# Mandatory modern applications: continuation ownership

On 2026-10-01 the user replaced the direct Chromium full-source-build task
with Zetscape, a much lighter browser that must run on general Win98SE and
use hardware acceleration on Shizuku Edition. The modern-web target remains
mandatory and has not been verified. Legcord/Discord, current open-source
Office, and Steam must still actually work, with source ports and suitable
modern libraries.
These requirements extend the original Windows 98 IO.SYS/GOP and IE/WebKit
work; none is replaced by a standalone companion operating system.

## Concurrent source ownership

| Lane | New files owned by this continuation | Purpose |
| --- | --- | --- |
| Zetscape | `apps/zetscape/` | Root owns the native host/build/ABI; the fixture agent owns `tests/` and `fixtures/`; genuine shared WebKit provider remains required |
| Chromium and Legcord | `tools/modern_apps/chromium*`, `tools/modern_apps/legcord*`, `docs/MODERN_BROWSER_PORT_83BD.md` | Current product/source pins, reuse existing app preflight and m98 APIs, real missing process-local address wait/wake prerequisite |
| Office and Steam | `tools/modern_apps/office_steam_*` | Pinned LibreOffice SAL source port, exact patch application, current Steam requirements and hosted prerequisites |
| Genuine IE engine | `tools/iewebkit_port/` | Actual WebKit/WTF/ICU/GCC runtime and JavaScriptCore build closure |
| Native IO.SYS trial and review | `shizukudos/iosys_uefi/`, root `tools/iewebkit_wtf_*`, `tools/iewebkit_verify_wtf.py` | Windows 98 entry/GOP, private VM resource guard, real WTF initialization/thread/CRT-exit acceptance |

The main Win98 chat owns the existing GOP driver, native m98/NT wrapper work,
canonical CSM runner, app preview and release integration. The existing IE chat
owns `/home/almalinux/workspace/iewebkit`. This continuation does not overwrite
those source trees or change their VM images.

The historical Chromium input remains the already retained official x86
157.0.8080.0 snapshot 1707946 and source revision
`73c8f84d67bfbad65ad4817d9839ffecb78b06ee` in `docs/TARGET_APPS.md`.
The independently inspected Windows Stable 155 release is a secondary source
reference. These inputs are retained without modifying the other session's
target documents; they are no longer a requirement to build a full Chromium
tree in this continuation. Chromium/Electron prerequisites can still matter
for the independent Legcord and Steam work.

The browser lane now binds that active input and source identity. Its address
wait/wake source and native probe built with the existing MinGW compiler,
warnings treated as errors, into an i386 PE32 with OS/subsystem 4.0. All 66
ordinary/delay import rows match the real Win98 export baseline. The private
output tree is 113,836 bytes, within the explicitly bounded 8 MiB compile
allowance. This source/static checkpoint is not native prerequisite execution
or Chromium startup. The final source receipt also binds eight Python controls
and Node entry/runtime/lease lifetime checks; see `docs/MODERN_BROWSER_PORT_83BD.md`.

The actual Legcord entry bootstrap requires a native source-read lease before
hashing/importing its entry. A cancellable `will-quit` event cannot release
the lease; cleanup waits for process exit. The C lease implementation exists,
but its native Node/Electron binding, Win98 filesystem behavior and complete
application-tree provenance still require integration and execution. Address
wait/wake calls must use one shared provider per process; separate static
copies across DLLs are not a cross-module implementation.

## Required actual acceptance

Each application must run from a cold-booted Windows 98 instance using the
selected execution layer and actual GOP desktop. Retain the exact app/source
and library hashes, fresh trial identity, screenshots and independent native
readbacks. A standalone Kernel64 run is evidence for that kernel only.

* Zetscape: real shared WebCore/JSC provider, rendered page, actual DOM/JS,
  modules, keyboard input and clean lifecycle on general Win98SE; exact
  network/TLS/origin/storage/media/full-target coverage. Shizuku additionally
  requires actual initialized graphics driver, device submission/completion,
  readback and native presentation. The small fixture subset or GPU metadata
  cannot certify 100% modern web or acceleration.
* Legcord: actual Electron/Legcord renderer and Discord UI, user interaction,
  session/network operation where authorized, and clean restart/exit. An
  Electron import audit alone does not establish Discord functionality.
* Office: actual current Writer/Calc or corresponding selected Office programs,
  editing and calculation, save, cold reopen and clean exit with contents
  verified. A SAL clock patch is one prerequisite only.
* Steam: actual current Valve Windows payload, hosted window/input bridge,
  network/TLS and client UI/restart. Any authenticated operations require an
  available authorized account/session. Public Linux steam-runtime source is
  not the proprietary Windows Steam client.

Missing implementations, unsupported errors, version emulation, helper UIs,
symbol exports and host tests cannot be counted as application success.

## Resource boundary and latest native evidence

The unchanged native runner requires at least 20 GiB free space and an
independent bounded private-disk growth quota. On 2026-09-30, shared host
writes consumed that headroom. No other mounted workspace disk had suitable
free capacity. Heavy builds, new guest trials and cache mutations are held
until their existing guards pass. Bounded new source/review edits remain
permitted; the native disk guard is not a source-editing ban.

Native trial j stopped in preparation, before QEMU. Native trial k booted real
Windows 98 to its GOP desktop, then stopped at the host reserve floor before
the WTF observer command was submitted. Its native aggregate remains FAIL:
nine entry checks passed and `emulator_healthy` failed after the owned abort.
The original IO.SYS and frozen/source artifacts remained unchanged. WTF v5
initialization and post-CRT exit remain NOT_TESTED; this is not a measured v5
runtime regression.

The independently reviewed k records are:

* `result.json`: `03d0f975e475ea667ee5abd13123c7d8a97d6320ffbf7cbc924012e93e589da0`.
* `iosys-entry-result.json`: `79006603b66bbf18c2eddc176238a5ce91a876284ad1ffe55887932ae50274c4`.
* `native-runtime-classification-review.json`: `1f297d153b129e1770b8e2bbcbfc812d96dd402951afae83eafc8290a8ff1172`.

They reside under
`build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-v5-83bd-20260930k/`.

## Shorter owned WTF control sequence

`tools/iewebkit_wtf_control.py` completes the observer control sequence after
an operator reviews a native boot-warning or desktop screenshot. It checks
the exact frozen manifest against the already injected guest-file plan,
QEMU executable/owner/start identity, exact private guest disk/device, approved
firmware flash drives and absent NIC. It locks out other cooperating drivers,
refuses a pending GUI request, and verifies the full submitted request and
acknowledgement identity to detect another writer. It submits only the fixed
WTFWAIT command. The new `--launch-only` option returns after acknowledgement
for screenshot-driven diagnostic observation and error-dialog handling before
the operator finishes the owned guest. The legacy fixed host delay does not
prove the same elapsed guest seconds while resource sampling pauses its CPUs.

It does not launch or kill a VM, read a live guest filesystem, or certify
application behavior. Its acknowledgements require final stopped-disk
validation with `tools/iewebkit_verify_wtf.py`. The original six host rejection
controls passed and the controller was used in trial l. Seven current controls
also validate the exact closed-checkpoint abort diagnostic scope. This reduces
input latency without converting queued keyboard input into runtime success.

## Source and provenance checkpoints

The Office lane has applied the exact opt-in clock patch to a private copy of
LibreOffice tag `libreoffice-26.8.0.3`'s genuine SAL source. Its 18 host controls
check bounded PE inventories, patch identity and fresh ODF artifact challenges;
no Office program was compiled or executed. The saved-artifact checker always
requires independent process/display/reopen evidence and cannot promote file
contents or self-reported generator metadata to a native application PASS.

The genuine JavaScriptCore pipeline now binds configuration, pre/post build
and C API linkage to its effective source/runtime/allocator profile. Seven
read-only graph rejection controls passed, and attempting to link the actual
incomplete core was refused before output creation. The retained partial build
was intentionally interrupted at 19/88; it has no JavaScriptCore link or
runtime success. The future link now checks compiler-selected startup/runtime
and platform archive inputs, binds loaded helper code to the reviewed bytes,
and rechecks the freshly generated `JSCNAT.o` before and after linkage. The
actual caller's source/header closure must come from a bounded compiler `-M`
query and match the later compilation's `-MD` dependencies. This includes
generated public headers which were absent from the earlier upstream graph.
Seven helper/header controls and eleven driver-selection controls passed.
These source changes have not run a real compiler dependency query or link;
the old partial build needs regeneration using the current paired runtime.

The final bounded checkpoint is
`build/iewebkit-core-83bd/jsc-source-checkpoint-20260930-v2.json`, SHA-256
`30ce9225748bc630305bb440a603779ef7e9df46279be32fbcfb5c0e8a173707`.
It binds eight source files and records the host-control scope explicitly.

Frozen WTF v5 retains exact PE bytes, genuine 177 WTF and 168 bmalloc members,
paired runtime source/object evidence and complete native import inventory.
Those existing receipts do not cover every compiler-selected implicit
platform archive. Do not describe them as full toolchain-source closure or as
native execution. The owned observer and real stopped guest log remain
mandatory for any future bounded WTF runtime acceptance.

## Final continuation integration check

`build/modern-apps-integration-83bd-source-checkpoint.json` independently
rehashes the browser, Office/Steam and genuine JSC source inputs against their
lane receipts, plus the browser prerequisite PE, root controller, stopped
native-trial records and frozen WTF manifest. It records current resource
availability separately from the retained historical checks. It does not
turn any component or host-control result into application acceptance.

Zetscape, Legcord/Discord, LibreOffice, Steam and actual IE/WebKit document
rendering remain unverified on Windows 98. Free space below the unchanged
20 GiB native floor blocks a new guest trial; upstream application builds also
need a suitable larger workspace. Source ports, real module/process/display
integration, network/TLS, and app-specific interactive trials remain required
after resources are available.

## October 1 actual continuation

Trial l cold-booted the real original IO.SYS Windows98 GOP desktop; its ten
entry checks passed. It launched the retained genuine WTF v5 caller and showed
an abnormal-program-termination dialog. Stopped WTF and observer log lengths
were both zero. The actual failure is observed; the last reached phase and
post-CRT exit remain unknown. It cannot be counted as rendering or app PASS.
`native-runtime-classification-review.json` under trial l records that scope.

The diagnostic caller closes every native checkpoint and adds a separately
closed direct GNU/COFF abort return-PC record. Actual final diagnostic v4
links the unchanged 177 WTF and 168 bmalloc members, native ICU and runtime;
its abort routing was checked in actual COFF disassembly. The earlier guarded
compile interruption and failed wrapper-name link remain separate artifacts.
Legcord's real header-derived Node-API source adapter now exists and passed
actual MinGW syntax/header and bounded host lifetime controls. It is not a
built addon or an executed Electron/Discord application.

The dedicated disk lane reclaimed 8,519,680 bytes of physical mapped data
through reviewed full-range deduplication. It preserved the pinned input
bytes and historical receipts. Larger host free-space swings came from
concurrent activity, not this optimization. No peer data was deleted.

Zetscape's current real native host PE built at 77,872 bytes with 77 imports
matching the actual media baseline after nested-message lifetime fixes.
The historical first artifact was 76,803 bytes. Its real shared provider,
full browser deployment weight, actual ordinary98SE browsing and Shizuku
GPU acceptance are still unfinished. The current source and independent
representative page fixture are under `apps/zetscape/`.

Trial m's ten original IO.SYS entry checks passed. It reached the GOP driver's
initialization, but both reviewed QMP and physical framebuffer captures were
black and all three selected diagnostic logs were absent after stopping.
The controller had advanced from the boot warning by a fixed timer; its
acknowledged launch request therefore establishes no native caller execution.
`native-runtime-classification-review.json` under m records that failure.
The revised controller now acknowledges a warning, closes a reviewed welcome,
opens Run from a reviewed desktop, or launches from a reviewed Run dialog in
separate invocations. It never advances these stages from a timer; eight
host boundary controls passed. Trial n uses fresh diagnostic fixture r3 and
retains the same 20 GiB floor, 128 MiB dirty budget and native firmware inputs.

The Steam lane has actual x86 socket and owned-child observer executables and
a separately reviewed, bounded controller. It has not executed the Windows
Steam client or passed a native socket trial. Integration checkpoint v1
rechecked 279 then-current source/provenance inputs without drift; it predates
the later stage-control source change and is preserved as historical evidence.
