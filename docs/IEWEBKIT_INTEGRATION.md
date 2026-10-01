# IEWebkit in the installed Windows 98 guest

The consuming guest is **Windows 98 SE 4.10.2222, x86, classic mode, Internet
Explorer 5.00.2614.3500**. The installed `IEXPLORE.EXE` and `SHDOCVW.DLL` both
identify that version. Windows ME / IE5.5 evidence does not certify this target.

The independent source checkout is `/home/almalinux/workspace/iewebkit`, remote
`https://github.com/zukuapp/IEWebkit.git`, baseline commit
`dd93262508ecec2969d3267b9d6d831d66fcd489`. Its host lifecycle, request capture
and engine portability work are being edited by another session. The integration
builder reads each selected source once and compiles a private frozen snapshot;
it changes no file in that checkout.

Its canonical `variants.json` declares IE5.5 through IE11 and no Win98/IE5.0
profile. Exact selection with `tools/variants.py select --ie 5.0 --os win98se
--arch x86 --mode classic` rejects the target with “no exact variant”. The new
builder deliberately labels the Win98/IE5.0 build experimental, compiles with
`WINVER=0x0410`, `_WIN32_WINDOWS=0x0410`, `_WIN32_WINNT=0x0400`,
`_WIN32_IE=0x0500`, and keeps release eligibility false.

## Integration tools

From `/root/Win98-Modern-boot`:

```sh
python3 -B tools/iewebkit_build_win98.py \
  --checkout /home/almalinux/workspace/iewebkit \
  --output build/iewebkit-win98-ie5-browser-83bd \
  --diagnostic-handoff
python3 -B tools/iewebkit_audit_guest.py \
  --disk build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-gui-manual/windows-uefi.raw \
  --bundle build/iewebkit-win98-ie5-83bd/bundle \
  --output build/iewebkit-win98-installed-audit-83bd
python3 -B tools/iewebkit_guest_fixture.py \
  --bundle build/iewebkit-win98-ie5-browser-83bd/bundle \
  --output build/iewebkit-win98-guest-fixture-83bd \
  --runloop build/iewebkit-win98-engine-83bd/RUNLOOP.EXE \
  --browser-handoff
python3 -B -m unittest discover -s tools -p 'iewebkit_test_integration.py' -v
```

Existing output directories are rejected. Use a new name for a new run.

The builder produces the normal engine-gated `iewebkit-host.dll` and
`iewebkit-navigation.dll`, plus native target, COM lifecycle, moniker binding
and VARIANT probes. `--diagnostic-handoff` additionally builds separately named
`IEWKHOST.DLL` / `NAVBHO.DLL`. Those diagnostics permit entering the real
DocObject without an available provider; view activation still fails without
the engine. The normal adapter retains its complete-provider check.

`IETARGET.EXE` checks the actual Win98 platform/build and the installed
IEXPLORE/SHDOCVW version resources, then loads only adjacent
`iewebkit-engine.dll` using the existing engine loader. Exit 4 is a target
mismatch; exit 3 is an absent/incomplete provider; exit 0 means the target and
provider ABI checks passed. None of these exits certifies rendered content.

The installed-import audit opens the source disk read-only, copies only imported
system DLLs to a private build folder, and compares every named and ordinal
import with their actual exports. Media-baseline presence and installed-module
presence are recorded separately from callable API behavior.

The guest-fixture tool binds its copied executables to the build receipt and a
fresh nonce. All manifest inputs and returned outputs are bounded GOPLAB files.
The original COM probes write fresh logs in `C:\ZUKUQA`; the batch copies those
logs to GOPLAB for receipt-bound readback. Optional browser handoff registers
only the diagnostic DocObject/BHO in the disposable clone, launches the actual
installed `IEXPLORE.EXE` at its remote HTTPS moniker, and provides
`RUNIE.BAT cleanup` to unregister both after closing IE. It changes no global
HTTP/HTTPS association and performs no network request in the offline guest.

## Current measured gates

`build/iewebkit-win98-ie5-83bd/build.json` records six linked x86 PE32 images,
PE OS/subsystem version 4.0, with all imports present in the pinned Win98 SE
Korean OEM media export baseline. The same six images also pass the actual
installed-system export comparison in
`build/iewebkit-win98-installed-audit-83bd/installed-imports.json`.

`build/iewebkit-win98-ie5-browser-83bd/build.json` records the separately built
offline diagnostic DLLs and their exact source/artifact hashes. The thirteen
integration boundary tests pass: changed binaries, a substituted ME target,
oversized fixtures, reused outputs and ambiguous MBR partitions are rejected;
source bytes remain unchanged. Returned-log tampering, a substituted runtime
ME version and a failed owned QEMU shutdown also fail verification. Unicode
probe source changes fail its build-receipt binding, and a skipped wide-window
creation remains unverified rather than being reported as a failed call.

The actual native guest experiment is isolated at
`build/shizukudos/csm/run-win98-uefi-83bd-ie-native-diagnostics`.
`iewebkit-native-review-v2.json` binds the run receipt, fresh nonce, executable
digests and returned log digests. Its five native diagnostic groups pass:

| Gate | Fresh returned evidence | Result |
|---|---|---|
| Exact installed target | `guest-output-IETARGET.LOG`, SHA-256 `803aab1255215f5919dcfbe7af5debc76acc87c28a4d7a34de4253f2f386d633` | Actual Win98 SE 4.10.2222 / IE5.0.2614.3500; provider status -2 (absent) |
| DocObject ownership | `guest-output-HOSTTEST.LOG`, SHA-256 `ec40376390929dea0da517182e314151c9f96dbdf497246505b3910f2e1e3003` | Site replacement, reference lifetime, null rectangles and reentrant teardown pass |
| URLMon / moniker | `guest-output-NAVTEST.LOG`, SHA-256 `4dd20fcc744fabb92ccff9519262a2c38af865c3e0eab570724c2cfa22885596` | Two remote monikers retain their exact URLs through actual binding, explicit Load and GetCurMoniker |
| Request values | `guest-output-NAVVALUE.LOG`, SHA-256 `ffcd16426976bebdcc31cb2554fd72d3f60a3e5d7bad64e26648db66db3ad53e` | Nested values, cyclic rejection, nonempty-header and POST rejection pass |
| RunLoop helper | `guest-output-RL9X.LOG`, SHA-256 `d78ac2bc2afd0d6b696af65cb581b8eb17360e25902c8aff99f1b81892823385` | Hidden context, 96 worker messages, timer, destruction and quit-code 37 pass; exit 0 |

The tested RunLoop executable is specifically the frozen
`build/iewebkit-win98-engine-83bd/RUNLOOP.EXE`, SHA-256
`7526fbbcae8cd12ea90f523c943b63e14ffeec25349b4accd660004e8c8d34d8`.
A later durable-source rebuild has a different binary digest and must receive
its own guest evidence. The test fixture's `full_engine=0` remains explicit.

The visible Microsoft IE trial reached its first Internet Connection Wizard
and was stopped within the bounded run. Browser-driven DocObject activation
and diagnostic unregistration were **not verified**; `IENAV.LOG` and
`IEUNREG.TXT` were not returned. The disposable disk retains that interrupted
diagnostic state. It must not serve as a clean installed-browser baseline.
The owned QEMU process exited with code 0. Graceful Windows shutdown was not
established. The runner verified the source raw disk, archived checkpoint and
original firmware templates unchanged; the experiment used new variables.

The receipt can be reproduced without starting a guest:

```sh
python3 -B tools/iewebkit_verify_guest.py \
  --run build/shizukudos/csm/run-win98-uefi-83bd-ie-native-diagnostics \
  --manifest build/iewebkit-win98-guest-fixture-83bd/guest-files.json \
  --output /absolute/new/private/iewebkit-native-review.json
```

## Engine connection and remaining work

The provider seam remains the independent C ABI in `include/engine.h`:
`IEWebKitGetEngineV1` from adjacent `iewebkit-engine.dll`. The host requires
HTML, CSS, DOM, JavaScriptCore, verified TLS and origin isolation capabilities.
An incomplete engine must not claim those bits to bypass validation.

The native Win98 WTF RunLoop port is maintained under `tools/iewebkit_port/`.
The pinned WebKit 2.54.0 original and patched `RunLoopWin.cpp` translation
units both compile against the actual WTF and ICU headers. The frozen receipt
`build/iewebkit-core-83bd/focused-runloop/objects-verified.json`, SHA-256
`ba876d6305ff95f8bc680d7edc87c0dde6e6508811cca82294069bc87d56e808`,
records original object SHA-256
`9465e900e78bd807b2109836b50cb88acb9d948a9c1aaac29081c5b6f36bb714`
and ported object SHA-256
`0f63d52dc6850cc28a8118859237813ba1694bc874e021c5c23518313d7c3966`.
The genuine Generic-layout negative compile fails as expected; the Windows
layout is required. Object compilation does not prove a linked WTF archive,
JavaScriptCore execution, full callback semantics or an engine provider.

The native countercheck **created a window with HWND_MESSAGE successfully**
(`created=1`, `error=0`). It used `CreateWindowExA` and does not prove the
upstream Unicode/generic-window path works. Do not state that Win98 always
rejects HWND_MESSAGE.

A second cold private clone at
`build/shizukudos/csm/run-win98-uefi-83bd-ie-unicode-compare` ran the focused
wide/ANSI API comparison without starting IE or registering a component.
`iewebkit-unicode-review.json` binds the selected source, build receipt,
binary, fixture nonce, unchanged original sources and fresh returned logs.
The installed target again reports Win98 SE 4.10.2222 / IE5.0.2614.3500.
`RegisterClassW` returns atom 0 / error 120 (`ERROR_CALL_NOT_IMPLEMENTED`).
The fixture therefore skips `CreateWindowExW`; its independent behavior is
not established. The shared ANSI port registers its class with error 0,
creates the hidden window, preserves the context and receives `WM_CREATE`,
then exits 0. This measures the Unicode registration seam directly.

The second run binds `RLCMP.EXE` SHA-256
`de2c9f41f2e00be3bda35265a7b05096e6d7b3f36cbf3346c382f7d5d969736a`
to `tools/iewebkit_port/core_unicode_native.c` SHA-256
`3e12d2baaeb47e54f4a893e5b9d68b8e5d5d530669f61bdbd0455b49dfbec76b`.
Fresh `guest-output-RLCMP.LOG` SHA-256 is
`ac47c37e0a245106121fb89a0852a382659b7fb88d7da9e9864e6af3d25cac8a`;
fresh `guest-output-IETARGET.LOG` SHA-256 is
`54f03262f64b45620f5888904d4584d15852f7cbde427b458a1015ced3eb5795`.
The fixture SHA-256 is
`b14ba89febee43a874aa2a0f787b660eebeca3de3ad659c75335cb4a76ddaf92`.
The VM used no NIC and exited with QEMU code 0 after its 300-second bound;
graceful Windows shutdown was not established. Both integration-owned VMs
are stopped. Other sessions' VMs were left alone.

The second receipt can also be reproduced without starting a guest:

```sh
python3 -B tools/iewebkit_verify_unicode.py \
  --run build/shizukudos/csm/run-win98-uefi-83bd-ie-unicode-compare \
  --manifest build/iewebkit-win98-unicode-fixture-83bd/guest-files.json \
  --probe-receipt build/iewebkit-core-83bd/focused-runloop/RLCMP.receipt.json \
  --probe-source tools/iewebkit_port/core_unicode_native.c \
  --output /absolute/new/private/iewebkit-unicode-review.json
```

No complete WebKit provider is currently included. Actual rendering, DOM/JS,
TLS date/hostname/CA validation, origin isolation, Korean input, forms/POST
headers, browser history and teardown remain separate exact-target guest
gates. The existing Shizuku Wine-based browser and Kernel64 JSC work use a
different host/runtime and do not prove Microsoft IE integration on Win98.

Microsoft binaries, guest disks and returned private artifacts stay under
ignored build directories and must not be distributed with this source.
## Later original IO.SYS / GOP integration

The cold root `win98-iosys-gop-ie-gui-83bd-20260930g` trial runs the exact
Windows 98 SE 4.10.2222 / IE 5.0.2614.3500 target through the original IO.SYS
entry port and GOP driver. The independent GUI memory probe passes actual
2 MiB allocation, access, release and accounting recovery with fresh nonce and
four digest-bound provenance fields. It needs no DOS console.

The actual IE local server is created and shown; its BHO arms the intercepted
GET and the custom DocObject reaches its genuine show/engine-missing path.
IE shutdown, component unregisters, private key removal and exact wizard-value
restoration pass. The document URL acceptance fails with native exit 29 because
IPersistMoniker Load and its remote-HTTPS trace are not reached. The diagnostic
Show rejects the absent engine before that later callback. Do not promote the
successful BHO/DocObject activation or the emulator-health exit 0 to rendering
or complete URL-ingress success.

See the hash-bound
[integration review](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-ie-gui-83bd-20260930g/integration-review.json)
and the visually reviewed
[physical GOP desktop](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-ie-gui-83bd-20260930g/screen-044-physical-gop.png).
All original media, original IO.SYS and the cold source disk remain unchanged.
Full engine/provider, JavaScript, TLS and WebKit page rendering remain unverified.

## Actual protocol ingress and genuine WTF startup in trial i

The later cold `win98-iosys-gop-wtf-protocol-83bd-20260930i` trial again
boots original Windows 98 through the IO.SYS entry port and GOP driver.
All ten IO.SYS entry checks pass. The diagnostic host is a private, pinned
snapshot; the peer-owned canonical IEWebkit checkout remains untouched.

The actual installed IE5 successfully supplies the fresh intercepted GET to
the URLMon protocol component. Exactly one handoff retains its URL and nonce,
uses the same attached thread and pending request, and obtains real
`GetBindInfo` success. GET verb 0, zero body bytes and `TYMED_NULL` satisfy
the measured eligibility gate. Pending state is cleared before the successful
custom CLSID, MIME and data-report callbacks. This bounded protocol ingress
component passes; it does not assert that IE completed the page bind.
The report is explicitly aborted, with completion and success both false.

The complete IE acceptance remains **FAIL(29)**. Show reaches
`engine_missing`, and neither `IPersistMoniker::Load` nor the remote-HTTPS
Load trace is present. The owned IE process/window closes, both diagnostic
components unregister, four private keys are absent, and the exact previous
wizard value is restored. Independent review verifies 59 hash/size bindings
and these callback/cleanup boundaries in
[independent-ie-protocol-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/independent-ie-protocol-review.json),
SHA-256 `b6302b306cbb86a761e0c48c83cf49c95b0060ea830481ff91d89ea9389152af`.

The same trial runs a genuinely linked WTF/bmalloc/ICU PE, not the earlier
standalone RunLoop helper. Frozen `WTFNAT.EXE` is 47,734,594 bytes with
SHA-256 `0554e029684dca0c43f31af30cb70adf50c3fd9f9e76931061e09f48b1fcd33c`.
Its fresh stopped-disk log proves exact-target startup and actual CryptoAPI
measurements: `CryptAcquireContextW` fails with error 120; the ANSI counterpart
and `CryptGenRandom` succeed. An earlier live FAT read returned zero bytes;
the definitive returned log contains 282 bytes and supersedes that observation.

WTF initialization fails with the actual Win98 illegal-operation dialog at
`EIP=005d2316`. Exact frozen disassembly resolves `__mi_theap_default + 6`
and `mov %fs:0(,%edx,4), %eax`. This identifies an incompatible NT TLS-layout
fast path in genuine mimalloc. The [native crash review](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/wtf-native-crash-review.json)
binds the screenshot, returned log and exact executable/disassembly; SHA-256
is `2069b089ffee1cb07ece93d65f9ea40ff6476b423ea1408a1118212046e6eee6`.
Initialization, genuine RunLoop dispatch and timers did not pass. The retained
thin-member supplement is only a post-link observation, not proof of v3 member
bytes at link time. Subsequent candidates require fresh pre/post link bindings.

The ongoing genuine-source port replaces Win9x allocator TLS access with real
`TlsGetValue`/`TlsSetValue` storage and selects the measured ANSI CryptoAPI
path. Independent review also found that winpthread destroys GCC-emulated TLS
before the allocator's late detach callback. The next candidate therefore
moves its internal allocator TLS values into lifetime-bound Win9x TLS storage
so heap abandonment precedes identity-page release. The v4 compile/import and
pre/post provenance checks passed, but it is retained as a static-only candidate
and has not been executed natively. The corrected candidate still needs its
own actual Win98 initialization, worker dispatch, timer and cleanup evidence.

Actual JavaScriptCore execution, a complete WebCore provider and visible
WebKit rendering in Microsoft IE remain outstanding. Successful protocol
ingress and API/allocator compilation do not certify those gates.

The root-owned `tools/iewebkit_wtf_runner.c` observes the actual frozen WTF
child through `CreateProcessA`, bounded waiting and `GetExitCodeProcess`.
Its separate fresh log records the OS exit after the child's CRT/TLS teardown;
the caller's earlier `exit=0` line alone is insufficient. Timeout termination
uses only the handle of the child it created. Its GUI PE passes all 66 imports
against the native export baseline, but the observer's behavior still requires
the next actual guest trial. `tools/iewebkit_wtf_runner.py` freezes it alongside
the genuine caller with exact receipts; it does not start a guest.

`tools/iewebkit_verify_wtf.py` reviews stopped outputs, exact frozen PE/receipt
bindings, genuine pre/post thin-archive snapshots, original-entry/native health
consistency, measured allocation bounds, fresh target/nonce and real WTF
initialization/dispatch/timer/monitor gates. It also requires the external
post-CRT child exit. Fourteen authored evidence controls pass, including a
successful caller log followed by a failing OS process exit. These controls
test evidence rejection, not engine execution; native runtime acceptance
remains pending until a frozen candidate returns its own fresh logs.
