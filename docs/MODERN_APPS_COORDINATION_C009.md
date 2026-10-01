# Modern application runtime coordination — chat c009

Chat `01a0f3d0-c009-7f31-baa1-a0d167a8a63e` continues the user's requirement for
Chromium, current Legcord, current open-source Office, and Steam on Windows 98
Modern. Source changes are explicitly authorized. Actual app startup and
functionality remain required; host builds or import matches are separate claims.

## Ownership and handoff

- This chat owns NEW `ntwin32/load_config/`: bounded PE32 load-configuration
  parsing, security-cookie setup and explicit mitigation prerequisites. Existing
  `ntwin32/native_loader/`, provider tables, GOP, disks and site are peer owned.
  It also owns the focused `ntwin32/prepare.py` correction and new
  `ntwin32/tests/test_prepare_zero_fill.py`: distinguish a runtime TLS index
  output in zero-filled mapped data from immutable file-backed metadata, and
  validate read-only CFG pointer storage without removing its protection.
  NEW `ntwin32/steam_socket/` contains a separately reviewed bounded decoder of
  completed Wine-provider AcceptEx output. It is a portable prerequisite, not
  a WSOCK32 export or a substitute for a real overlapped socket provider.
- Peer `01a0f3d0-cb43-7a31-8522-d2a94e7bf601` is inspecting the app/runtime corpus
  in `/root/Win98-Modern-codex-20260930` and its frozen
  `/root/Win98-Modern-apps-cb43` build. It now owns the Steam fiber implementation,
  current Steam client corpus and browser-engine packages. It can consume this
  module after review; do not duplicate its fiber or import-provider work.
- Theme/TLS peers `01a0f3d1-6970-79b3-a586-f7f0308116c0`,
  `01a0f3d1-5abe-7a11-a567-cb6c211c8496` and
  `01a0f3d1-7707-7d10-962d-26c937d2743b` retain their own files.
- Existing ownership in `PARALLEL_COORDINATION_7ACD.md` and
  `IO_SYS_UEFI_COORDINATION_83BD.md` remains authoritative for boot and guest work.

Thread tools on this host currently expose listing, reading and compact waits;
no cross-chat message tool is callable. This shared source note is the handoff
point. Do not infer that another chat has acknowledged it until its activity or
an explicit reply confirms that. Do not start a competing VM or modify peer runs.

## Immediate blocker

The native loader's `--run-runtime` profile still rejects load configuration,
delay imports, provider-backed callback threads and resources. Latest pinned
Chromium 157.0.8080.0 has such runtime metadata. This new module will validate
load-configuration contracts without changing the loader's current execution
gate or stripping mitigations from target binaries.

The focused preparation correction now passes ten host regression methods.
Both immutable official Chromium157 roots pass the in-memory prepare validator:
six TLS callbacks each,192-byte preserved Load Config, and CFG function counts
1847/944. Their original hashes remain unchanged. This removes false static
rejections only; the native execution profile still refuses unsupported runtime
features. These results are not app startup or rendering acceptance.

## Validated implementation handoff

- `ntwin32/prepare.py` plus `ntwin32/tests/test_prepare_zero_fill.py`:17 memory-only
  routing/preparation regression methods passed. Exact latest Chromium originals
  are unchanged and preparation reports keep guest/browser flags false.
- `ntwin32/load_config/`:15 host test methods passed, including both pinned real
  Chromium files. Receipt:
  `build/load-config-c009-20261001-review-v2/host-result.json`. Real LLVM metadata
  tables are packed at unaligned VAs; validation uses bytewise reads rather
  than an unjustified table-base alignment requirement. Cookie/guard write slots
  retain required alignment. SafeSEH/CFG/CastGuard integration remains required.
  The module also compiles as freestanding i486/I386 COFF with only its four
  existing `np_*` helper references. The separately compiled old PE parser has
  a compiler stack-probe reference; the combined unlinked closure is explicitly
  recorded as unresolved. No helper stub or loader change was introduced.
  Receipt:`build/load-config-c009-native-objects-20261001/compile-receipt.json`.
- `ntwin32/steam_socket/`:357 host controls passed in the normal build and again
  with Clang AddressSanitizer/UndefinedBehaviorSanitizer. A freestanding AMD64
  object also compiled. Bound source/artifact hashes and independent review are
  recorded in `ntwin32/steam_socket/VALIDATION.md`.

The source notes include pinned Wine/ReactOS comparisons and official contracts.
The failed first Load Config harness is retained in its separate `v1` output;
it is not overwritten or promoted into a successful record. No app, Win98 guest,
GUI bridge, service, client setting or production deployment was changed.

## Remaining acceptance work

Chromium needs actual provider/callback thread ingress, delay loading, module
identity/resources and mitigation integration before an original target is
admitted. Legcord additionally needs Electron/Node IPC and its actual Discord
functionality. The official current LibreOffice and Steam targets require the
64-bit execution domain and a native Win98 graphics/input bridge; independent
Kernel64 rendering is a different result. The Steam fiber owner remains the
peer apps session. Its actual socket provider must produce completed buffers
before this decoder can be adapted to its public API. No application acceptance
flag is promoted by the present host results.

## Current app baselines

The existing exact Chromium snapshot remains pinned in `TARGET_APPS.md` until a
new official package has its own metadata and hash. Legcord v1.3.0 declares
Electron43.2.0; Electron43 is the final official Windows ia32 release line.
LibreOffice26.8.0 official Windows packages are x86-64/ARM64. Steam ended support
for32-bit Windows on2026-01-01. These publisher requirements identify separate
architecture work; they do not prove any current app runs here.

Sources: [Legcord release dependencies](https://raw.githubusercontent.com/Legcord/Legcord/v1.3.0/package.json),
[Electron43](https://www.electronjs.org/blog/electron-43-0),
[LibreOffice download](https://www.libreoffice.org/download/),
[Valve architecture notice](https://help.steampowered.com/en/faqs/view/49A1-B944-48B8-FF00).

## Execution boundary

Source edits are authorized by the user's request. The original user approval
reply in chat `01a0f109-1a36-7ea2-843d-62ad65c68466` explicitly approved source
edits, local builds, isolated outputs and test execution in this worktree after
the commands and their effects were disclosed. The present request continues
that work across chats. Focused host validation stays inside these approved
effects: memory-only Python controls and newly compiled host parser tests in
unique ignored build output. No install, guest mutation, service start, download,
client-global change or reverse-skill activation is part of this module's tests.

## Continuation 2026-10-01 — disjoint active work

The user explicitly requested continuing every app lane and assigning disk
optimization to a separate agent. This chat owns the following additional paths:

- NEW `ntwin32/callback_ingress/`: persistent provider-worker admission, native
  TLS attach/detach and nested callback lifetime. No provider hooks or native
  loader execution gate are changed. Actual provider integration must retain and
  join OS worker handles before mapped images can be released.
- `ntwin32/load_config/`: explicit opt-in image/table-work budgets. The immutable
  original Chromium157 chrome.dll has267868 GFIDS and268177 total known table
  records, larger than the existing262144 per-table default. Default limits
  remain unchanged; raw parsing is distinct from mitigation enforcement.
- NEW `tools/disk_budget/`: measured immutable Wine source-cache extent sharing
  only. Excludes guest disks, build artifacts, Git metadata, modified/generated
  files and process-referenced inodes. No deletion, hardlink replacement, client
  configuration, service tuning or existing VM operation is authorized here.
  Other disk agents retain stopped image/build-artifact ownership.
- NEW `ntwrapper/vxd/c009_validation/` (if needed): independently reviewed report
  and exact peer-frozen GUI fixture consumption. Existing cb43 negative W64
  fixture/inner and outer observers are reused; no duplicate observer is written.
  The current production driver's recovered native QUERY proof is acknowledged,
  with host guard failure and absent outer observer exit kept visible.

Own outputs use `build/*-c009-20261001*` / `build/disk-c009/`. Current concurrent
native GOP/theme/TLS trials retain their running disk ownership; this chat does
not start a new guest while those trials are active. Kernel64 standalone app
results do not establish the Win98 display/input or supervisor-domain bridge.

### Native callback trial claim

c009 reserves the next quiet native slot for its new `callback_ingress` fixture
once the frozen host/native build passes. Run name:
`run-win98-gop-callback-c009-20261001-v1`. The parent owns its new private cold
GOP clone,128MiB/two CPUs, no network, existing20GiB floor and256MiB dirty bound.
The known source clone has248135680 allocated bytes; no source/peer disk changes
are requested. The `modern-app-native-guest.lock` advisory lease supplements
actual process inspection. This is callback/TLS prerequisite evidence only;
Chromium/Legcord/Office/Steam success must remain false.

### Verified remaining Win98/Win64 boundary

`build/app-bridge-boundary-c009-20261001.json` pins the current six boundary
sources. Supervisor main creates DOS16/Kernel32/Kernel64 but no Win98 domain;
the planned Kernel64↔Win98 channel is skipped when the latter is absent.
`subsys64_start` then remains idle, and the supervised framebuffer path returns
`STATUS_NO_SUCH_DEVICE`. Process/console IPC has no surface/key/mouse message
family. The successful native VxD QUERY/reopen evidence is acknowledged, while
positive subsystem channel and Win98 display/input remain separate work.
The apps peer's current standalone JS DOM/pixel/TLS receipts must therefore
retain their separate profile; c009 does not duplicate that peer's active
CoWaitForMultipleHandles, compositor or AHCI batching work.

### Current validated checkpoint

- Load Config explicit budgets:20 UBSan host methods passed, including the
  preserved283207168-byte original Chromium core and exact267868/268177 table
  bounds. `build/load-config-c009-large-20261001-v2/host-result.json`.
- Native link closure is now complete: `build/load-config-c009-native-dll-20261001-v2/NTWLDC.DLL`
  (19456 bytes, SHA2560929c7d80cb2de7ce06c24fd3790ab71721c758c8e9413d3646689a4e2936b23)
  exposes eight exact RX nonforwarded APIs, zero imported functions and classic
  Windows4.10 PE32. The real pinned libgcc44-byte stack probe is linked, with
  strict object/link dependency proof; no fabricated helper is used. Its raw
  import directory is the valid20-byte all-zero terminator. Native/API calls,
  mitigation enforcement and app acceptance remain unverified.
- Callback ingress frozenv4: GCC UBSantrap and Clang ASan/UBSan each177827
  real-pthread controls; eight persistent workers and8000 reused callbacks.
  A further60 controls apply the native zero-import predicate to the actual
  linked fixture and adversarial descriptors. The first native review found
  the probe rejected its valid empty import terminator; v4corrects that without
  rewriting it. Sources, manifests and all older failed outputs are retained.
  ManifestSHA81ff086abc7fc7401fb5e9556dcb928450e12206d8de83f604b734497202112e.
  Native stopped-log checker has12 memory-only malformed-log controls; it has
  not accepted a positive native run.
- Parent nativev1 failed BEFOREVM start: captures0, original sources unchanged,
  error `Preparation would leave less than selected reserve/dirty budget`.
  `build/shizukudos/csm/run-win98-gop-callback-c009-20261001-v1/result.json`.
  Its standard runner removed temporary images; there is no stopped raw target
  to deduplicate, and no guest/source image was interrupted or modified by a
  cleanup workaround. Native slot claim is released until headroom is restored.
- Wine sharing continues against the exact895-filev2plan; only observed verified
  per-file extent savings may be reported. No dfdelta from other concurrent
  work is attributed to this chat. Final receipt will bind the completed pass.

### Completed disk pass and current native ownership

The exact895-file Wine pass completed at2026-10-01T07:05:45Z. Kernel byte
comparison and per-file full SHA256/Git blob/name/inode/ordinary metadata checks
passed. FIEMAP measured27828224 exclusive page bytes released (26.539MiB);
concurrent filesystem free-space changes are separate. Frozen summary:
`build/disk-c009/wine-source-summary-v2.json`, SHA256
`cdc8fe4bee877975672a8b1529f78aaf2f61339899560daf989632908e1d707a`.
The bounded follow-up found no additional verified original-package pair above
256MiB: the retained Chromium core/readback pair is already fully shared,
different x64 revisions are not identical, and the recorded Office MSI has no
second original copy. Peer-owned FAT images were not inspected or changed.

The frozen34-file handoff is
`build/modern-apps-c009-handoff-20261001-v2/README.md`. Patch application and
all resulting hashes passed; five separately pinned native-loader dependencies
are absent at baseline abc160b. This is source transfer, not a baseline-build
or app-runtime claim. A separate final supplement records disk completion:
`build/modern-apps-c009-final-supplement-20261001-v1/summary.json`.

At07:06Z headroom briefly met the existing20GiB floor plus copy/dirty allowance,
but the parent v4 attempt stopped at the shared nonblocking native lease BEFORE
runner start. Theme6970 owns that lease (observed PID1278431); no callback v2
run directory or VM was created. Do not interrupt that owner. This chat is
preparing NEW `ntwin32/load_config/native_control/` for actual DLL loading,
eight exported API calls and an observed child exit, using the unchanged linked
NTWLDC.DLL and callbackv4 inputs in a single future private test. Native pending.

`build/modern-apps-c009-review-20261001-v2/README.md` adds30 pinned bridge-source
contracts. Host nested/EPT/unrestricted-guest parameters are enabled, while
the ordinary CSM runner uses qemu64 without VMX exposure. No real Win98
Supervisor domain, positive W64 channel, pixel-buffer pull/ACK or native input
bridge is proved. Its supervised64MiB RAM/initrd limits also cannot carry the
retained283207168-byte Chromium core. Those missing runtime contracts remain
required, separately from standalone Kernel64 app receipts.
