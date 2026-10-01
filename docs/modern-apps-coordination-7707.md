# Modern applications coordination — chat 7707

User requirement: functioning themes, current Legcord/Discord, Signal,
current open-source Office applications, broad modern application support,
and OS TLS 1.3. Port source and selected current libraries together.

This chat (`01a0f3d1-7707-7d10-962d-26c937d2743b`) owns new secure-transport
files only in `/root/Win98-Modern-tls13-7707`, branch `codex/tls13-7707`.
It is implementing a pinned TLS 1.3 library backend and native x86 fixture.
`ntwin32/tls` is thread-local storage, not TLS secure transport.

Related active chats found through Codex thread inspection:

- `01a0f3d1-6970-79b3-a586-f7f0308116c0`: theme and application work.
- `01a0f3d1-5abe-7a11-a567-cb6c211c8496`: broad application support.
- `01a0f3d0-cb43-7a31-8522-d2a94e7bf601`: Chromium, Steam, Office, Legcord.
- `01a0f3d0-c009-7f31-baa1-a0d167a8a63e`: modern application work.
- `01a0f109-1a36-7ea2-843d-62ad65c68466`: existing native desktop/runtime owner.

No peer-owned theme, wineport, kernel, display-driver, preview, or runtime
source will be edited by chat 7707. Existing VM instances and disk images
are not taken over. Native TLS tests will use new disposable guest artifacts
or be handed to the established guest owner. Please record disjoint ownership
in a separate coordination document; this file is owned by chat 7707.

There is currently no available send-message-to-thread tool on this host.
This shared file supplies the ownership and integration handoff. A compiler
pass is not a guest TLS handshake, and a library handshake is not system-wide
Schannel/WinHTTP or application support.

## Frozen handoff and combined branch

Transport source commit: `2c5e2a6` on `codex/tls13-7707`. Peer 5abe's
`a12a4a9` themes/latest TLS/app inventory was cherry-picked into this private
branch as `9560069`; no peer worktree or active VM was changed. Peer
acknowledgment is recorded in `docs/modern-apps-coordination-5abe.md`.

Final transport host receipt SHA256:
`6851a064ed6a168a72840023bc38d458cbef48464fafa5613c05a52ec6be710a`
(11 actual memory-queue TLS protocol cases). Native receipt SHA256:
`e80ac28e5ea1ac5c719c4f2223a0f1017d3f27ae03d5972d625d560b6f688494`
(3 PE32 artifacts; static checks only). M98TLS.dll SHA256:
`905afad1554867693375bc18b58cb07522965ec351f81b5d604ddf6054ea98bb`.

Use only the guest manifest:
`/root/Win98-Modern-boot/build/secure-transport-7707/tls13-v3-dos/guest-files.json`
SHA256 `9b88a8ef866dab8c80349afe754d3d3ff838b5438debbb7184ecc9b72858c13f`.
The earlier `tls13-v3` staging is superseded due to an overlong DOS executable
name. Eight input files, explicit DOS8.3 paths, exact source receipt, fresh
nonce and output names are bound. Launch the short `C:\GOPLAB\TLSRUN.BAT`
path; do not paste its189-character probe command at an interactive prompt.
The batch observes zero/nonzero only; an outer observer must retain actual
exit/CRT teardown and guest/boot identity. No guest has run this fixture.

The unchanged guest harness requires20GiB free. Shared-host space is below
that floor. Do not lower the guard or remove peer evidence. The fixture uses
in-memory TLS records with networking disabled and cannot count as native
DLL loading, sockets/DNS, Schannel/WinHTTP/WinINet, or application operation.

Fresh combined-branch theme312/sanitizer/PE and app inventory19checks pass.
Source/protocol/PE success never substitutes for guest/application gates.
Read `docs/MODERN_INTEGRATION_7707.md` in the combined worktree for the
consumer boundaries and remaining actual guest requirements.

Final combined branch HEAD: `1041d05`, clean. Fresh own-worktree builds
passed theme312+ASan/UBSan+three PE gates, latest4.2 TLS16 real loopback
cases+PE gate, inventory19, inherited ntwddm core308637/theme88/present53
and native/i386 freestanding checks. No guest/system/application claim.
Exact new combined receipts/hashes are bound in
`/root/Win98-Modern-tls13-7707/benchmarks/secure-transport-checkpoint-7707.json`.
The peer's original checkpoint retains its original worktree receipts.
Please prefer the combined notes for callback/ABI differences and consumer
boundaries; do not link the two private PSA implementations into one program
or assume multiclient support. Current host space remains below20GiB.

## Disk retry, 2026-10-01

Own regenerated source caches removed393371648 bytes; allocation-only
OpenWatcom tree dedup reclaimed642215936 bytes. All protected artifacts,
archives, original VM images and evidence preserved and hashed.

Superseding native trial manifest:
`/root/Win98-Modern-boot/build/secure-transport-7707/tls-observed-v1/guest-files.json`
SHA256 `d5417af64ca5dddc1bf99a5a37fb9d11adfba3b99c0a45d855f3086f7cad3dc4`.
It replaces BAT with no-CRT TLSWATCH.EXE observing the actual TLS13PRB
post-CRT full DWORD exit, exact Win98 SE identity and errors. Exact source
review plus45 unique host fault cases pass; native execution still pending.
Nonce `tls7707_20261001_a8c03941`; command
`C:\GOPLAB\TLSWATCH.EXE --nonce tls7707_20261001_a8c03941`.

7707 owns one canonical CSM GOP private clone trial after free>=21991407616
bytes plus bounded staging/log margin. No VM launched yet. 5abe owns
allocation-only immutable QA ISO duplicate recovery and native theme
supervisor; 6970 owns app staging image duplicate allocations and native
theme presentation. Please run native trials sequentially. Unrelated active
guests stay untouched; no reserve guard override is authorized.

Keyboard preflight correction: observed-v1 is superseded WITHOUT guest use.
Use observed-v2/guest-files.json SHA256
`890c929918c5d1dd03ce8881c4085eb3e7be6675378547fa1b1e35568f3981dc`,
nonce `tls7707-20261001-a8c03941`, same command with hyphens. Canonical
keyboard typing supports hyphens and rejects underscores.

Native launch claimed: /root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-tls-observed-v2-7707-20261001T0338; flock modern-app-native-guest.lock.
Canonical20GiBfloor+248MBclone+256MBdirty guard preserved. Please defer
new theme/transport trials until this bounded900s trial completes.

Actual v2 outcome: Win98SE4.10/low2222 observed, child timeout90s andguard5s; noTLS13.LOG/actualzeroexit. screen039 explicitly DOSdisplaywindow unsupported. NativeverificationFAIL preserved. GUI TLSWATCH worked; preparing actualGUIlink TLS13PRB with samecustommainCRT andfilelogging. NoPEheadermodification. Please inspect themechildsubsystem beforeGOPnativeacceptance. Ownv2VMstopped/lockreleased; newGUI trialpending.

GUI retry claimed: /root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-tls-observed-v3-7707-20261001T0400
Freshsource/build/manifestpins; actualGUIPE2+customCRT; host11protocol/static8fixturePASS. Same20GiB reserve +256MBdirty budget, newprivatecoldclone. Protectedoldv2FAIL preserved.


## User browser-engine direction, 2026-10-01

The user explicitly removed full WebKit porting as a mandatory prerequisite. Extend the existing Trident-based engine with modern HTML5/DOM/CSS, WebAssembly and modern JavaScript (2026 target) functionality. Actual conformance and user-visible execution are required; a version string or compatibility stub is insufficient. Existing themes, Legcord/Discord, Signal, latest open-source Office, broad application and OS TLS 1.3 goals remain active.

Exact user statement and recipient handoff: `/root/Win98-Modern/.codex-collaboration/7707-trident-direction-20261001.json`. The native thread-to-thread send tool is unavailable, so this shared coordination note is the cross-session delivery path.

## Native SSPI checkpoint 2026-10-01 07:24 UTC

7707 completed disjoint commits `3720778` and `ef55f5d` on `codex/tls13-7707`. They provide frozen native TLS observation/legacy CRT correction, the real portable outbound SSPI stream core, and an explicit-loading ANSI `M98SSPI.dll`. The corrected adapter opens only an existing ROOT store for reading; its old store-opener receipts remain historical. Fourteen core/ABI groups and native fifteen-export/forty-seven-OEM-import gates pass; actual native DLL/ROOT/socket/OS-provider and application acceptance remain pending. The single canonical v5 run `run-win98-gop-tls-observed-v5-7707-20261001T0718` acquired the cooperative lock and is still verifying its private cold copy; no native TLS verdict yet. The independent/no-activation R2 site remains live at `https://m98.nyase.kr/`, with Trident standards work explicitly pending. Owner handoff details and precise receipt bindings remain in the 7707 ledger.
