# Current integration status — c957

Date: 2026-10-02, Asia/Seoul. Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
Branch: `codex/pma-c957-20261002`.
Worktree: `/root/Win98-Modern-pma-c957-20261002`.

Actual Windows 98 remains the product OS, retaining VMM, USER, GDI, Win16,
Win32 and Explorer. PMA and the native kernels are backend components. The
complete requested architecture remains unfinished; this evidence admits
specific implementation slices only.

| Scope | Implementation and verification | Remaining limit |
| --- | --- | --- |
| Cross-chat cooperation | Bidirectional ownership ACKs, scoped imports and reciprocal reviews with 163f, fada, fd5c and 6970 | Canonical integration and actual Win98 boot remain coordinated separate lanes |
| Native synchronization/NT spin operations | f07d0e4 + 79afb00 + 8a74d9a independently approved; root GCC/ASan 40000 publications each, TSan 2000, i486 and actual NT IRQL/ISR operators; 11 commands pass | UP IRQL implementation; caller IRQ/reentry rules and finite ticket token lifetime apply; no SMP acceptance |
| Lock test provenance | Exact production bodies and complete current headers bound; three copied-source mutations and 13 predicates pass | Observed before/after stability requires frozen sources |
| Framebuffer/clipping | 092c4fe + eb56785 + c6199b + reserved-alias fix 444e293; root and independent reviewer each reproduce 63 getter + 156579 clipping assertions in GCC/Clang ASan; 20 compiled inputs bound | GOP ranges must end at or below 64 GiB; generic MMIO callers are outside this fix |
| Capability inventory | Timer/work contracts plus4e6beea captured-manifest/source/staged-publication repair;78 tests pass, independent11 actual CLI race controls pass;120 families/56 frontend/17 backend | Native/behavior flags remain false; persistent drift checks are point sampled and do not prove native API acceptance or concurrent/crash durability |
| IPC geometry/pool ownership | 7252e3e; root GCC 3665542, Clang ASan/TSan 3665528 each, freestanding 32/64/MinGW and 6000 independent C/Python frames pass | Stable geometry and caller pool lifetime required |
| IPC message snapshot | c6c6577 imported: checked header, CRC and payload use one aligned private slot; deterministic collision regression | Fresh GCC 3665554 / Clang ASan+TSan 3665540 each and 6000 crossframes pass; independently approved; no atomic-copy guarantee against a violating sender |
| Supervisor pending-doorbell WAIT | af06f0e; actual domain.c host fixture passes 607 assertions in GCC and Clang ASan | VMCS/injection boundary modeled; no native VMM wakeup proof |
| GOP/EDID selector | 305448b; root GCC/Clang ASan 966 checks each; actual isolated OVMF/KVM retained 2560×1440 after ExitBootServices and verified five pixels | OVMF had no EDID; 402f2cb AUTO failure guard passes 15 actual-entry scenarios/180 checks per compiler; no real hardware EDID acceptance |
| VxD admission/epoch/replies | 4aeaa89 + 7252e3e reproduced three transport failures; root efc5e8b repairs copied-header validation; all 13 tests pass and independently reproduce | Merged 273+04 receipt fixes pass all23 host tests with50inputs/7dependency sets, independently approved; outstanding reset needs peer/window teardown for pool reclamation |
| Supervisor text/cursor | 149dec3 + cded260; root GCC, Clang and Clang ASan each 329657 production video/glyph checks pass | Host component evidence, not Windows desktop rendering |
| Shared font compile binding | c9be098 imported; five actual compile.py mutation/control tests with mocked build boundary pass and independently reproduce | Actual compilation recorded separately below |
| Closed NTW64 handles | 8c51a72; root GCC/Clang ASan each 2162440 lifetime checks over 65528 create/release cycles, plus failure/deferred-close groups | Slots retire at generation exhaustion; transport mocked; no unlimited reuse claim |
| Kernel32 publication | 8671fba; root 17 production checks in GCC/Clang ASan; fresh isolated KVM guest passes all nine original checks | Fresh updated v2 guest passes12 total checks/44preemptions/31ms wait/50ms sleep; standalone backend, not Windows 98/Supervisor/SMP |
| Kernel32 guest provenance | 665792e imported; current receipts bind source/evaluator/build before/after hashes and immutable artifacts; root control regressions executed | Fresh v2 guest PASS, artifacts/receipt/36-source closure stable; 12 runner controls PASS; prior guest receipt remains historical |
| Kernel64 PMA policy | Reviewed644c94f four-file finite aging source imported as fcb36a0; fresh212-input four-profile build, focused11-check/35-assertion and full38/38 ROOT guests pass | Canonical same-source actual guest independently fails arrival wait5/remaining4; correction remains owner163f's lane. All earlier failed receipts preserved; no VMM/SMP acceptance |
| PMA event/completion service | d461529 production-reviewed; host GCC/Clang ASan3429 each; ABI GCC37764/ASan+TSan37716 each and2000 threaded exchanges pass; ROOT full successor passes16PMA plus32legacy Win64 checks,48total | Actual standalone fixture/rings only; historical sampler/loader/scheduler failures retained; no native VMM delivery proof |
| PE DLL collision successor | d08e1cb allows non-stripped empty-directory DLL fallback mapping; GCC/Clang ASan and independent reviewer each20cases251checks pass | Actual archived WinMM/T_GUI_STATUS passes with all151apps in source-bound full38/38 guest; no nativeWindows98 or ten-required-modern-app acceptance |
| Website preservation/refactor/publication | Source7050f3e;54 tests and independent review;100 assets, both48-frame viewers, desktop/mobile/keyboard/games/noJS and5 actual ZIP downloads pass. New nginx current213716 and100 normal-headed public HTTPS body hashes verified | Final ISO and native proof not published; prior public headless403 retained; generic direct/headless access not inferred; NAS/large-artifact publication floors retained |
| Partial NT priority projection | Unwired common helper supports35 non-realtime class/level combinations and Win32±15 ↔ NT±16 sentinels; GCC/Clang ASan each3456 checks and i486/x64 freestanding consumers pass with independent review | Runtime handle/rights/object-lifetime/API/init wiring remains pending; helper adds inventory input213 and does not change scheduling behavior |
| DOS boundary audit | Pinned actual FreeDOS entry, EXEC, exit and reentry paths inspected; see status/dos-boundary-audit-c957.md | Executor/VMM callback prerequisites assigned to163f Windows/NT lead; an INT21 lock alone misses real transfers; actual DOS gate/boot pending |
| Private replacement preparation | a4fcab9 imports peer f7f1aea and closes appended-extent/invalid-EOC readback findings; original25PASS and targeted3RED retained; corrected30 actual synthetic FAT/mcopy/NASM controls and independent review pass | Source preparation only; recognized producer closure remains partial, NAS/resource/native boot owners unchanged, all actual Windows replacement/native flags false |

## Latest frozen component and website evidence

Full details are in `status/scheduler-integration-c957.md` and
`status/site-ux-c957.md`. The frozen fcb36a0 four-profile build passed at
21:25:29Z with212 sources and both build helpers stable. Full actual KVM guest
`build/pma-c957-pma-bridge-aged-final/result.json` passed38/38 at21:30:00Z,
216.49seconds/QEMU1/no timeout. It binds212 sources,8 direct inputs and5
runner/helper identities. All151 historical fixture EXEs exit0/faulted0,
35 scheduler assertions pass, and48 loopback checks comprise32 legacy Win64
and16 PMA checks. Older descriptions of48 additional legacy checks were an
overcount; raw receipts/logs remain unchanged.

Canonical's separate actual guest with the same212 source/five helper
identities fails the arrival boundary5/remaining4. Its modeled READY/BLOCKED
coordinator control supports possible aged-thread fixture interference but
does not close the natural guest failure. Both real guest receipts are
retained. Owner163f handles the reviewed correction and fresh acceptance.

The new unused NT projection header extends complete kbuild inventory to213;
the212-input whole-kernel receipts remain historical at their frozen epoch.
This helper has host/freestanding verification only and no existing consumer.

Official static nginx current is `/srv/m98/releases/20261001T213716` with100
files/5,181,666 bytes; previous152940 is preserved. Both publication locks,
source/current guards and100 actual origin-body hashes pass. Normal headed
Chrome153 subsequently verifies public HTTPS Korean/English pages, all100
body hashes and five actual browser downloads with matching ZIP bytes/hashes.
TLS validation stays enabled; no custom UA/proxy/host mapping was supplied.
No ISO, native proof, private media, console or nginx configuration changes.
Final ISO download and actual Windows98 acceptance remain pending.

## Historical build and execution records

Baseline four kernel profiles and baseline Supervisor compilation passed; their
original outputs are preserved. The merged four-profile build at `743edf6`
also passed and is retained in `build/pma-c957-kernels-743edf6`. It predates
K32 publication, reserved framebuffer and IPC snapshot imports and is not
final current-source acceptance.

The four-profile build at `2052796` passed and is preserved unchanged in
`build/pma-c957-kernels-2052796`. The next historical combined compiled-source epoch at
`2ec11830a333160822e27fab0f5b0411147701bc` passed on
2026-10-01T19:56:56Z with all 212 current kernel inputs equal before/after.
Receipt preserved at `build/pma-c957-kernels-2ec1183/kernels-build-result.json`.

| Profile | Bytes | SHA-256 |
| --- | ---: | --- |
| Kernel32 | 24516 | `3acd7e53fccc0bef4e9148e56dda1e494af79e59ea55329f2ba7a9dcb6d43d23` |
| Kernel64 | 742736 | `db7965cd7a4d54e177177c6b12cb4624d7ec5ab3ed0d690d6b159c49ac834a91` |
| Kernel64 standalone | 836954 | `8ccf2c8aa3d8839c5852e86f837e08a6bc93cd6788f0112540037b383c5a2eb7` |
| Kernel32 standalone | 26916 | `09d35cb1a54a60273b462de165c9c50d5bd88e1a064faee461a839c79165e90b` |

Fresh Supervisor compilation passed with all105 source hashes stable, including
shared glyph dependencies and current loader AUTO/ABI changes. Receipt:
`build/pma-c957-supervisor-combined-final/result.json`.
Payload136118 bytes, SHA-256
`88b60a40cf2e552cd8a9cc8e67e249ba358295c03b1c55e4e2c7ccf632d273fb`.
Loader173056 bytes, SHA-256
`c6b5f5e4a3d0cf1a061dc2fbaf297fe6d5a0655b22f90f94e44c67b31a65a9b5`.
VM_executed and Windows98_executed are false. Earlier compile receipts remain
historical at their original epochs.

Fresh K32 v2 guest: `build/pma-c957-final-k32-v2/run-kvm/result.json`, PASS12
checks, 36-source build closure and artifacts/receipt/evaluators stable.
Fresh K64 focused KVM: `build/pma-c957-k64-pma-final-kvm/result.json`, FAIL,
with sampler observation32/65 while actual ready residence32. TCG of identical
kernel: `build/pma-c957-k64-pma-final-tcg/result.json`, PASS11checks.
Receipt omission repair `2ec1183` is independently approved with6 modeled
controls, then full13 controls pass using the genuine TCG serial. These do not
override the failed KVM scheduler acceptance.

Bridge runner correction `4e605359a4bdac5dffbb66ec9ec48605ea7495dc` requires
fresh output and exact isa-debug-exit rc1 without timeout. Actual-runner RED
reproduced old-output reuse and four abnormal-exit false positives;5 GREEN
methods independently pass. Mock controls execute no guest. The fresh real
combined bridge guest ended FAIL in `build/pma-c957-pma-bridge-final`:204.8s,
38 checks, QEMU rc3. All16 PMA assertions,32 legacy service assertions and151
ordinary app exits pass; the one sampler failure remains a failed whole guest.
Its sources/artifacts/runner helper stability checks pass. Original logs and
receipt are preserved. The independently reviewed sampler guard86f52c1 subsequently passed a full212-input four-profile build and fresh focused KVM11checks. That build is preserved at `build/pma-c957-kernels-86f52c1`; its K64 SHA is b9ef854980ff69f255e6d5f8ee569915c415812e858a6a3b2a003ca860debeb1 and K64S SHA25d060c6144d5caf72797156528daeffd700d0b1df350602af6e337e393a72b9.

Its full bridge successor `build/pma-c957-pma-bridge-sampler-final` still failed:217.67s, QEMU rc3,38checks with three failures resulting from T_GUI_STATUS.EXE failing to load archived WinMM. All scheduler assertions,16 PMA/32 legacy service assertions and150 other apps pass in that historical failed guest. The archive DLL has stripping clear and relocation directory0/0 but preferred-base collision was treated as fixed-base. Narrow source successor d08e1cb has genuine RED/GREEN and independent host approval. Fresh four-profile compilation passed at2026-10-01T20:43:56Z with212exactcurrentinputs. K64 SHA71fb04d908344cda48b95c4d6d64373ea1e29cba7b3c482c35e56e2f4d065995; K64S SHAacc02413b8fb7b009780c99cda95d3c32160281c322f37fc7eea1aafd2482663; K32/K32S unchanged. Fresh focusedKVM11checks and16controls pass.

The actual full loader-successor guest `build/pma-c957-pma-bridge-ldr-final` is terminal FAIL:301.7s, QEMUrc3/no timeout. All151ordinaryapps exit0/faulted0 includingT_GUI_STATUS/archivedWinMM;16 PMA/32 legacy service assertions and sampler64/32,32/ready32 pass. Two actual PMA failures remain: zero useful work in the second low-priority phase and refreshupdates625199/first164/loops0. Source/artifact/helper gates pass; this reproduces the canonical useful-progress problem in ROOT. No threshold or gate was weakened and no blind rerun performed. Neither earlier whole-guest failure is relabeled.

Canonical2bde Python source/helper provenance is consumed in3efbc6f, plus independently reviewed focused fresh-output preservation.16 controls and real fresh KVM11checks pass at `build/pma-c957-k64-helpers-{green,kvm}`; GCC/ClangASan K32host17checks each and two actual copied-header CLI controls pass. These bind their original sampler-only compiled epoch. The canonical peer refresh failure remains a distinct unresolved gate.

Its Win64 initrd is explicitly a pinned historical component fixture:
archive SHA-256 `a098a49fdf686973d5246f74e7f61d8257afced11ab28a11a7f4bd47c0dc7a7e`,
original source epoch `6d860bf`, built2026-10-01T18:39:22Z. Original receipt
copied unchanged alongside `component-fixture-provenance.json`; no fresh
current-source Win64 runtime build or Windows98 media claim is made.

Root actual OVMF evidence: `shizukudos/uefi/build/ovmf-9mj49jrn`.
Root current K32 evidence: `build/pma-c957-final-k32-v2/run-kvm`; earlier output retained.
Each guest used new isolated outputs and ended; existing VMs and private
Windows/DOS media were not changed.

## Product acceptance still pending

Actual Windows 98 boot on replacement DOS, positive VMM→PMA work/wait/result,
VMM responsiveness, native SMP, per-process VGA/SVGA virtualization, complete
DOS state serialization and modern driver/application acceptance remain open.
Original-DOS controls, absent-peer VxD rejection, inventories and host or
standalone component tests do not satisfy these gates. The full goal includes
final1.0.0 ISO, complete m98.nyase.kr refactor and verified nginx/public
delivery. Website source7050f3e, frozen local browser verification and actual
bounded static nginx/public delivery are complete; see status/site-ux-c957.md.
No final ISO or private media was published. Shared source main/origin and
client-global configuration remain unchanged by this lane.

The earlier actual public headless browser baseline at20:51UTC reached a
valid-HTTPS Cloudflare403 challenge, preserved unchanged. The later normal
headed public delivery success is a separate receipt; final artifact download
and general direct/headless access are not inferred from it.

Fresh current-loader capability CLI report: `build/pma-c957-cap-receipt-ldr-final/capabilities.json`; all58currentprojecthashes rechecked,120/56/17 inventory, native/behavior flagsfalse. The prior report remains historical at its captured pre-loader source epoch.
