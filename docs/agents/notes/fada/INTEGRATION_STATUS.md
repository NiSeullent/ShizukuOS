# Integration status — PMA bridge lane

## Current state

Portable event service, real Kernel64 worker integration and independent ring
validation are implemented. Corrected review findings include last-thread
process cleanup, mixed W64 deadline progress, persistent receive corruption,
shutdown admission/rundown, and complete build-manifest validation. Final source
uses the peer's single private IPC snapshot. Exact PMA commit d461529 passed the supported-display native guest. The
additional peer private-alias display correction d71ec6c passes a fresh merged
four-profile build and native guest. Narrow runner acceptance correction from
c957 is imported as 21badda and its five modeled controls pass.

## Cross-chat collaboration

Coordinated with `문서화 Win98 통합 아키텍처`, `Integrate ShizukuDOS 10 PMA`,
and `Coordinate ShizukuDOS integration` using shared ownership, exact tested
commits, cross-review and defect acknowledgements. Their files remain disjoint.
163f transferred subsys64.c ownership to this lane. c957 and fd5c independently
reviewed service lifetime/shutdown and supplied reproduced defects. This branch
reviewed/imported their display and IPC fixes.

## Fresh evidence

| Check | Result |
| --- | --- |
| Service behavior | GCC and Clang ASan/UBSan: 3429 checks each; i486/x64 layouts pass |
| Production transport | GCC 37764; ASan/UBSan and TSan 37716 each; 2000 threaded exchanges per run |
| Independent saturated rundown | 1612 checks each GCC/ASan against final IPC snapshot |
| Outer ABI after snapshot import | GCC 3665554; ASan/UBSan and TSan 3665540 each; 6000 C/Python frames, i386/x64/MinGW pass |
| Display host contracts | 63 handoff and 156579 clipping checks each GCC/ASan after alias fix |
| Existing VxD host regression | Fresh build; 12 groups including 234 bridge and 2504 WIN64 assertions pass |
| Four kernel profiles | All four profiles pass after final snapshot and alias correction; 207-source manifest |
| First actual no-NIC KVM guest | PMA 16/16 and W64 loopback 48/48 pass; full result FAIL on 7 display-dependent apps |
| Corrected display-enabled guest at d461529 | PASS: 38/38 gates; PMA 16/16, W64 48/48, 151 ordinary apps exit 0 |
| Final merged guest with alias successor | PASS: 38/38 gates, 212.08 s, guest exit 0; unchanged 207-source manifest |
| Actual Windows VMM wait/event delivery | Unverified |
| ShizukuDOS→WIN.COM→VMM→Windows desktop | Unverified by this lane |
| Actual SMP execution | Unverified by this lane |

The first guest ran for 119.93 s without timeout. It omitted every display
adapter; seven apps required actual window creation or explicitly exited 2
when no display was available. Preserve that FAIL receipt/log under
`build/shizukudos/kernel64s/pma-bridge-final-run/`. The corrected run adds the
existing supported Bochs VBE adapter and retains all original assertions,
without a NIC. It passed in 218.27 s under its 240 s limit: guest exit 0,
expected QEMU status 1, runner exit 0, every one of 38 checks PASS. All 206
compiled source hashes, input binaries and five runner/helper sources were
unchanged. Keep this receipt, serial log, matching build receipt and accepted
kernel/stub under `build/shizukudos/kernel64s/pma-bridge-display-final-run/`.
The three existing hardware-input phases in T_GUI_INPUT report absence of a
host driver; no QMP/PS2 input proof is claimed. No UEFI GOP, native Windows
VMM/VxD, Supervisor or SMP execution is established by this standalone guest.

## Reviewed peer imports

- Display 092c4fe5 → local 2935768: checked handoff span/alignment and safe clipping.
- Display eb567858 → 240b669: direct-map aperture bound.
- Display c6199b59 → ce7860c: compiler-derived source closure in receipts.
- IPC geometry 7252e3e → c117ce2: checked channel/ring/pool geometry and ownership.
- IPC snapshot c6c6577f → e0007fc: checked and returned bytes use one private copy.
- Display alias bound 444e2934 → d71ec6c: admitted GOP ranges stop before the 64-GiB graphics arena and all later private aliases.

## Remaining acceptance

Service/runtime source is committed at d4615296c27a0ccb27ce1ab344bbd2ed322ce4c8
and its passing guest receipt is published to peers. The source-bound
merged alias build/guest rerun also passes. The reviewed c957 runner successor
4e605359 is imported as 21badda; all five modeled controls pass. Independent final reviewer repeats all five controls, reproduces the immutable
predecessor false-positive paths, confirms actual native receipts and all
207 compiled sources remain unchanged, and finds no actionable blocker.
Final local ownership/evidence documents are ready for commit. Actual Windows identity binding,
VMM callbacks and native wait delivery remain broader integration work. Do not
convert host/standalone success into Windows or SMP claims.

## Runner acceptance follow-up

Independent c957 production review approved d461529 and replayed service/ring
host tests. It found two P2 acceptance-tool weaknesses: a launch error can leave
a prior PASS in a reused output directory; a successful serial can pass despite
an abnormal QEMU status. Its lead supplied reviewed successor 4e605359, imported locally as 21badda.
Our actual accepted guests used unique new output directories, returned status
1, and passed with recorded hashes; those historical results are valid. Keep
them intact. No source/runtime defect was implicated. Independent modeled
controls must remain distinct from actual native execution receipts.

The corrected runner requires a fresh output directory before preflight and
accepts only expected QEMU debug-exit status 1 with no timeout. Root replay
`python3 -B shizukudos/tests/test_k64_pma_bridge_controls.py --out build/shizukudos/pma-bridge-runner-controls-final`
passes all five modeled methods, including abnormal statuses -9/0/2/3, timeout,
reused output, fresh launch error and a positive control. It launches no VM.
The preserved actual merged guest's status is 1 and exit marker is 0; root
re-evaluated its real serial, current 207 compiled sources and actual binaries
under the corrected exit criterion, with 38 PASS checks.
`recorded-result-recheck.json` explicitly records no additional guest execution
and retains the original receipt/helper hashes. The final Python-only correction
does not change compiled guest code. Do not rewrite the original native receipt.

## Reproduction

Run tests/build from the repository root. Supply a new guest output path on
every run; earlier receipts are preserved. WIN64.IMG is the SHA-bound cached
project test fixture documented in input provenance, not a fresh current-source
Win64 runtime build or Windows 98 media.

```sh
python3 -B shizukudos/pma_bridge/test.py
python3 -B shizukudos/pma_bridge/test_transport.py
python3 -B shizukudos/abi/test_abi.py
python3 -B shizukudos/kbuild.py
python3 -B shizukudos/tests/run_k64_pma_bridge.py --accel kvm --timeout 240 --out build/shizukudos/kernel64s/pma-bridge-reproduction-NEW
```
