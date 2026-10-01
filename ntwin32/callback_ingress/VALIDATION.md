# Frozen callback ingress handoff — 2026-10-01

The v3 receipt retained below documents host/build evidence only. The current
native handoff is **v4**: `build/callback-ingress-c009-20261001-v4/result.json`,
SHA-256 `f16035917f678a8020d394a1a93f958d2d21826f13512cb71490a252d9137f61`;
manifest SHA-256 `81ff086abc7fc7401fb5e9556dcb928450e12206d8de83f604b734497202112e`.
It repeats177,827 GCC UBSan-trap and177,827 Clang ASan/UBSan checks and adds60
actual compiled-fixture protocol controls under Clang ASan/UBSan. All used
current/frozen source hashes match; the reviewed ingress library is unchanged.

Independent review found that GNU ld emits a legal20-byte null import descriptor
for this zero-import DLL. The v3 probe incorrectly refused any nonzero import
directory RVA. The v4 shared native predicate admits an absent directory or
exactly20 bounded raw zero bytes; all actual/nonzero dependency descriptors
remain refused. The host gate now runs that same predicate on the actual linked
DLL and rejects each nonzero descriptor byte and invalid declared/raw bounds.
The separate parent v3 native attempt stopped at its preparation reserve guard,
before VM launch, so this structural error was found by source review, not an
observed guest failure. The v3 build/manifest and failed native run stay intact.

Current v4 artifacts: `CIFIX.DLL`8065B SHA-256
`90c881dc25963180f3e19584577b5743e5ed31b2ac115acf91f76a3114ec92af`;
`CIWRK.EXE`78015B SHA-256
`fba0133929df78f589c4bd480f8845c9a9e762ce696cebc5baa6abe505436369`;
`CISUIT.EXE`27786B SHA-256
`0c4304b5d27466bb17496d86561866637f8634bf0e4904e9dee3c1f9d7a4dbb0`.
Its exact guest command and fresh report names remain the same. Native execution
is still pending; no source/build record is an application success.

`review_native.py` consumes stopped parent runs only. It binds the v4 build,
manifest, sources, binaries, prepared copies, actual raw child/suite reports and
completed runner/cold-clone lineage. Twelve memory-only parser methods reject
missing assertions, fake aggregate counts, duplicate fields, nonzero exits,
timeouts, truncated/non-ASCII logs and unintended scope promotion. It does not
open a VM image or observe the suite's own OS exit, and explicitly preserves
both visual screenshot review and production/app integration as unestablished.

Retained v3 receipt:
`build/callback-ingress-c009-20261001-v3/result.json`
SHA-256 `3a6149ca41df250816d676eade527c2b718af83450c27ca29ab774f4c732cf85`.
Its status is **HOST_BUILD_PASS_NATIVE_PENDING**. Both the production native
loader and provider integration flags are false; application success is false.
All frozen/current used source hashes matched after validation.

- GCC UBSan traps:177,827 checks passed; Clang ASan/UBSan:177,827 checks passed.
  Each runs eight actual pthread workers and8,000 repeated callbacks through
  the real existing TLS engine. Normal worker TLS reuse, actual owner checks,
  nested LIFO frames, double/stale/foreign-manager frames, closing, worker and
  depth exhaustion, index/output aliases, occupied/foreign TLS slots, partial
  rollback/detach recovery and notification reentry are covered. Host TLS-slot
  adapters do not verify native FS/Win98 ABI.
- `CIFIX.DLL`, `CIWRK.EXE`, `CISUIT.EXE` compile as i486 PE32/GUI4.10 with
  OS4.0 and no modern load-config/delay/CLR directory. The own mapped DLL has
  zero imports; probe/suite have33/13 imports, all in the retained real OEM
  Kernel32 inventory. Its two MS-ABI compiler FS instruction operands are
  exactly0x2c, at RVAs0x1008/0x102d, absent from relocation targets (separate
  read-only verification of the frozen DLL). Only the DLL has automatic TLS.
- Native probe behavior remains pending. It maps the own DLL, checks relocated
  TLS identities, publishes templates with the existing native Win98 backend,
  and starts two actual native provider-like workers. Each executes128 mapped
  compiler-TLS calls while retaining one thread attach/detach. The main TLS
  stays separate. Real thread waits/exits/joins precede TLS disposal and image
  release. The child suite validates the fresh complete report and observes
  actual child OS exit0; an outer observer must still establish suite exit.

Frozen guest manifest:
`build/callback-ingress-c009-20261001-v3/manifest.json`
SHA-256 `33ab3460024c86f047337857513361d0adbe6d750c7dde087e616bdc3cc440c6`.
Exact command:`C:\VXDLAB\CISUIT.EXE`. Fresh outputs are
`C:\VXDLAB\CIWRK.LOG` and `C:\VXDLAB\CISUIT.LOG`.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| CIFIX.DLL | 8065 | `8880630bf18557b535f0f9db3a7f85fb100e0d83292a51801dd22e851048c957` |
| CIWRK.EXE | 78015 | `686fc71606c3ed9ddccc2081dadb9ecf81d7b59d1bbaf2495f37d11866c8ccec` |
| CISUIT.EXE | 27786 | `0c4304b5d27466bb17496d86561866637f8634bf0e4904e9dee3c1f9d7a4dbb0` |

Independent read-only review caught and corrected manager identity collisions;
the parent review caught and corrected manager storage overlapping a prepared
live TLS index/template. Two-manager actual-TLS-plan and slot-zero index tests
exercise those defects. A subsequent review also tightened failing native
worker paths: keep the borrowed report/lock live until process termination and
never unmap while plan disposal is incomplete. No peer file was edited.

The original output `build/callback-ingress-c009-20261001/` is retained as FAIL:
GCC compiled the source but could not link the absent installed libasan/libubsan
shared libraries. No library was installed. The fresh v2 build passed using
GCC UBSan traps and Clang ASan/UBSan with177,755 checks each. Fresh v3 adds
notification/callback TLS replacement controls and the native failure-path
correction, passing177,827 each. No failed receipt was overwritten or promoted.

No VM, app, disk, provider table, native execution gate or global setting was
changed by these builds. Integration still requires provider worker hooks,
retained thread handles and a join API, mapped graph notification adapters,
actual native ingress/exception/exit behavior and application trials. The
existing provider execution gate must remain until those prerequisites pass.
