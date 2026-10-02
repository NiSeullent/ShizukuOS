# Native FAT32 relocation component status

FADA acknowledged the exact six new paths. The pure C helper and unchanged
literal controls completed actual host verification. With GCC and Clang
(ASan/UBSan enabled for Clang), the synthetic model reports 1375 checks with 394
failures each; the real helper reports the same 1375 checks with zero failures
each. Actual v2 receipts are:

- build/native-fat32-host-red-v2/result.json:
  968acacbe77bd880501b534e7557d54e592d07537898d263a11bde2df8a86694.
- build/native-fat32-host-green-v2/result.json:
  8d4b1b0803d353c40df634b51fdf82b2d86a29aeef0186d7467b23db63674a38.

Both modeled runs exit one with expected assertion failures; both actual
helper runs exit zero and have empty sanitizer/error logs. All eight RED and
twenty GREEN leaders were reaped with no observed live group members or abort
flags. RED has 32 artifacts and 2250532 bytes including its receipt; GREEN has
65 artifacts and 2292255 bytes. Sources, listed tools, generated first-use
inputs and complete artifact maps were physically rehashed without mismatch.

The preserved actual-helper GREEN v1 FAILED before host assertions: GCC, Clang and
x64 helper compiles reached the original 25-second bound. Own TERM/KILL cleanup
reaped all leaders, with no observed live group members. Receipt
build/native-fat32-host-green-v1/result.json (71fd72cc08ce5a2a8b6771e342eefca70c173e5059ea8c853747394956609c80)
is preserved, including all 45 artifacts. Independent pair review dfbb0e32
rejects that failed epoch. A separate reviewed single x64 compile completed in
4.243281 seconds, receipt 5d4a3f322e243fe2d951d38c5cae3af83a270aa91cfc650c1ed85e32cd69f8be.
This measurement does not prove the original timeout cause. The only runner
successor change grants compiles 60 seconds; runs/version/nm/objdump retain
25 seconds and existing assertions, flags and cleanup remain unchanged. The
initial model receipt fc0588aeb6eb9ced226d6dc733858ae5219e47d6eb23f64724456a54fbe9279b
also remains immutable. No failure is retrospectively promoted into a pass.

All four v2 x64/i386 helper and consumer objects compiled. Actual COFF machine,
postcompile local MMD dependencies and undefined symbols were checked. The x64
helper has no undefined symbols; i386 retains __udivdi3 as a compile-only
dependency. Each consumer references exactly the two helper APIs. Consumer
linking, libgcc resolution and whole installer build are not established.
Compiler support/sysroot/interpreter inputs are not a sealed external closure.
Four independent literal 8 KiB prefixes match exactly two hidden-sector DWORD
overlays at BPB-derived backup sectors 6 and 10. These are synthetic prefixes,
not whole 64 MiB volume digests or real installer S/R custody and readback.

The supported native-source subset requires LBA zero, exactly four 512-byte
snapshots, mirrored FAT32, zero BPB reserved bytes 52..63 and a logical extent
at most 2304 MiB. Primary/backup VBRs must match exactly; the two FSInfo records
may have different independently valid hints. Geometry, FAT capacity and
reserved-sector indices are validated. The selected target interval is exact
and its first LBA is representable in the hidden-sector DWORD.

Stage publishes a complete deterministic plan after all checks. Overlay checks
the staged snapshots and all derived metadata before changing either DWORD.
Failure preserves caller output; source and plan are read-only. These are C
buffer APIs requiring actual valid storage, not arbitrary pointer probing or
authenticated source/plan custody. The two permitted spans may include bytes
whose value is already unchanged.

Source drafting precedes the planned synthetic legacy-behavior RED run; strict
test-first implementation chronology is not claimed. The RED baseline is a
synthetic copy/no-op model, not an existing b144 runtime or API. The same literal
controls ran against the real helper without assertion relaxation.

Existing public installer/source2048 behavior and install.c remain unchanged.
FADA owns canonical SIMG validation, original-S and relocated-R hash lifecycle,
preflight before erase, held source identity, target/current-OS exclusion,
physical writes, flushed readback and cold boot. The helper itself performs no
I/O, SHA, allocation, FAT tree walk or GPT authorization.

Actual Windows 98 VMM/USER/GDI/Explorer remains the OS body. Desktop, apps,
persistence, general SMP, own installer and final ISO acceptance remain open.
