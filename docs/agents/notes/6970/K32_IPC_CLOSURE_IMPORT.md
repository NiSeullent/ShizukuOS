# Kernel32 IPC receive: committed source import and fresh closure gate

Source-only checkpoint: exact canonical6a750722ccc1cfeed0bbb8f03942a190e11181b6
contributes three paths. Own guarded execution is pending. Windows98 remains
the product OS; Kernel32 serves the ShizukuDOS replacement for MS-DOS.

Canonical cd59e040c33d9364c6d29e8f5b97966c3becbf84, parent
d67b7f94a49a2128ff7df83fc72150e829e1d57a, bounds each IPC receive pass to32
frames and yields before polling again. An unconsumed metadata/head error
returns to the next wait rather than spinning forever; consumed malformed
frames can be skipped while later valid requests are served.6a750722 changes
the existing host runner to invoke the exact resolved compiler paths it hashes.

## Exact committed import

| Path | Bytes | SHA256 |
| --- | ---: | --- |
| shizukudos/kernel32/ipc.c | 5327 | aedac9a030f22b379e844a66c72ed159cecc4b8796f22218f32dc85e1bab8bd2 |
| shizukudos/kernel32/tests/test_ipc_host.c | 8044 | 165391eb9704f8e4f0a65b0f2a5d7a9439e710a3bccfd47893dc37b799359e21 |
| shizukudos/tests/test_k32_ipc.py | 5052 | 6fe78436f8d48c5df143cbf7b3018bd686a4db77004a5bcd68594fa7fcef4531 |

Own original ipc.c exactly matched the cd59 parent, SHA256
da1334447456982068591fb7319dd8b0beae88d59cf1b11cb230c702dd187e64.
Both newly imported test paths were absent. Before any writes the importer
checked all three committed blobs and the own parent. Canonical's uncommitted
runner was changing during preparation; its bytes were refused and never
imported. Peer worktree/index, shared ABI, scheduler/publication/deadline
sources, master documents and K64/runtime sources remain untouched by this
scoped import. Source import does not establish execution.

## Peer evidence and own validation boundary

An independent agent read canonical's actual result/log/artifact bytes:
build/pma-integrated-k32-bounded-ipc/result.json6926B SHA256
a4c302ce786c4f712ac79bc2106f6fb900a1c7366d305847b2e0324a8f869bf5.
Its17 commands exited0; GCC365 and Clang ASan/UBSan365 checks passed across
seven cases and the production ipc.c i486 object compiled. Its runner pin is
the committed6fe78436 source above. Later working-runner edits do not inherit
that receipt. This is peer-authored component proof, not a new own execution.

Own shz_ipc.h differs from the canonical header. The shared error/consumption
contract is compatible on source review, but canonical's receipt cannot attest
the own closure. The original runner has a manual project dependency map and
bounded30s children, but no complete recursive output/floor/process-group
guard or actual -M/-MD system-header closure. It is not authorized for local
execution below the20GiB floor. The IPC TU does not include the deadline helper;
its mocked semaphore/yield boundaries do not test real scheduler deadlines.

The new disjoint guarded runner will compile the complete imported fixture
using HOST GCC and Clang ASan/UBSan, require all seven exact case outputs
(10/11/11/11/19/270/33 checks,365 per mode), and separately compile only
production ipc.c with the canonical freestanding i486 flags. Actual -M/-MD
source/system-header before/after closure, resolved compiler hashes and an
ELF32 little-endian EM_386 ET_REL object are required. Every temporary,
capture, binary and self-inclusive receipt shares one new8MiB output root
admitted above20GiB; no RAM/compiler/VM exception.

Object compilation is distinct from native execution. Actual Win98/VMM,
context-switch/deadline scheduling, cross-domain and peer integration flags
stay false. A later combined K32 compile/link and real Windows→Shizuku worker
return path are separate acceptance work. Sole canonical/main/site/ISO owners
retain publication; no main adoption or final deployment is presumed.

## First own attempt: fixture compile failure, not assertion RED

Prepared guard835dfd13 and workflowdd640bb4 ran at exact
c9c09ed9b7bf091b028eb616d2d1b899d543aef4 in
[run36929140107](https://github.com/NiSeullent/Win98-Modern/actions/runs/36929140107),
job110593794449. GCC rejected the fixture watchdog's `(void)write(...)` for
ignoring a warn_unused_result return under unchanged -Werror. No IPC case or
native object completed. The actual four commands returned0,0,0,1 and were
reaped without abort. Resource failure was absent, accounting verified and
minimum free92,386,041,856B; this was a fixture compile failure, not product
assertion RED or success. Root and an independent reviewer matched the full
logged receipt and exact492B compiler diagnostic capture.

Failure receipt60,032B SHA256
03d9341845c9721e585d73b53a5c08438ec02a1ad37da97ba3103a1b0ee0a775;
actual log134,771B SHA256
a0fd054d610e6c7f0f1bb08b085a4de393e083410225683ce81343272b2a2075.
The historical committed fixture165391eb and guard835dfd remain in Git and
their actual proof is preserved unchanged.

The own fixture successor stores the same async-signal-safe write result in
ssize_t and discards that variable, then unconditionally exits124. No warning
option, CHECK, case count, production code or watchdog success rule changes.
Fixture8137B SHA256
c3cad2b11a9ac7bae97aca531ab40817c51ede4b8cd98ded320ec09452663858;
guard42098B SHA256
88179baec8ff68cc5e6ef0ee1b601622521b7303e388ba9a8c4171ffa3697364.
Only the guard's fixture digest and size pins changed. Independent static
review cleared the narrow successor; actual subsequent execution is below.

The companion combined K32 build at c9c09ed succeeded in run36929139750:
all43 compile/link commands0 with30 source snapshots. Its snapshot included
the old host fixture even though no kernel compile command compiled it.
That broader snapshot is historical after the watchdog change; a new combined
build is required rather than declaring the30-input current closure unchanged.
Receipt94,786B SHA256
d09235577283f48a5a1c08bd80e9242d061898b767d96fa63e4f2dd9b97136b2.

## Actual own-header GREEN and refreshed combined build

Successor f5e58113c9ffac9d5a6f6335ec0f48fec932cb0c ran in
[run36929706181](https://github.com/NiSeullent/Win98-Modern/actions/runs/36929706181),
job110595663225. HOST365 and Clang ASan/UBSan365 checks passed across every
exact case. All22 actual commands exited0 and were reaped without abort or
diagnostics. Root and an independent reviewer matched the full actual API
log, printed receipt and all14 stdout captures. Source9 before/after/current
matched, including the retained own IPC header892e0009, distinct from peer
17c19bcf. Actual -M/-MD lists and source/system-header identity/hash snapshots
matched: HOST112 inputs, sanitizer114 inputs, freestanding object8 inputs.

Receipt237,539B SHA256
f30bf864619fce437039d707388e76bff01f6d69f31afa79e30a7cefd08fd5a0;
actual log462,327B SHA256
7db14098f44b85dd21ed028f35ec3639f59fe38342e16fabe263840f2ec96f95.
Minimum observed free92,385,374,208B, final output1,998,083B,
peak observed1,998,084B, resource failure absent and self-inclusive accounting
verified. The actual production object is5388B SHA256
ff6171a0b8f467aaa1feda476c7f0b8b4f7c916ba63777b36086268daf4afa1f,
ELF32 little-endian EM_386 ET_REL. It is compile-only; complete section and
instruction-set validation, linking and execution are not claimed.

The same successor ran the unchanged deadline/build workflow in
[run36929706409](https://github.com/NiSeullent/Win98-Modern/actions/runs/36929706409).
Deadline job110595664040 passed76 HOST and76 sanitizer checks with6 clean,
reaped commands and eight current source pins. Build job110595734669 passed
all43 compile/link commands with30 before/after/current source snapshots,
including the new host fixture as an inventory input rather than a kernel
compile input. The two K32 profiles and multiboot stub are ELF32 EM_386
ET_EXEC with no undefined nm symbols. The stub remains an ELF32/Multiboot
structure proof rather than a verified i486 instruction or boot execution.

Deadline receipt11,729B SHA256
f5b2ffdc1833fd7c0f971aed77d49776c1cb0157f1f4f9bf17bd3fe7456b27fb;
build receipt94,778B SHA256
b226695db9cdc27657957622b9d168ff82b96a6560443673bf156b763626accf.
Build minimum free92,259,364,864B, final output1,678,865B,
peak observed1,678,866B, no resource failure and accounting verified.
Resolved tools/project sources are bound; full implicit toolchain/runtime and
all transient peaks remain outside these receipts.

This fresh own-header proof does not inherit peer receipt a4c302ce. Real
semaphore scheduling, native context-switch/guest boot, Windows98/VMM,
cross-domain execution and peer integration remain false. Raw evidence stays
in bounded RAM while physical persistence fails the separate reserve gate.
Source import6cceb118, guarded preparationc9c09ed and watchdog successorf5e58113
are reviewable scoped commits for canonical integration. Main adoption and
official ISO publication remain unverified.
