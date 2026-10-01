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
