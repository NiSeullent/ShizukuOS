# Owned runtime checkpoint adapter

`private_checkpoint_adapter.py` supplies the runtime boundary required by the
reviewed `private_checkpoint.py` API. It does **not** wire the canonical
`run_vm.py`, start or clean up QEMU, resume a guest, capture a Windows disk, or
write to NAS. Canonical 163f retains controller/native Win98 integration.
Kernel32/Kernel64 remain components of the actual Windows 98 foundation.

## Ownership and source closure

Create `OwnedRuntime(process, pidfd, monitor, checkpoint_module,
owned_qmp_module, held_sources, roles)` inside the controller's existing
exclusive capture interval, on the Python main thread. Inputs must be the
controller's **already-owned** actual `subprocess.Popen`, held `os.pidfd_open`
descriptor and exact existing `OwnedQMP` instance. This API accepts no socket
path, arbitrary PID or cleanup callback. The caller retains process/socket/fd
ownership and must perform final checks and reap its exact child before
releasing source leases.

`roles` maps exactly `controller`, `qemu`, `owned_qmp`, `checkpoint_helper` and
`checkpoint_adapter` to names in the tuple of existing `ReadLease` objects.
Include the complete controller source/input closure and all proof tools, not
only these five roles. Canonical paths, real read-only descriptor access,
`F_GETLEASE`, SIGIO-aware callbacks, descriptor/path identity, exact extent and
full independent SHA are checked. The loaded adapter/helper/OwnedQMP paths
must match their leased sources. The owner must import these modules and the
SHZ parser from the exact expected source bytes while their leases are held;
`__file__` alone is not an attestation of already-loaded Python code.

Before and after every request, the adapter checks the actual Popen lifetime,
unchanged argv, pidfd inode/fdinfo/PID and readiness, Linux process starttime,
exact kernel cmdline SHA, executable inode against the leased QEMU binary,
current socket identity and `SO_PEERCRED` PID/UID. It preserves the existing
QMP request IDs, bounded responses, pump and absolute/per-request deadlines.
The initial absolute deadline must remain unchanged. Owned argv must explicitly select `q35` or a
`pc-q35-*` machine; hardware layout still comes from the running child.

## Actual physical memory observation

The canonical controller first acknowledges `stop` and proves current
`running=false/status=paused`. Then call:

```python
runtime.write_observation(fresh_private_ram_receipt)
```

The adapter observes version, memory-size summary and `info mtree -f` through
the same owned QMP connection, with stopped-state checks before and after.
It requires zero hotplug memory. The complete bounded response is retained in
a fresh private source receipt. The parser selects exactly the shared FlatView
containing `AS "memory", root: system`, checks every row of that view for
recognized syntax, ordering and nonoverlap, converts inclusive ends to
exclusive ends, and extracts only writable `ram: pc.ram` spans. ROM, MMIO,
device RAM and nonvolatile RAM are excluded. Physical and backing-offset
extents are checked independently; total RAM is never used as a physical
address ceiling. FlatView enumeration numbers and unrelated address spaces
are not hardware identities.

The strict parser follows the primary [QEMU 10.1 FlatView emitter](https://github.com/qemu/qemu/blob/v10.1.0/system/memory.c)
and [HMP command definition](https://github.com/qemu/qemu/blob/v10.1.0/hmp-commands-info.hx).
An unsupported downstream format fails closed; do not guess missing rows or
substitute a Q35 default formula.

For a diskless `-S` protocol probe only, `allow_prelaunch=True` also permits
`running=false/status=prelaunch` and records
`scope=read_only_prelaunch_protocol_probe`. Such a receipt **cannot bind a
checkpoint adapter**. The helper's exact paused-state requirement is unchanged.
No resume is needed to observe the stopped machine.

## Layout and budget proofs

`prove_layout(checkpoint_module, info_module, held_header, held_parser,
held_compiler, fresh_private_layout_receipt)` performs an actual bounded C
compile and probe with the leased compiler path, fixed locale/environment,
private temporary outputs, CPU/file limits, timeout and owned process-group
cleanup. The parent UID/privacy is checked before any temporary output or
compiler launch. An exit racing with a failed wait still receives a bounded
reap attempt, and cleanup errors are attached to the original failure.

The generated C source is checked against its expected bytes and passed to
the compiler through a held read descriptor. The compiled binary is pinned
and read-leased before execution; `Popen` executes that descriptor with the
original argv retained in the receipt. The actual stdout/stderr descriptors
are independently snapshotted after the owned child exits, then reopened and
read-leased against those exact inode/extent/bytes. Hashing and interpretation
use the same snapshot. Source, binary and output bindings remain held through
proof publication. A subsequent artifact-close or temporary-cleanup failure
invalidates only the producer's canonical proof inode, with best-effort fsync.

It compares sizes, every field offset and every field extent for
`shz_info_t`, `shz_blob_t`, `shz_domain_info_t` and `shz_vmcs_snapshot_t` against
the source-pinned Python structures, including nested types and array strides.
It retains compiler/source/binary/output hashes, exact commands and exits,
and source hashes before/after. Compiler helpers, includes and shared libraries
remain external; `complete_toolchain_closure_verified=false` is explicit.

The caller obtains and read-leases the real NAS owner's separate budget
receipt. The adapter does not authorize or generate that approval. Its exact
JSON schema is:

```json
{
  "schema": "shizuku.private-checkpoint-budget.v1",
  "private": true,
  "approved": true,
  "scope": "private_ram_checkpoint_only",
  "approved_lane": "/mnt/shizukuos-native-workspace-fada-20261001/<approved-private-lane>",
  "disk_bytes": 2147483648,
  "capture_bytes": 16777216,
  "total_bytes": 2164260864,
  "retained_free_bytes": 18253611008,
  "timeout_seconds": 120
}
```

The reviewed helper's exact 2 GiB disk, separate capture allowance up to
16 MiB, minimum capture extent, unchanged 17 GiB floor and 1–900 second
timeout are enforced. Budget validation checks lane syntax without accessing
NAS; the actual producer/NAS owner still performs live allocation, transport,
mount, lane ownership and capacity checks before any real write.

## Binding into the reviewed helper

After read-leasing the new RAM and layout receipts and approved budget, retain
every original descriptor and call:

```python
binding = runtime.bind(info_module, all_held_sources, existing_eight_role_refs)
# Later, only inside canonical owner integration and admitted NAS capture:
# checkpoint_module.capture_private_checkpoint(
#     binding.adapter, binding.reservation, fresh_private_output)
```

The eight roles remain exactly `controller`, `qemu`, `ram_observation`,
`info_header`, `info_parser`, `layout_receipt`, `budget`, `checkpoint_helper`.
Extra adapter, OwnedQMP, compiler and input sources remain in the held tuple.
Binding checks the leased observation against a fresh exact paused observation
of the same child and checks the nested layout proof and budget pins. Every
subsequent `observe_ram()` reobserves the actual geometry/version and rejects
drift. The helper-facing call permits only `stop`, `query-status` and bounded
`pmemsave`; dumps require a complete observed RAM span and a fresh private
precreated file under the separately approved lane. The adapter holds the
verified destination open and sends QEMU `/proc/<controller-PID>/fd/<FD>`;
QEMU therefore selects that inode even if a pathname changes during an
ownership check. The helper keeps its original canonical filename for
independent readback. Identity, privacy and exact extent are rechecked before
returning, and the descriptor remains held until the QMP request completes.
The real owner integration must retain Linux procfs visibility/permissions
for its same-UID QEMU child; this host suite models that request, and the
diskless protocol probe did not exercise `pmemsave`. Single captures remain
at most 16 MiB, and aggregate physical requests cannot exceed the separate
disk-plus-capture reservation. Failed requests remain charged.

Small proof files publish from verified held descriptors, with actual read
leases, exact serialization/inode checks, file and directory fsync, and no
overwrite. Source SIGIO handling is chained/restored. A failed publication or
terminal close invalidates only this producer's canonical inode with
best-effort cleanup; crash durability cannot be promised if the filesystem
rejects fsync or access. Partial files remain private and unaccepted.

Binding records always leave controller wiring, VM/Windows boot and private
disk capture false. The existing checkpoint helper's runtime, shutdown,
cold-boot persistence and live-flush flags remain false. A real controller
integration receipt and an actual Windows-created file surviving a new cold
boot from a captured disk are still required.

## Host checks and limited protocol evidence

```sh
PYTHONDONTWRITEBYTECODE=1 python3 shizukudos/supervisor/native_win98/tests/test_private_checkpoint_adapter.py
```

The host tests use real Popen/pidfd/Unix peer credentials, regular files,
leases and C compilation. Their QMP provider, QEMU reference, physical 4 GiB
layout and approved budget are explicitly modeled; no actual QEMU, NAS,
Windows media or disk capture occurs in this suite. Any separately admitted
64 MiB diskless, networkless, stopped Q35 protocol probe must retain a separate
private receipt and cannot upgrade those host-model results or any Windows acceptance
flag. The sole retained probe at `build/private-adapter-probe/receipt.json`
observed the prior adapter SHA
`64c25b4994b6ec0b1a65ed6dcbd0c06ec94148d27a0016462b77dc2c7430ed2e`.
The subsequent execution/output/destination repairs have host evidence only;
that older runtime receipt does not prove the changed adapter executed under
QEMU, and its older layout command schema cannot bind this revision.
Keep all raw runtime/disk evidence private and outside public m98/ISO.
