# Optional owned native-controller checkpoint

The prospective `run_vm.py` integration is explicitly opt-in. Canonical 163f
still owns promotion and actual native execution. The reviewed checkpoint API
and adapter remain unchanged. Without either optional argument, the controller
keeps the existing original Microsoft DOS control, four-helper source identity,
256 MiB diagnostic total, 1 GiB preflight budget and default finalization.

**Actual optional-controller execution is not admitted.** This is a prospective
host-verified component patch. The inherited bounded cleanup can fail to reap
its child; CLI exit then releases its source/output leases and pidfd. Before
real optional-controller promotion, an external resource owner must retain
those exact resources across an unresolved child and controller exit until
exact reap. This patch supplies no custody implementation. In-process retained
objects would not protect resources after CLI exit. Successful host collection
does not resolve this runtime admission blocker.

Every optional controller receipt carries machine-readable readiness:

```json
{
  "schema": "shizuku.checkpoint-controller-readiness.v1",
  "actual_optional_controller_admitted": false,
  "external_unreaped_child_custody_verified": false,
  "blocking_requirement": "external custody must retain exact process/pidfd/leases across unresolved-child and CLI exit"
}
```

The owner supplies both arguments:

```text
--checkpoint-reservation <absolute-private-manifest.json>
--checkpoint-reservation-sha256 <exact-manifest-SHA256>
```

The controller never writes an approval or invents an owner callback. The
manifest and referenced budget are separately supplied, source-pinned private
inputs. The manifest is a bounded, owned mode 0600 file with exactly these
fields:

```json
{
  "schema": "shizuku.checkpoint-controller-reservation.v1",
  "private": true,
  "approved": true,
  "scope": "private_ram_checkpoint_only",
  "budget": {"path": "<absolute-budget.json>", "sha256": "<64 hex>", "bytes": 1},
  "compiler": {"path": "<canonical-compiler-path>", "sha256": "<64 hex>", "bytes": 1},
  "sources_sha256": {},
  "checkpoint_output": "<exact-fresh-private-output-directory>"
}
```

Replace all placeholders and byte sizes with actual observations. The exact
source map contains SHA256 values for these nine paths:

- `shizukudos/supervisor/native_win98/build.py`
- `shizukudos/supervisor/native_win98/prepare_vm.py`
- `shizukudos/tools/qemu.py`
- `shizukudos/tools/shzinfo.py`
- `shizukudos/supervisor/native_win98/run_vm.py`
- `shizukudos/supervisor/native_win98/owned_capture.py`
- `shizukudos/supervisor/native_win98/private_checkpoint.py`
- `shizukudos/supervisor/native_win98/private_checkpoint_adapter.py`
- `shizukudos/supervisor/include/shz_info.h`

The header must match the actual source-bound ESP builder. Referenced files
must use canonical paths. The separately approved budget retains the reviewed
`shizuku.private-checkpoint-budget.v1` schema: full logical 2 GiB disk, bounded
helper capture allowance up to 16 MiB, exact total, at least 17 GiB retained
space, explicit NAS lane and bounded timeout. The output must be fresh inside
that actual approved `/fada/replacement` or fresh authorized evidence lane,
with owned mode 0700 parents. No existing checkpoint, original media, ESP or
installed disk is overwritten. Budget parsing does not create approval; real
live capacity is checked before launch and repeatedly by the frozen producer.

The optional branch retains canonical original and frozen source descriptors.
A small controller-owned bootstrap read lease protects the build helper;
subsequent leases use that exact evaluated helper. Imports execute the exact
SHA-checked descriptor bytes while leases remain held. The actual nested
C/Python layout proof runs before QEMU, under compiler/header/parser leases
and fresh host/cgroup admission. Compiler helper/include/library closure
remains explicitly unverified.
Every observable finite ancestor memory and process limit must retain the
stated proof reserve. Missing root-controller files are recorded as absent;
the controller does not invent numeric bounds for them.

The controller creates its existing Popen and OwnedQMP. The adapter receives
that exact process, actual pidfd, monitor, canonical source descriptors and
real lease callbacks. Current process starttime/cmdline/executable and ongoing
QMP peer credentials are checked. Acknowledged `stop` and current exact
`running=false/status=paused` precede the actual owned FlatView observation,
binding and raw captures. Physical ranges come from the running child's
complete bounded FlatView, including high RAM and holes.

The checkpoint timeout plus five seconds finalization is reserved **within**
the original controller timeout; at least twenty seconds observation remains.
For example, a 120 second approved checkpoint timeout needs an overall timeout
of at least 145 seconds. The optional branch preserves the original QMP
absolute deadline throughout capture and cleanup. Each existing QMP request
still has its five second limit. Slow NAS/QMP or an exhausted deadline fails;
the integration does not extend a live adapter deadline or relax diagnostic
or source budgets.

The frozen producer validates current SHZ info, actual loader-map coverage,
paused state, every bounded chunk, independent full extent/SHA and source
identities before publishing its private receipt. The controller retains
read leases on the resulting raw disk and canonical producer receipt through
its owned quit/reap and final provenance checks. It remains stopped until
cleanup; it never resumes a guest. Failed inputs, ownership, pause, proof,
capacity, capture or cleanup leave controller acceptance false, with retained
failure evidence. A producer receipt alone is insufficient controller or
Windows acceptance.
Each layout, FlatView and checkpoint proof is admitted against the exact
canonical serialization of its producer's returned record, rather than a
fresh self-hash of whatever bytes appear at its pathname after return.

After reap, the controller independently reads every still-held descriptor,
checks its full SHA and exact extent against its original pin, rechecks the
canonical pathname/inode and lease, and records per-descriptor results. This
audit also obeys the original absolute deadline. A late output swap, expired
deadline or cleanup failure clears controller checkpoint acceptance. The
output-through-reap flag is established only after these checks succeed.
An escaping finalization error uses the retained attempt record. Its failure
receipt preserves actual launch, PID, reap and cleanup observations; it cannot
relabel an already launched attempt as a prelaunch refusal. Acceptance and
runtime readiness remain false on that fallback.
The optional branch records launch and PID immediately after successful
`Popen`, before log-writer closure or another fallible finalization operation.

All Windows GUI, VMM boot, ShizukuDOS replacement, modern applications,
cold-boot persistence and live storage-flush flags remain false. This source
does not establish that Windows created or reopened a durable file. The old
diskless Q35 probe belongs only to adapter SHA `64c25b...`; it is not evidence
that this controller or the repaired adapter executed under QEMU.

Host checks execute the real controller entry. Default cases model the child;
opted cases use actual Python Popen/pidfd/Unix peer credentials/Linux source
leases and actual nested C compilation, with an explicitly modeled QMP
provider, RAM and capacity. One bounded model changes disk/chunk constants
only in the test-loaded module to 8 KiB/4 KiB and runs the frozen producer body
to exercise output leases/provenance. That is host evidence, with no actual
QEMU, Windows, NAS or guest disk capture. Production requires the full 2 GiB
extent; no test model may upgrade its acceptance flags.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 shizukudos/supervisor/native_win98/tests/test_controller_main.py
```

Keep all runtime receipts, guest disk bytes and installed media private and
outside GitHub, public m98 and final ISO publication.
