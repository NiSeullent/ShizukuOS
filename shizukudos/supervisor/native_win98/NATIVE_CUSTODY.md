# Private native task custody

This is an explicit testing controller, never automatic normal boot. It does
not verify Windows, the replacement DOS runtime, SMP, applications, persistence
or an ISO. A successful host test only exercises Linux process/descriptor APIs.
No checkpoint capture or prospective checkpoint wiring is enabled here.

The reviewed implementation plan is: reproduce the old launch/log-close error;
add bounded inherited seqpacket RPC; admit immutable origins and frozen source
bytes; give the independent guardian the actual target Popen and pidfd; place
controller/target in a fresh delegated child cgroup before exec; retain custody
through all failed cleanup; test actual small host children and obtain independent
review. Root owns source commits and real VM authorization.

`run_vm.py` must be invoked by `task_custody.py`. Its ordinary CLI refuses a
missing inherited custody endpoint before modifying the private plan. The four
helper identity keys stay `native_win98/build.py`, `native_win98/prepare_vm.py`,
`tools/qemu.py` and `tools/shzinfo.py`, each prefixed with `shizukudos/`.

The guardian manifest schema is `shizukuos.native-custody-manifest.v1`. Required
keys are `schema`, `plan`, `repo`, `sources`, `lineage`, `producers`, `limits`,
`timeout`. All file pins are exact `{path, bytes, sha256}` with canonical absolute
nonsymlink paths and nonzero lowercase SHA256. `sources` has these nine keys:

- `shizukudos/supervisor/native_win98/build.py`
- `shizukudos/supervisor/native_win98/prepare_vm.py`
- `shizukudos/supervisor/native_win98/run_vm.py`
- `shizukudos/supervisor/native_win98/owned_capture.py`
- `shizukudos/supervisor/native_win98/custody_rpc.py`
- `shizukudos/supervisor/native_win98/task_custody.py`
- `shizukudos/supervisor/native_win98/disk_lineage.py`
- `shizukudos/tools/qemu.py`
- `shizukudos/tools/shzinfo.py`

`lineage` orders the actual constructor profile, launch receipt and replacement
preparation receipt. `producers` orders independently approved source-profile
and constructor source pins. The guardian executes the admitted lineage parser
from held bytes and leases the original disk, selected disk, all profile payloads,
boot template, DOS receipt and retained DOS build source pins. It also expands
all builder source snapshots and six original input pins plus five preparation
input pins. Writable owned `esp.img` and `OVMF_VARS.fd` are never read-leased.
The original images and source inputs remain independently protected.

Optional `preparation_receipt` pins the separate outer
`shizukuos.actual-native-vm-preparation.v1` receipt with status
`ACTUAL_FRESH_PRIVATE_VM_INPUTS_PREPARED_FROM_SELECTED_ESP_NOT_RUN`. This binds
`vm_plan_derived_from_actual_return`, `actual_prepare_return_snapshot`,
`preparation_runtime_helpers_sha256`, the two executed preparer source hashes,
the six originals, selected ESP result/terminal/builder pins and frozen header.
The canonical plan is never rewritten to add helper metadata. The outer receipt
must retain its exact false runtime/publication flags and actual lease/readback
facts. Missing optional preparation helper binding is recorded honestly.

`limits` supplies literal `memory.high`, `memory.max`, `pids.max`, `cpu.max` for
the task child leaf. Root must select the real limits and actual guardian unit.
The guardian checks current finite ancestor memory/PID headroom, 6 GiB host
admission/2 GiB running floor, 17 GiB storage reserve and existing capture byte caps.
The original recipe remains 4 GiB guest, one CPU, no network. Observation defaults
to 300s, cleanup retains 16s. Preflight and post-reap finalization each have an
explicit finite budget equal to the selected observation timeout; neither
extends guest execution. The guardian unit must actually be active, delegated,
its MainPID must be this process, and RuntimeMax must be infinite. The guardian
moves into a surviving sibling leaf; both controller and target enter the fresh
capped child leaf before exec. The fresh owned delegated parent enables its
task controllers explicitly; no shared ancestor limits or global configuration
are changed.

The guardian itself and RPC module must execute independently pinned held
bytes. The caller supplies `__executed_sha256__` in each module and a callable
`__bootstrap_check__` in the guardian. That check must validate the caller's
held read leases, full admitted SHA/extent/inodes and break latch. Directly
running a mutable script pathname is refused. A root-owned preparation/launch
caller can use the same held-source loader pattern as its other reviewed
producers: open/pin/read-lease the two modules, hash all bytes, create a module
named `native_custody_rpc`, compile its captured bytes, register it in
`sys.modules`, then compile guardian bytes with its declared `__file__` and
`__name__='__main__'`. Keep those initial leases until guardian returns; include
all actual invocation/tool/limit evidence. No caller should invent the pins.

Only the inherited Unix socketpair is an endpoint; there is no public socket
listener or arbitrary command/PID API. Every packet has actual kernel sender
PID/UID credentials, exact schema/order and at most 16 KiB/three descriptors.
Only one independently reconstructed recipe can launch. Three distinct writable
anonymous log pipes are validated and their received FD numbers replace only
the serial/debugcon positions. A gated admitted launcher obtains the target
pidfd before releasing descriptor-based target exec; pidfd allocation failure
cannot execute the target. Source descriptors close across target exec.

Frozen project modules are admitted before imports and compiled from received
held bytes, including prepare_vm's nested builder import. The C/Python evidence
layout uses admitted header bytes from stdin and executes a sealed memfd probe;
it never reopens a replaced project header. Python/host shared libraries and the
compiler SDK are not represented as fully source-closed product builds here.

QMP admission checks the actual socket peer PID/UID against the held target
pidfd, executable inode, argv, starttime and cgroup. The guardian holds a duplicate
socket but never reads or writes that shared stream. Controller-loss recovery
uses only owned pidfd signals. Successful spawn acknowledgment sets controller
PID/execution truth before fallible log closure. A lost ACK records uncertainty;
only the independent guardian can report whether target exec was observed.

Actual target and controller exit status comes from parent `waitid(P_PIDFD)`, never CPython's ECHILD
fallback zero. A never-released launcher without a pidfd can be actually waited
without claiming target execution. Foreign reap with an already-dead original
pidfd is failed/unknown-status physical cleanup; it never becomes a successful
collection. Native collection must also be paired with the final guardian
receipt; the controller receipt alone is insufficient.

EOF, cancellation, timeout, bad packets, lease break and failed state reads
cannot authorize releasing inputs while the target or a confined task member
could execute. Recovery keeps a directory FD and checks the original leaf inode
and caps before accepting empty direct membership and recursive
`cgroup.events` populated=0, or issuing descriptor-relative recursive
`cgroup.kill`. Failed controller status, membership or cgroup reads stay in the
same resident recovery loop.
If cleanup still cannot establish exit, a bounded unresolved receipt is attempted
and the guardian stays resident with the same union/pidfd. Kernel-forced lease
revocation is recorded as failed integrity, not as uninterrupted protection.
Do not kill that guardian to make a failed job appear finished.

Host controls use actual Python children, pidfds, socket credentials/SCM_RIGHTS,
read leases and task cgroups. They model QEMU/VMCS only in the retained ordinary
controller regression cases. The tested kernel refuses cgroup rename; the empty
foreign-leaf control explicitly models a changed path selection using two actual
delegated leaves and a live descendant. The finalization deadline control uses an
injected elapsed clock after actual target reap. Neither is a Windows runtime test.
