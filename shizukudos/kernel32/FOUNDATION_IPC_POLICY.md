# Kernel32 foundation and IPC policy

The captured native attempt11 selected `shz.foundation=win98`. Kernel32's
entry point accepted that handoff, but IPC initialization used only the older
`shz.k32-service=win98` parser and panicked before starting its server.
The observed exit99 disables the Kernel32 backend. SeaBIOS and the inner disk
boot continued afterward; this does not establish the cause of their later
real-mode behavior or establish Windows boot.

The repair uses one Kernel32 runtime policy decision in both entry
and IPC initialization. It preserves a negative foundation decision, falls
back to the existing legacy parser only when foundation returns0, and leaves
the original QA interpretation intact. Neither policy creates a Win98 owner
or a channel. An admitted persistent service must continue refusing QA
`SESSION_END` requests with `SHZ_E_UNSUPPORTED`.

`tests/test_foundation_ipc_host_fada.c` includes the actual entry and IPC
implementations plus the existing endpoint harness. Its native fixture maps
channel0 at the actual ABI GPA with the full region extent, generation7, a
complete bootinfo, and the real channel/ring initialization. Scheduler and
privileged hypercall boundaries are modeled; the IPC requests and replies
use production rings. Controls cover foundation startup, persistent service
behavior, legacy startup, QA/ABI1.0 fallback, malformed handoffs, and existing
endpoint cases. The old implementation must fail both positive foundation
consumers before the repair is applied.

The first bounded epoch stopped at a host fixture compiler warning before
any behavior controls ran. Its failed result, terminal and source snapshots
are preserved separately. With a volatile expected exit value across the
modeled entry return, the unchanged production sources then failed precisely
the two positive foundation consumers. The other 30 controls, existing
foundation policy suite and 32-bit entry/IPC object compilation passed.
The repair is validated against the same controls in a fresh bounded epoch;
exact source, result and PID1 terminal pins are recorded in the separate
build handoff. Source and primary tool descriptors remain held through final
full SHA checks and are closed before the returned result is published.

The current canonical entry also selects a native AP policy before its
service policy. Its adaptation replaces only the foundation/legacy selection
with `native_policy ? 0 : k32_boot_runtime_service_mode(bi)`. The native AP
policy, snapshot refusal, native-count run and exit, and bypass of IPC remain
unchanged. This tree's earlier entry has no native AP branch; replacing a
canonical entry with this older file would discard that branch. The recorded
canonical source review supplies the narrow hunk for its current file.
Host success will remain component evidence; real Windows98 VMM/USER/GDI/
Explorer, GUI, SMP, modern application and persistence acceptance require
separate actual runtime observations.
