# PMA event bridge implementation plan

Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
Chat: `01a0f8ca-65e2-7742-81a0-fada3fa27129`.
User requested rapid parallel implementation and mandatory cross-chat collaboration.

## Product contract

Windows 98 remains the product OS. Actual VMM, USER/GDI, Win16/Win32 and
Explorer own Windows execution and presentation. ShizukuDOS modernizes its
DOS/boot/hardware foundation; Kernel32/64 are backend execution domains.
Windows scheduling stays in VMM, native worker scheduling stays in the existing
Shizuku schedulers. An event bridge explicitly synchronizes the two domains.

The supplied Win98-Modern architecture principles and ShizukuDOS 10 mega
integration specification are the task specification. Existing working paths
and frozen historical evidence remain intact.

## Existing architecture checked against source

- `supervisor/src/domain.c`: domain scheduling and VMX/hypercall dispatch.
- `kernel32/sched.c`: protected-mode native thread scheduler.
- `kernel64/sched.c`: real preemptive native scheduler with process context,
  stacks, FXSAVE, sleep/join and synchronization; currently uniprocessor.
- `ntwrapper/vxd/bridge.c`: existing Win98 endpoint for channel 2.
- `abi/shz_abi.h`, `shz_ipc.h`: ABI 1.1, checked fixed 64-byte message headers,
  SPSC rings, generation/request IDs and shared-pool ownership.
- `kernel64/subsys64.c`: actual process/console service and threaded loopback.
- `supervisor/src/main.c`: opt-in native Win98 domain creation already exists.
  Its presence alone does not prove DOS replacement or a working PMA wait.

## Parallel deliverables

1. New versioned PMA payload/service: negotiated capabilities; manual/automatic
   events; asynchronous wait, signal, cancellation, timeout and owner rundown.
   Preserve the outer ABI and existing W64 opcode behavior.
2. Kernel64 connection: use the existing service thread and transport; retain
   completions until successful publication and add real threaded loopback checks.
3. Independent validation: malformed/stale/duplicate frames, bounded queues,
   event token accounting and completion retention using production code/rings.
4. Root integration: inspect diffs, run host/cross-build/guest checks, commit
   only passing changes, and publish exact commits to the other active chats.

## Verification commands and local effects

All commands execute in this isolated worktree. Host tests write local ignored
build files; kernel builds write `build/shizukudos/`; QEMU uses a bounded isolated
guest without a NIC. A cached project-generated `WIN64.IMG` is copied as an
input with provenance, while changed kernels are freshly built.

```text
python3 -B shizukudos/abi/test_abi.py
python3 -B ntwrapper/vxd/tests/test_vxd.py
python3 -B shizukudos/pma_bridge/test.py
python3 -B shizukudos/pma_bridge/test_transport.py
python3 -B shizukudos/kbuild.py
python3 -B shizukudos/tests/run_k64_pma_bridge.py --accel kvm --timeout 240
```

No source download, dependency installation, global client configuration,
host boot change, remote push or media publication is needed for this lane.

## Acceptance and remaining integration

Completion of this lane requires real production ring/service tests and
Kernel64 execution with unchanged W64 regression behavior. It establishes a
backend synchronization path. It does not establish actual Windows VMM wake,
ShizukuDOS→WIN.COM→VMM→desktop, multi-CPU execution or complete driver families.
Those remain explicit broader integration milestones owned collaboratively.
