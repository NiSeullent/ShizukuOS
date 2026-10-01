# Kernel32 per-CPU scheduler foundation

Owned branch starts at 3cbc1f8. This slice uses the existing Kernel32 scheduler
and real i486 UP context path. It does not start APs or change the Supervisor ABI.

Production contract:
- Up to 32 logical CPU records, each with FIFO ready head/tail, current, idle and
  outgoing context; separate ready and wait links in each TCB.
- Affinity must be nonzero and wholly contained in the real online mask. Invalid,
  foreign, unonline or active cross-CPU transitions fail without mutation.
- BSP identity is a validated kernel GS descriptor/anchor, not CPUID CPU count.
  IRQ entry restores kernel GS; wrong/unregistered timer owners cannot charge
  BSP time or modify its queue. Online mask stays 1. AP registration is explicitly
  unsupported until architecture/Supervisor and shared-resource owners agree.
- A short common ticket lock protects queue/state admission. Kernel callers mask
  local IRQs before taking it. Never allocate, free, wait or switch stacks while
  holding it. Outgoing context remains owned until ESP is saved and no longer
  executing; assembly then calls a completion hook on the destination stack to
  publish it. No lock survives the switch.
- Existing finite 64-bit deadlines, lifecycle and ring-3 publication remain.

Execution: runtime RED for absent APIs/core; actual production core FIFO,
identity, affinity and concurrent conservation controls; integrate UP selector
and identity/handoff; strict i486 compile; publication/deadline host controls;
fresh source-bound K32 KVM/TCG self-tests. Receipts pin compiler dependency
closure and artifacts before/after execution. Independent review precedes commit.

Remaining AP handoff: unique logical identity, perCPU GDT/TSS/interrupt and stack
resources, Supervisor vAP/IPI ABI, allocator/process/wait locking, global clock
ownership, address-space generation shootdown+ack, reschedule/load balancing.
Host multi-owner queue controls are not native AP execution or Windows 98 SMP.
