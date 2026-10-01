# Task6: Kernel32 per-CPU scheduler foundation

Review candidate in own linked tree `/root/Win98-Modern-k32-smp-163f-20261002`,
branch `codex/k32-smp-163f-20261002`, base
`3cbc1f8b8b4b2b3f7f3586441ed7f6cc2341c9ee`. No canonical/boot mutation and no
commit yet. Implementation is a foundation used by the existing UP scheduler,
not native AP execution, integrated SMP, or Windows 98 product completion.

Production changes: bounded 32 CPU records and per-CPU FIFO queues; separate
ready/wait links; TCB affinity and `on_cpu` ownership; common short ticket admission
with local IRQ masking; CPU0-owned UP clock. Equal affinity preserves FIFO;
foreign/zero/offline/invalid active-owner masks reject without mutation. Runtime
AP registration returns unsupported and the actual online mask stays 1.

Selector 0x30 is a new private kernel GS data descriptor; Kernel32 previously used
only selectors 0x08..0x28. A trusted BSP anchor supplies CPU identity without
CPUID, MSR or APIC assumptions. GDT load and every interrupt/syscall entry load
trusted GS before C; interrupt return restores the interrupted GS, including
ring3. Context switching releases the ticket before changing ESP. Assembly then
calls `sched_switch_complete` on the destination stack, before POPFD, to clear
outgoing ownership and publish READY exactly once. Wakeups during handoff cannot
queue a live stack; join cannot reclaim a zombie while `on_cpu` is owned. Stack
allocation/reclamation run outside the ticket. Existing finite 64-bit deadline
helper and arithmetic are unchanged.

Evidence under `build/k32-smp-final`:
- Baseline runtime RED: `build/k32-smp-red/host/result.json` reports both absent
  production APIs and queue interface, not compiler/infrastructure errors.
- GCC and Clang ASAN/UBSAN each pass 25 actual scheduler/IRQ-boundary checks,
  14 actual queue checks, 76 existing deadline assertions, and 17 process
  publication assertions. Six pthread owners perform 12,000 bounded queue
  attempts and conserve all 48 unique TCBs. Host operations do not execute APs or
  guest stacks. Compiler-MM project closure, compiler driver and executable are
  pinned before/after each proof.
- `negative-controls/result.json`: four private copied-source controls pass:
  unmodified positive; omitted ownership release; omitted offline affinity
  validation; and admitted live stack. Each mutant fails its exact production
  assertion. Shipping sources remain unchanged throughout.
- Fresh single Kernel32 profile compiled every unit with `-m32 -march=i486` and
  `-Werror`. The normal publication runner pins 37 profile inputs before/after
  compilation, then validates exact membership/hash and BIN/ELF/stub before and
  after launch. Receipt: `kernel32s-build-result.json`.
- Actual KVM and TCG runs both pass 12/12 gates (nine native gates and three
  provenance gates), with 22 guest PASS checks and zero failures. New native CPU,
  affinity, AP-gate and queue assertions execute before and after actual ring3
  syscalls/#GP/#PF, while preemption/mutex/sem/sleep/MM/heap tests also pass.
- Additional explicit TCG `-cpu 486` attempt is infrastructure FAIL: this host
  QEMU reports `unable to find CPU model '486'` before executing the boot stub;
  serial is empty. `run-i486` preserves that result and stable inputs. No true
  486 runtime acceptance is claimed. Successful native controls use `-cpu max`.

Exact hashes, commands, source archive and receipts are in `handoff.json` and
`reviewed-inputs.zip`. Normal native commands:

```
python3 shizukudos/tests/run_k32_cpu_host.py --out build/k32-smp-final/host-gcc
python3 shizukudos/tests/run_k32_cpu_host.py --cc clang --sanitize --out build/k32-smp-final/host-clang-v2
python3 shizukudos/tests/run_k32_publication_guest.py --build --kernel-dir build/k32-smp-final/kernel32s --accel kvm --out build/k32-smp-final/run-kvm
python3 shizukudos/tests/run_k32_publication_guest.py --kernel-dir build/k32-smp-final/kernel32s --accel tcg --out build/k32-smp-final/run-tcg
```

AP owner handoff remains required: distinct perCPU GDT/TSS/anchor/stack resources,
trusted unique logical-to-physical identity, Supervisor vAP/IRQ/IPI protocol,
allocator/process/wait synchronization, runtime clock ownership and reschedule,
address-space generation shootdown with each target's invalidate+ack before page
reclamation. The generic internal host queue initializer is not a supported AP
activation API. Do not call the BSP initializer on an AP. Global ticket admission
is a correctness foundation; fine-grained locks/load balancing and actual K32
AP dispatch remain subsequent work. Root integrates after independent review.
