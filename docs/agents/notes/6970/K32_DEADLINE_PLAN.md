# Kernel32 finite deadline repair plan — 6970

Windows 98 retains VMM scheduling. This repair is for the existing uniprocessor Shizuku Kernel32 backend worker scheduler; it adds no Windows scheduler or SMP claim.

## Existing failure and ownership

The current production scheduler multiplies uint32 milliseconds by1000 before dividing by TICK_US, and stores the absolute result in a uint32 wake_tick despite a uint64 clock. Long requests can expire immediately; a finite deadline of2^32 truncates to the zero infinite-wait sentinel. Source audit alone is not a RED execution.

This lane proposes only kernel32/sched.c finite sleep/semaphore expressions, kernel32/k32.h wake_tick width, a new abi/shz_sched_deadline.h helper and dedicated tests. Session163f owns Kernel64 scheduling. Fd5c is investigating a different Kernel32 thread/process publication race; root exchanges exact hunk ownership before production edits. Preserve both changes by scoped merge.

## Test first

1. Author a host fixture including the actual complete k32.h and production sched.c. Substitute privileged IRQ/CR3/TSS/stack-switch boundaries only; do not substitute deadline arithmetic, queues, thread layout or sched_tick/sem_post logic.
2. Freeze source closure: fixture, runner, sched.c, k32.h, khc.h, shz_abi.h and start.asm. The existing main KVER-only header update can be imported as an explicitly recorded baseline before RED.
3. At fresh20GiB+8MiB admission run real compiler and fixture with bounded output and a live resource guard. A compile/harness/resource failure is not RED. Preserve actual unchanged-production assertion failures.
4. Cases cover4,294,968ms and UINT32_MAXms; clocks before/after2^32 including a deadline that truncates to0; sleep0 minimumone tick, timeout0 minimumone tick and sem_wait indefinite0; actual wake immediately before/at expiry; timeout/post both orders with waiter links, timeout marker and token count checked. Keep context-switch assembly stack pointer offset0.

## Small production change after RED

Widen wake_tick to64 bits. Replace only finite deadline expressions with one checked common conversion/addition helper. Convert positive uint32 tick intervals using quotient/remainder without unchecked multiplication/addition; clamp unrepresentable finite deadlines to UINT64_MAX. Preserve minimumone tick and the explicit zero infinite-wait sentinel. Leave mutex policy, process publication and Kernel64 untouched.

The clock at UINT64_MAX has no representable later absolute time. Saturation is a documented finite-clamp policy, not a proof of full counter rollover, arbitrary-duration modular ordering or monotonic clock calibration. Do not test sched_tick past that endpoint and infer correctness.

## GREEN and integration

Add the helper to exact source closure. Run actual production fixture normal and ASan/UBSan, actual compiler argv/hash/version/exits, identical meaningful assertions, no sanitizer errors, before/after closure hashes, bounded self-inclusive receipt and resource samples. An independent reviewer checks production code and the host-only hardware substitutions.

Share tested scoped commit with canonical master and sole main publisher. Re-run merged Kernel32 build/standalone regressions including fd5c publication repair when resources permit; HOST arithmetic/queue results do not establish assembly switching, hardware preemption, VMM integration or actual Windows98 boot.
