# Kernel64 CPU queue foundation

Own linked branch starts4bd5de1. Preserve the existing native policy:32 priorities,
FIFO heads,32 tick aging, basequantum1..16, independent fixed4eligible-tick aged
allocation and all original useful-work/regression thresholds.

First runtime RED against actual sched.c/internalqueue interface; then move the
existing queue/policy implementation into bounded CPU records and consume it from
UP execution. Six concurrent host owners exercise the same production queue
operations, including foreign/offline/active-owner rejection and conservation.

Coordinate CPU identity with shz_smp_this_cpu() owned by existing smp_boot backend;
GS remains per-thread NT KPCR/TEB. No AP registration until architecture, interrupt,
syscall/stack, allocator/process/object/wait/TLB and Supervisor contracts permit.
An absent physical-map provider cannot produce a fabricated AP identity.

Short common ticket admission requires local IRQs disabled and releases before
context switching or external callbacks. Outgoing stack remains on_cpu until
saved/inactive; destination-stack callback is contingent on ASM owner approval.
Existing global current/syscall stack symbols remain explicit CPU0 compatibility
until their owners supply actual perCPU entry/exit paths.

Pin project compiler-MM inputs/tools/executables before/after host proof and full
normal kbuild closure/artifacts/helpers around fresh UP nativeKVM/TCG proof.
Independent review precedes ownbranch commit; root owns canonical integration.
