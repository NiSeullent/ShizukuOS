# Supervisor CPU-local VMX ownership foundation

Owner:163f root; isolated branch based a269fb5. Own vmx.c/vmx.h, one run_slice load call in domain.c, new vmx_cpu_state.h and dedicated host tests. No main/kdom/Win98 profile or kernel scheduler/allocator edits. Peer foundation source freeze remains independent.

Problem: a single global VMXON page and control-MSR cache cannot support multiple physical CPUs; vCPU loads have no CPU ownership fence. Implement immutable physical-APIC-to-logical mapping, separate aligned VMXON/control/host-table state per CPU, monotonic lifecycle, and CPU-bound VMCS admission BEFORE VMPTRLD. Capture live host GDTR/IDTR/TR on each initializing CPU; reject shared descriptor state between CPUs. Keep native Win98 on CPU0, permit no VMCS migration or CPU hotplug/reinitialization. Ordinary current boot initializes one BSP; this does not introduce Supervisor AP startup or virtual AP emulation.

TDD: actual C policy/lifecycle tests must reject duplicate/unknown identities, topology replacement, wrong/offline CPU binding, repeated initialization, shared host tables and retired CPU reuse; run GCC and Clang sanitizers. Native Supervisor source compile must include real consumers and unchanged assembly offsets. Real VMX/AP execution remains required separately. Preserve every initial RED and exact source/tool/artifact closure.

Primary architecture source: Intel SDM Volume3C, VMCS/VMXON region ownership and VMCS activation/migration rules, https://cdrdv2-public.intel.com/774497/326019-sdm-vol-3c.pdf. Each CPU uses a separate VMXON region; VMCS migration requires explicit VMCLEAR and is outside this foundation.
