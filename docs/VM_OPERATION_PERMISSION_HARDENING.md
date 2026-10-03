# Kernel64 virtual-memory operation permissions

The allocation, free and protection mutators now require the existing typed
process-handle policy and PROCESS_VM_OPERATION (0x0008). A query/read/write-only,
synchronize-only or zero-access handle cannot change a target address space.
This matches the documented process right for
[VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex),
[VirtualFreeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)
and [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex).

A retained process-object reference covers input and output copies. It preserves
the process slot, while an explicit process/object/PID/PML4/lifecycle check also
rejects teardown or a changed address space. That check and the VAD mutator run
within the existing UP IRQ guard; the three VAD paths already use this guard
and do not sleep. User copies and final object release remain outside it.
Permitted calls preserve their VAD arguments, returned results and output order.

Run the production-source component fixture in a fresh output directory:

```sh
python3 shizukudos/tests/test_vm_operation.py --out build/vm-operation-check
```

Its 8 MiB ceiling covers that invocation's output directory. Unrelated parent
build files are not counted or scanned. The fixture extracts actual process/
object layouts, handle/ref/cleanup bodies, mutators and public VAD IRQ wrappers.
Account decisions, caller-copy scheduling and locked VAD results are controlled
boundaries. It checks 84 cases and compiles the full syscall.c for Supervisor
and standalone profiles with both GCC and Clang. The final component run passed
3195 checks each under GCC and Clang ASan/UBSan.

Denied requests avoid base/size buffer copies and VAD work inside these functions.
The existing dispatcher retrieves extra stack arguments before calling allocate/
protect, so this patch does not claim zero caller-memory reads across dispatch.
Queries and routing retain their existing implementation. These tests do not
establish real page allocation, SMP lifetime safety, guest execution, Windows98
integration or final ISO acceptance. Actual Windows98 on ShizukuDOS remains the
product; account/authentication and hardware integration require their own checks.
