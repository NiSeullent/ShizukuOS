# Kernel64 GetContextThread permission and lifetime checks

`k32_get_context_thread()` requires the existing typed thread handle policy and
`THREAD_GET_CONTEXT` (0x0008) before copying caller memory. A query-only,
synchronize-only or zero-access handle cannot read a thread context. The right
matches the documented
[GetThreadContext access contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext).

The function retains the thread object across input and output copies. Under
the current UP IRQ guard it resolves the live TCB again, checks reciprocal
object/process/PID/TID identity and lifecycle state, then copies registers and
FPU state into local buffers. A detached or recycled TCB cannot provide another
thread's state. All return paths release the retained reference. Existing
ContextFlags conversions and unrequested caller bytes are preserved.

Run the dedicated production-source fixture in a fresh output directory:

```sh
python3 shizukudos/tests/test_get_context_thread.py --out build/get-context-check
```

The fixture extracts the actual object/handle/ref/close/detach/function bodies
and full process/TCB/frame layouts. It models account-admission decisions,
current-thread/IRQ boundaries and user-copy scheduling. It checks 22 cases,
including insufficient rights, wrong types, fault cleanup, close/detach,
termination/reuse and exact authorized context output. It also compiles the
full sysk32_proc.c for both native kernel profiles with GCC and Clang.

Initial component validation passed 940 checks each under GCC and Clang
ASan/UBSan. GCC sanitizer linking was unavailable because installed linker
scripts point to missing runtime libraries; the runner records this separately.
The original NT settings host fixture also fails at the pinned baseline because
its auth/scheduler adapters are stale; its success is not claimed by this patch.

This is Kernel64 component evidence. Full authentication, Windows98 frontend
integration, kernel/guest execution and SMP lifecycle safety need separate
acceptance. Valid pseudo-current FXSAVE and output-copy-time detach were reviewed
in source but are not separately exercised by the initial fixture. Actual
Windows98 on ShizukuDOS remains the final product.
