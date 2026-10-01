# Native CSS child observer

`M98CSR.EXE` starts only its own adjacent `CSS13PR.EXE` from `C:\GOPLAB`.
It checks the actual Windows98SE version, its own exact path and the absence of
all three logs before starting a child. It records the real child process
handle, wait result and `GetExitCodeProcess` DWORD, checks output flush and
handle closure, and limits termination to that exclusively owned child after a
60second timeout with a separate5second reap bound.

The original control flow derives from this project's GPL2 Trident observer.
Host OS doubles inject18 lifecycle/failure scenarios, including stale output,
crash exit, failed exit query, un-reaped timeout, short writes and final
flush/close failures. Normal and ASan/UBSan tests exercise those paths; native
PE/import/full i486 checks establish a cross-build profile only.

`supervisor.requested-exit-code` precedes final flush/close and `ExitProcess`.
It is not an independently observed actual supervisor exit. Child exit alone
does not establish successful CSS styles, geometry or pixels. Fresh strictly
validated fixture logs and reviewed initial/modified captures are required
separately, using the canonical cold/noNIC/oneQA harness. No browser conformance,
WebGL/WebGPU, installation, registration or unrelated process control is supplied.
