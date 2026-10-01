# Native numeric WAMR child observer

The additive observer derives the independently tested single-child CSS
observer control flow without changing its original sources or stages. This
profile exclusively runs `C:\GOPLAB\WAS13PR.EXE` from
`C:\GOPLAB\M98WARUN.EXE`, records `WARUN.LOG`, captures child stdout/stderr
in `WAOUT.LOG` and requires `WA13.LOG` to be absent before launch.

All output files are freshly created. The observer identifies actual Win98
SE4.10.2222 and its exact own path before creating the child. It retains only
its own CreateProcess handle, obtains the full DWORD child exit, flushes output
and closes its handles. A60s timeout terminates only that owned child and waits
up to5s for reaping. Failed creation, exit query, wait, reaping, write, flush or
close is unsuccessful. Never control another process or accept a stale log.

Normal and ASan/UBSan host controls execute this exact profile's production
control flow across18 injected scenarios, including crash DWORDs, timeouts,
stale/raced logs, short writes and final supervisor flush/close failure. These
are Windows API doubles; they do not prove installed Win98 behavior. The builder
snapshots current source/logs and requires complete raw i486 executable-byte
coverage plus actual OEM PE/import/relocation/stack gates. It starts no VM,
downloads nothing and changes no global system setting.

`supervisor.requested-exit-code` precedes final log flush/close/ExitProcess. It
must remain distinct from the actual supervisor exit, which requires a separate
outer observer. Actual child exit0 is necessary along with the numeric probe's
complete ordered checks and fresh stopped-run readback. A QEMU exit, requested
exit or terminal STATUS cannot replace the actual child exit.

Native execution remains unverified until a frozen private-input stage and
strict stopped-run verifier have been prepared and an actual new offline Win98
trial passes. Browser WebAssembly, complete Wasm, WebGL/WebGPU and modern apps
remain mandatory unfinished work. Original images, caches, source archives,
failed trials and previous component stages remain preserved.
