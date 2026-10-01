# Owned native Winsock child observer

`SPWAIT.EXE` starts only `C:\GOPLAB\SPROB.EXE` with the parent's fresh 16–80
character ASCII nonce. It requires its exact own path `C:\GOPLAB\SPWAIT.EXE`,
real Win98 SE version readback and a previously absent `C:\GOPLAB\SPWAIT.LOG`.
Each Win32 checkpoint is flushed and closed. It inherits no handles, uses the
explicit child application path and working directory, and retains only the
handles returned by this invocation's `CreateProcessA`.

The observer waits at most 90 native seconds, requires `WAIT_OBJECT_0` and
`GetExitCodeProcess=0`, and closes both process/thread handles. This observes
termination after the child's CRT teardown; the child's own final log alone
cannot do that. Timeout, failed wait, or logging failure triggers termination
and a bounded five-second reap of only that owned child. Reaping still occurs
when termination races a normal exit. No process lookup, peer termination,
provider change, remote connection, Steam payload or account action occurs.

The separate observer build script reuses the preserved Winsock probe builder's
actual guard/hash helpers. It requires unchanged 20 GiB + 256 MiB + 8 MiB
admission, continually samples the 20 GiB floor, caps private output at 8 MiB,
and gives compiler children 45-second CPU / 2 MiB file / zero core limits.
It records actual compiler, transitive headers, source and PE import provenance.
No build starts a child probe, socket endpoint or VM.

```text
python3 -B tools/modern_apps/steam_win9x_socket_probe_observer_build.py --output build/steam-socket-prerequisite-83bd/observer-pe-v1
python3 -B tools/modern_apps/steam_win9x_socket_probe_observer_fixture.py --observer-build build/steam-socket-prerequisite-83bd/observer-pe-v1 --output build/steam-socket-prerequisite-83bd/frozen-native-v1
```

The fixture tool freezes the original successful `SPROB.EXE`, this observer,
both actual build/header/import receipts, their exact source inputs and origin
bindings. It generates a new nonce and stages two input paths / two output logs
for a later parent-owned Win98 IO.SYS/GOP trial. It starts no VM and requires no
guest NIC. All native behavior and full Steam flags remain false until actual
parent evidence is reviewed; even a genuine socket prerequisite pass cannot
establish current Windows Steam compatibility.
