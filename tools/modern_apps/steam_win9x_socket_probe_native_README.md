# Exact Steam socket native controller and stopped review

These tools operate only the already frozen `frozen-native-v1` fixture, hash
`04be7ecedbfb6035c5e3f7fd4d7c6f928f9c025d2faf2d12c30322fbd40b20d9`.
Its never-used nonce is `83bd-steam-socket-72ea2f19be40488a84fb4fc9ef5deb92`.
The exact inputs are `C:\GOPLAB\SPROB.EXE` and `C:\GOPLAB\SPWAIT.EXE`; the
only outputs are `C:\GOPLAB\SPROB.LOG` and `C:\GOPLAB\SPWAIT.LOG`.
The command is `C:\GOPLAB\SPWAIT.EXE` followed by that nonce.

The controller never starts a VM, reads its live disk, changes providers or
connects to a network. Root starts a separate owned native Win98 IO.SYS/GOP
trial named `win98-iosys-gop-steam-socket-83bd-<unique suffix>`. Control requires
the exact manifest/injected hashes, real QEMU UID/executable/start-time token,
the precise owned disk/firmware drives and `-nic none`. Each request requires
the existing queue to be acknowledged; its exact command/keys/name and owned
screenshot are bound to the runner acknowledgement. Another pending controller
is refused. These acknowledgement checks do not establish any application effect.

Every visible transition is a separate invocation with a newly personally
reviewed screenshot. `ack-warning` accepts only stage `boot-warning` and sends
Enter once, then returns. `close-welcome` requires stage `welcome` and sends
Alt-F4 once, then returns. `open-run` requires a ready `desktop` and opens Run
once. `launch` requires a newly reviewed `run-dialog` and submits the exact
SPWAIT command once. No timer assumes a warning became a desktop, closes a
welcome, assumes Run became ready, or finishes the guest. `capture` and
`finish` can operate independently of any launch on the exact owned guest.

For each action, use the same exact run/manifest/PID, its freshly reviewed image,
and the matching stage/action:

```text
python3 -B tools/modern_apps/steam_win9x_socket_probe_native_control.py --run OWNED_RUN --manifest build/steam-socket-prerequisite-83bd/frozen-native-v1/guest-files.json --manifest-sha256 04be7ecedbfb6035c5e3f7fd4d7c6f928f9c025d2faf2d12c30322fbd40b20d9 --qemu-pid OWNED_QEMU_PID --reviewed-image OWNED_RUN/screen-NNN.png --stage desktop --action open-run
```

After native observation and explicit finish, the stopped reviewer checks the
original IO.SYS hash, all ten entry checks, preserved originals, stopped QEMU,
unchanged 20 GiB reserve / 128 MiB actual allocation gate, exact two injected
PEs, 17 frozen receipts and 166 actual MinGW headers for each build. It binds
the controller acknowledgements to the actual runner's records/screenshots,
then checks both fresh stopped logs' nonce, real target readback, all probe
operations and the observer's owned child zero exit after CRT teardown.

```text
python3 -B tools/modern_apps/steam_win9x_socket_probe_native_verify.py --run OWNED_STOPPED_RUN --output OWNED_STOPPED_RUN/steam-socket-stopped-review.json
python3 -B tools/modern_apps/steam_win9x_socket_probe_native_test.py
```

Artifact consistency remains separate from independent parent review of the
actual guest/process/module provenance. Every log-only result and automated
stopped review keeps native execution/prerequisite acceptance and full Windows
Steam false. Authored synthetic logs can exercise consistency/refusal controls
but never become native execution evidence. A genuine x86 Winsock prerequisite
also cannot establish the current Win98-hosted Win64 Steam provider/client,
TLS, login, updates, game operations or full client dependency closure.

The controller pattern derives from the GPL-2.0-or-later root WTF controller;
its ownership, queue and acknowledgement checks are retained in this separate
namespace. Its timed UI transitions were removed. The allocation predicate was
copied unchanged from root's reviewed WTF verifier, source hash documented in
`steam_win9x_socket_probe_native_allocation.py`. Peer sources and the frozen
native fixture remain unchanged.
