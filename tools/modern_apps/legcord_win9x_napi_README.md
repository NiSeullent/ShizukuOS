# Native source lease adapter

This GPL-2.0-only adapter calls the existing, unchanged native Win98 source-read
lease helper. It supplies `acquire(files)` and returns an object with a read-only
`held` getter and an idempotent `release()` method. The caller must retain that
object while imports or application code still need its handles. The existing
entry bootstrap and the new loader retain their leases until process exit.

The addon requires actual PE32 Win98SE 4.10.2222, Electron 43.2.0, Chromium
150.0.7871.129 and Node 24.18.0. It resolves every required Node-API export from
the actual main executable and rejects a missing symbol or wrong environment.
It uses the exact Electron public header types with Node-API version 8 and
registration symbol version 1. It does not use the V8 C++ addon ABI or pretend
that the Node module-version number is the Node-API registration version.

Production compilation uses the exact Electron 43.2.0 headers. A separate
compile control uses exact Node 24.18.0 headers. The header extraction receipt
binds the complete official archive checksums, selected header bytes, Electron
DEPS and the retained Node MIT notice. Electron's public export attribute differs
from Node's; function signatures are taken from each actual header. The original
helper, header, entry bootstrap and their existing receipts are not modified.

Native paths must be unique ASCII absolute DOS file paths under MAX_PATH, without
device names, aliases, dot components, trailing spaces/dots or network drives.
Actual `GetDriveTypeA` restricts acquisition to local fixed, removable, CD or RAM
media. A lease has at most 256 files; each environment has at most 16 active
leases. The helper holds `GENERIC_READ` handles with `FILE_SHARE_READ`. Partial
failures close acquired handles. Object finalization and real environment cleanup
also release handles without invoking JavaScript; explicit release publishes the
released state first. Detached methods and foreign receivers are rejected.

`legcord_win9x_napi_bootstrap.cjs` loads the actual addon before calling the
unchanged entry bootstrap. Its external manifest must be supplied with its exact
SHA-256. Schema `legcord-win9x-napi-frozen-tree-v1` contains `root`, `entry`,
`adapter`, `entryBootstrap`, `runtimeSha256` and `files`. The selected paths are
relative to the ASCII DOS root. Each file row contains `path`, `bytes`, `sha256`.
There may be at most 255 files of at most 8 MiB each and 64 MiB total. The manifest
is outside that root and occupies the final native lease slot. Missing/extra files,
links, unrepresentable names, wrong hashes and a different runtime PE are rejected.
Every inventoried file is hashed while the actual native lease is held. The entry
uses the observed FAT spelling so the unchanged bootstrap's path membership check
continues to work.

Initial addon and loader staging must already be trusted: the addon cannot lease
itself before it is loaded, and a hash followed by module loading alone does not
remove the replacement race. Existing-file handles also do not freeze directory
membership. The inventory checks cover startup snapshots; later added files or
lazy dependency resolution require independently controlled staging. A source
digest does not prove a Git source commit. This adapter does not provide Node,
Electron, Chromium, graphics, networking or a working Legcord runtime on Win98.

The static builder creates only a new owned build directory, pins its actual
compiler inputs, and checks PE32, ordinary imports against the exact native Win98
baseline, subsystem/OS versions and real module registration exports. It never
executes a native PE or runtime. Limits are 8 MiB total allocated output, 2 MiB
per child-created file, 45 CPU seconds and the unchanged 20 GiB free-space floor
with 256 MiB additional headroom before starting. Do not install globally.

```text
python3 /root/Win98-Modern-boot/tools/modern_apps/legcord_win9x_napi_build.py --headers /root/Win98-Modern-boot/build/legcord-napi-83bd/headers-v1 --output /root/Win98-Modern-boot/build/legcord-napi-83bd/native-v1
```

`LNLEASE.EXE <fresh-nonce> <new-local-directory>` is an independent native GUI
helper probe. It checks actual OS/build, an existing writer rejecting acquisition,
held leases rejecting writers/deletion, release/reacquisition and invalid/missing
second-file cleanup. It writes only its newly created fixture and preserves
`LEASE.LOG`, including nonce and exact probe/helper/header provenance.

`legcord_win9x_napi_probe.cjs` must run in the actual exact native Electron port,
with exposed GC for its finalizer control. It exercises invalid and partial input,
real writer/deletion exclusion, idempotent release, receiver rejection, real worker
environment termination and actual GC finalization. Its fresh `NAPI.LOG` records
component results separately from whole-application results. Worker timeout or
unavailable GC prevents lifecycle PASS. Neither probe has been executed here.

Official sources: https://nodejs.org/download/release/v24.18.0/ and
https://electronjs.org/headers/v43.2.0/ ; runtime linkage guidance:
https://www.electronjs.org/docs/latest/tutorial/using-native-node-modules .
Native Electron acceptance and whole Legcord/Discord behavior remain UNVERIFIED.

Below the static build's disk threshold, `legcord_win9x_napi_check.py` performs
only actual compiler `-fsyntax-only` checks against both pinned headers and host
JavaScript parser/path/wrong-runtime rejection controls. Compiler children have
zero-byte file-output limits and 45 CPU seconds. These checks do not load a
native addon, exercise lifecycle behavior or substitute a host Electron runtime.
