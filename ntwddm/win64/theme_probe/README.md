# Genuine AMD64 theme painter acceptance

The original freestanding `probe.c` executes the immutable application-local
Modern UXTHEME candidate inside the actual ShizukuDOS standalone Kernel64 guest.
The current run passes **94 Windows ABI assertions** and an independent check of
**16,800 actual QEMU framebuffer pixels**. Classic and Modern button backgrounds
appear beside each other in a real USER32 window.

The probe dynamically loads exactly `C:\SHZ\SYS64\UXTHEME.DLL`; its small FAT
tree contains only the probe executable. The frozen derived initrd contains the
source-bound provider at that path. All 33 probe import names are resolved
against the real derived archive before execution. There is no CRT, synthetic
Windows API implementation, external service, network interface or installer.

Actual guest checks include:

* Relocation of the AMD64 executable and ordinal 47 matching the named export.
* Explicit OFF, Classic and Modern selections, and the Modern candidate default.
* Real CreateDIBSection/CreateCompatibleDC/GdiFlush/BitBlt/GetPixel behavior.
  Independent expected palettes cover every border and interior pixel.
* One-pixel margins, content insets and borderfill sizes; exclusive right/bottom
  drawing bounds; clipping and restoration of the caller's clipping state.
* Unsupported drawing options and invalid geometry leave caller storage intact.
  Stale handles, handles invalidated by a style change and nonzero AMD64 upper
  handle bits are rejected.
* Real WINDOW horizontal gradient endpoints and identical interior rows.
* Bitmap deselection/deletion, memory DC deletion, visible-window destruction,
  class/timer cleanup, theme closure and provider unload.

The host evidence gate requires a fresh 32-digit nonce in records emitted by the
exact autorun PID, all individual assertions matching the reported totals, and
the external kernel's normal process exit 0. The field named `reaped` in this
peer's autorun log is the **raw C return value of proc_wait**, not a Boolean:
0 means successful teardown and reaping, and -1 means failure. The exact final
result grammar is required; the early "thread(s) still alive" branch is rejected.
Both `kernel64/proc.c` and its `tests.c` caller assertions are frozen and hashed
to bind this interpretation.

The original runner is loaded read-only. Boot stub, kernel, derived archive,
QEMU executable and firmware are sealed into the new owned run directory. Its
one QEMU child uses a private snapshot. The original 20 GiB minimum reserve and
256 MiB write quota remain enforced; own logs and captures additionally share
the 16 MiB host-output limit. The capture observer uses only this child's owned
QMP socket. It never controls a native Windows 98 VM or a peer's process.

Reproduce in a new pair of owned build directories:

```text
python3 -B tools/win64_theme_probe_trial.py prepare \
  --overlay /absolute/current/theme-overlay.json \
  --out /root/Win98-Modern-theme-6970/build/new-theme-probe-preparation
python3 -B tools/win64_theme_probe_trial.py run \
  --prepared /root/Win98-Modern-theme-6970/build/new-theme-probe-preparation/prepared.json \
  --out /root/Win98-Modern-theme-6970/build/new-theme-probe-run \
  --qemu /usr/libexec/qemu-kvm \
  --firmware-dir /usr/share/qemu-kvm \
  --firmware-dir /usr/share/seabios \
  --firmware-dir /usr/share/seavgabios --timeout 60
python3 -B -m unittest discover -s tests -p test_win64_theme_probe_trial.py
```

Current accepted evidence:

```text
preparation: build/tp64-prep-v4/prepared.json
acceptance: build/tp64-run-v2/theme-acceptance.json
serial: build/tp64-run-v2/serial.log
screenshot: build/tp64-run-v2/theme-screen.png
nonce: 897b1d08584c4593bd2b42044b5f4fe8
provider SHA256: f8e69da3c430f9b237fc490ea5f72cae8d3bcffab5b1efc77208ead22ce95442
actual assertions: 94 passed, 0 failed; 1 paint event
external child: exited exit=0 faulted=0 reaped=0 after 5250 ms
framebuffer: 8,400 Classic pixels + 8,400 Modern pixels all correct
host gate tests: 24 passed
observed minimum free: 58,240,233,472 bytes
peak private writes and capture outputs: 2,578,355 bytes
original and sealed inputs: preserved
```

The first actual run is retained as `build/tp64-run-v1`: its guest assertions
and framebuffer passed, but the initial host gate incorrectly treated `reaped`
as a Boolean and recorded FAIL. It has not been rewritten into a later PASS.
Compiler preparation failures in v1/v2 are also retained. The v2 guest run uses
a new nonce and freshly prepared v4 inputs after the evidence-gate correction.

This establishes the private painter's exercised AMD64 Windows ABI, memory
painting and visible button background pixels. It does not establish native
Windows 98 AMD64 loading, a Windows 98-to-Kernel64 GUI bridge, system-wide hooks,
persisted themes, text/font drawing, arbitrary theme API coverage, or functional
Signal/Office/Discord behavior. Those flags remain false in the receipt.

Lineage: this original probe and runner use the repository's GPL-2.0-only
license. The provider is the previously frozen shared theme engine; no provider
or peer source is changed by this workflow.
