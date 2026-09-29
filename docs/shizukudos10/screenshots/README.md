# Screenshots

Real QEMU `screendump`s, not mock-ups. They are taken by `shizukudos/tests/run_k64_gui.py --png` on the Kernel64
standalone profile (QEMU TCG, Bochs VBE 1024x768, no Supervisor, no VMX), and by `supervisor/test_bootmgr.py`
(every `GUI-READY` scene of a Kernel64 boot case is dumped while the VM is paused). The runner compares each scene with a
host-computed expectation before the image is kept.

| File | Scene | What it shows |
|---|---|---|
| `k64-status.png` | `status` (T_GUI_STATUS) | Every system DLL in `C:\SHZ\SYS64` loaded by `LoadLibraryW` in one process, the first named export of each resolved; `RtlGetVersion`, processor count and physical memory as the process sees them; every PCI function with the kernel driver bound to it |
| `k64-window.png` | `window` (T_GUI_WINDOW) | user32 window with the kernel compositor's frame and a GDI-painted client area |
| `k64-status-virtio.png` | `status`, `run_k64_gui.py --display virtio` | the same screen driven by the paravirtual virtio-gpu backend (`gfx_virtio`) |
| `uefi-k64-status.png` | `status` under `supervisor/test_bootmgr.py --case kernel64` | **UEFI boot**: OVMF (q35) → Shizuku boot manager `BOOT.INI mode=kernel64` → Kernel64 direct boot → the status screen (18 DLLs loaded) |
| `uefi-k64-gpu2d.png` | `gpu2d-b` in the same UEFI boot | T_GPU_2D after a 32x16 partial update |
| `k64-gdi.png` | `gdi` (T_GUI_GDI) | GDI blits, stretching, text, clipping, polygons, ellipse |

Not shown because it does not run yet: Chromium, Electron, Discord, Steam, Windows 98 itself, NT kernel drivers.
