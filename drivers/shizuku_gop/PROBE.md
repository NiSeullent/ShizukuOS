# Native Windows 98 GDI diagnostic

`probe_build.py` builds `SHZPROBE.EXE` separately from the frozen display-driver
package. Its default output is `build/shizukudos/shizuku-gop-probe`. The build
receipt audits the i386 PE32 GUI 4.10 header and classic Kernel32, User32 and
Gdi32 imports. It does not execute the Windows program.

Install the driver in an isolated Windows 98 trial before using this diagnostic
as part of driver validation. Stage the executable as
`C:\VXDLAB\SHZPROBE.EXE` and establish that `C:\VXDLAB\SHZPRB.LOG` is absent.
Run the executable from the native guest. It uses `CREATE_NEW`; an existing
output or a missing directory makes it exit with code 20 without replacing a
file. A successful diagnostic exits with code 0 and ends its new report with
`STATUS=PASS`. A failed diagnostic exits with code 1. Record both the guest exit
code and the newly collected report.

The program checks the native Windows 98 version, dynamically enumerates the
primary attached display adapter, and records its description bytes, geometry
and color depth. It creates two 160 by 96 top-down 32-bit DIBs. GDI fills a blue
background with one red rectangle, copies it, presents it in a transient window
for approximately five seconds, and reads the window surface back. Each stage
compares every pixel with an independent expected pattern, ignoring the unused
fourth byte. The FNV-1a value uses B, G, R bytes in row order and is `7ba089c5`.
Exact display readback requires a 32-bit display mode. The report is bounded to
4096 bytes. The window, drawing resources and output handle are released.

`BACKEND_HARDWARE_VERIFIED=0` is deliberate. GDI can read a shadow surface, so a
passing report does not establish that SHZGOP.VXD is loaded or that the physical
framebuffer received the pixels. Combine it with the actual installation,
backend handover/load evidence, a matching guest screenshot and, where
available, a bounded physical-framebuffer capture. The report includes the
pattern's screen coordinates for that comparison. Adapter description bytes
outside ASCII are escaped as `\xXX` so a CP949 name can be reconstructed.

Microsoft's original Windows 98 multiple-display example documents dynamic
`EnumDisplayDevicesA` lookup and the original 168-byte structure:
[Microsoft KB197671 (archived Microsoft content)](https://ftp.zx.net.nz/pub/mirror/ftp.microsoft.com/MISC/KB/en-us/197/671.HTM).
The diagnostic tries that structure size first and retains a larger allocation
for compatible later fields. The scope stays confined to normal Win32/GDI APIs;
it does not access firmware, physical memory, the registry or network services.
