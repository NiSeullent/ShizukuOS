# Source and license notice

Original Shizuku GOP backend and bounded handover parser: GPL-2.0-only.
The combined native driver is distributed under GPL-2.0-only; see GPL-2.0.txt.

The 16-bit display frontend, MiniVDD support, DIBEngine interfaces, software
framebuffer support and resource sources derive from JHRobotics/VMDisp9x,
commit d778a911035d414dea9ac852a638a7052c21c400, distributed under MIT.
Upstream authors include Michal Necasek, Philip Kelley and Jaroslav Hensl.
Original per-file copyright and permission notices remain in SOURCE.zip.
The repository MIT license is also included as LICENSE.MIT.

The build-time fixlink utility derives from JHRobotics/fixlink, commit
a2a74447daea3197255f3a4fb5cfb0c5a453dcc8, distributed under MIT; its notice is
included as FIXLINK.MIT. It fixes the NE expected Windows version and makes
every LE VxD object executable with a zero base, as required by that tool.
The utility binary is not part of the install package.
Open Watcom supplies the compiler and the linked 16-bit C runtime. Its license
notice is included as WATCOM.txt; compiler executables are not packaged.

Private source adaptations rename the VxD identity, select the native GOP
geometry, replace the VESA BIOS backend, repair register preservation and
initialization failure propagation, guard dispatch after failed initialization,
and retain the original DIBEngine exports. These adaptations and exact source
hashes are recorded by the build receipt and source-adaptations.patch.
DirectDraw HAL and Mesa ICD escapes return unsupported because their separate
upstream DLLs are outside this GDI display package.

The package contains no Microsoft binaries, guest images, application binaries,
firmware binaries or host compiler binaries. DIBEngine is supplied by the
installed Windows operating system. Original source files, third-party source
files and their notices are included for rebuilding this driver.
