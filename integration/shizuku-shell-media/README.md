# Native shell runtime staging

`stage_runtime.py` adds the compiled ReactOS-derived ShizukuOS shell and its
font/shell licenses (OFL, LGPL and GPL2 renderer) to a completed, externally pinned Win64 runtime. It reuses
only `pack_archive()` from the pinned production builder; it runs no compiler,
installer, VM or global build hooks.

The exact original DLL/application bytes remain in the archive. The shell's
actual imported DLL hashes must match those archive members. A stable source
map and the actual PE64 compile/import receipt are required. The output is a
fresh directory for the existing installer payload builder's explicit inputs
layout. Its receipt says `STAGED_PENDING_GUI_VALIDATION`, with separate base and
shell receipt hashes; staging is not a new runtime compilation or guest proof.

The existing kernel starts `C:\SHZ\SYS64\SHZDESK.EXE` in its desktop profile.
This staging tool places the **new shell's exact executable bytes** at that
entry path to reuse the working kernel launch path. It does not bundle or
select the old diagnostic desktop. The alias is recorded in the receipt.

Every input SHA-256 is explicit; run `--help` for arguments. Input paths are
read only and the output must not exist or overlap the runtime. Each input is
bounded to 16 MiB, output to 16 MiB and free space to a 17 GiB reserve. Archive
paths, duplicate members, overlapping extents and copied source paths are
validated before writing. Licenses travel inside the runtime archive.

Actual shell display, interaction, installation and Windows 10 compatibility
remain separate verification steps. This tool never publishes an ISO.
