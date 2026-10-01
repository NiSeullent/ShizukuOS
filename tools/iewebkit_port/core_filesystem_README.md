# Genuine WTF/JSC Win9x file paths

The selected real engine graph compiles `FileSystemWin.cpp` under `UNICODE`.
That file opens files and temporary files through Unicode APIs, while the real
JSC shell uses `_wstat`/`_wfopen` and an NT long-path prefix for modules. Script
paths elsewhere in the shell used UTF-8 bytes as active-code-page filenames.
These are concrete source surfaces; the individual APIs have not yet been
measured in the native guest.

`patches/core-filesystem-win9x.patch` adds opt-in branches in those genuine
sources. The Win9x branch uses real ANSI file APIs with the exact shared
`src/core_FileSystemWin9x.h` helper. Conversion rejects default substitution,
best-fit aliases, embedded NULs, excessive paths and insufficient buffers.
It uses a full ACP round trip with flags supported by the legacy profile.
The modern Unicode branches remain present. The temporary-file Win9x branch
retries actual name collisions and stops on other errors.

The port covers selected WTF file open, metadata, temporary paths/files and
volume block size, plus JSC shell script/module/descriptor paths. It does not
port all filesystem or WebCore operations. Filenames remain limited to
`MAX_PATH` and characters exactly representable by the active code page.
Unicode file contents are a separate property and are not recoded by this port.

The private `filesystem-port-stage-v1` stage contains the exact two patched
genuine sources and the helper header. Current engine source/build inputs and
all frozen WTF v5 inputs remain unchanged. Nine host conversion scenarios
passed against an explicitly synthetic ACP model; this is algorithm evidence,
not a Windows API result. The GUI `FSPATH.EXE` probe was built as PE32 x86,
subsystem 4.0, 99,915 bytes, SHA
`d792544d4facca497b201224c4a9c734c28f152528f7003d5dceae029e626558`.
Its complete 76-import inventory resolves against the original Win98 SE media
baseline. Native execution remains unverified.

The probe requires the exact Win98 SE 4.10.2222 target, a fresh nonce and four
provenance hashes in `C:\GOPLAB\FSPATH.DAT`. It measures original `CreateFileW`
without assuming failure, then uses the shared converter and real `CreateFileA`
to create, write/read exact UTF-8 contents, test exclusive creation and close/
delete its owned temporary file. It also checks rejected unrepresentable and
embedded-NUL paths. The output is `C:\GOPLAB\FSPATH.LOG`; both temporary names
must be absent before execution. No VM is started by the staging tool.

Apply this pinned port to the actual private source only after the broken WTF
runtime is diagnosed and native/build scheduling is released. Then include its
pin/header in the effective JSC source composition and regenerate the genuine
graph with the current source-matched runtime. Actual translation-unit, JSC
module/script and full IE rendering tests remain required.
