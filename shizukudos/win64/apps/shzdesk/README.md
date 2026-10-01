# ShizukuOS development desktop — ShizukuDOS 10 component

`SHZDESK.EXE` is a persistent Win64 system application, built by `win64/build.py`
from `apps/shzdesk/*.c` with the existing `ShzStart`/`shzcrt` entry machinery. It
uses the project's `kernel32.dll`, `user32.dll` and `gdi32.dll`. It is a ShizukuDOS 10 component shell used to develop the Windows 98 foundation.
Its standalone profile does not yet establish Microsoft Windows 98 Explorer or
external application startup. Native Windows 98 integration remains required.

The desktop and its taskbar offer Files, Text Editor and a launcher. The tools
are real top-level windows with custom-painted controls; common controls are
not required. The application has no session timeout. Its 200 ms timer polls
child-process completion without blocking input.
The desktop registers its HWND with the kernel's shared `SetShellWindow`
backend. `GetShellWindow` can retrieve it from other processes. Registration
requires a live, caller-owned top-level window and permits one shell at a time;
the window stays below application windows and registration clears when its
window or owning thread dies.

| Action | Keyboard | Mouse |
| --- | --- | --- |
| Open file browser | F2 | Files icon, taskbar button or Start item |
| Switch root directory | C, D or E in Files | C:, D:, E: buttons |
| Navigate | arrows select, Enter opens, Backspace goes up, F5 refreshes | click selects; second click opens; wheel scrolls |
| Open text editor | F3 | Editor icon, taskbar button or Start item |
| Edit text | printable ASCII, Enter, Tab, Backspace, Delete, Left/Right, Home/End | editor keeps keyboard focus |
| Save | Ctrl+S | Save button |
| Open current document | Ctrl+O | Open button |
| Change document path | Ctrl+L, type absolute path, Enter; Escape cancels | Path button |
| Start empty document | Ctrl+N, after saving existing changes | New button |
| Launch bundled app | F4 | Hello icon or Start item |
| Launch executable from Files | select `.exe`, Enter | second click |
| Hide current tool | Escape | X button inside its toolbar |
| Choose Classic / ShizukuOS theme | F6, then C / S | Theme button, then Classic / ShizukuOS |
| End session | F10 | Start / End session |

The default document is `D:\DESKTOP.TXT`. Change its path to
`E:\DESKTOP.TXT` for an installed system whose persistent ShizukuFS volume is
E:. A missing or read-only volume produces a visible error and no saved marker.
The editor accepts ASCII text up to 32,767 bytes. Typed Enter inserts LF; files
already containing CRLF retain those bytes. Binary and non-ASCII files are
refused without changing the buffer. Opening or replacing a dirty buffer is
refused until it is saved; a second F10 explicitly discards unsaved text.
Saving truncates/replaces the chosen file, writes every byte, flushes, closes,
reopens, and compares every byte before reporting success. A write/flush failure
can leave a partial file; unsaved text stays in the editor for retry. An empty
document is a valid zero-byte file.

The file browser enumerates the real directory, stores the first 128 entries
and reports the total count. Paths up to 259 UTF-16 code units can be browsed;
serial markers replace non-ASCII path characters with `?`. Directories and
executables are distinguished by their attributes and `.exe` suffix. Other
files open in the ASCII editor. Eight child processes can be tracked at once;
the launcher closes each thread handle immediately and closes its process
handle after reporting the actual exit code. F4 uses
`C:\SHZ\TESTS\T_HELLO.EXE`, whose expected test-program exit code is 7, not 0.

## Guest validation protocol

Action markers go through the existing runtime's `printf` serial output:

```text
SHZ-DESKTOP SHELL registered=1 hwnd=3002
SHZ-DESKTOP READY width=1024 height=768
SHZ-DESKTOP FILE name=DESKTOP.TXT dir=0 bytes=25
SHZ-DESKTOP FILES path=D:\ count=1 displayed=1
SHZ-DESKTOP EDITOR path=D:\DESKTOP.TXT bytes=0 dirty=0
SHZ-DESKTOP SAVED path=D:\DESKTOP.TXT bytes=25 verified=1
SHZ-DESKTOP CONTENT uefi desktop persistence\n
SHZ-DESKTOP OPENED path=D:\DESKTOP.TXT bytes=25
SHZ-DESKTOP LAUNCHED pid=60 path=C:\SHZ\TESTS\T_HELLO.EXE
SHZ-DESKTOP APP-EXIT pid=60 code=7
SHZ-DESKTOP EXIT requested=1
```

Values reflect the real run. FILE lines precede their FILES summary. CONTENT
escapes backslash, LF, CR and Tab as `\\`, `\n`, `\r`, `\t`; other printable
ASCII, including spaces, is literal. Only the first 128 content bytes are logged;
longer documents produce a separate CONTENT-TRUNCATED marker. Errors emit
`SHZ-DESKTOP ERROR operation=<description> error=<Win32 code>`; refused actions
emit REFUSED markers. READY requires a real display, registered class, desktop/tool/theme
windows, successful shared shell registration, a polling timer and
completed initial desktop paint.

A persistence test can use F3, type `uefi desktop persistence`, Enter, Ctrl+S,
Ctrl+O, Escape, F2, D, F5, Escape, F4, wait for APP-EXIT, F10. The exact file
content is the 25 bytes `uefi desktop persistence\n`. Boot again with the same
disk, then F3 / Ctrl+O to confirm the saved content; the host must also compare
the file on disk independently. A screenshot or marker alone is not disk
persistence evidence.

## ShizukuOS themes — development candidate

`F6` or the desktop Theme button opens the Classic/ShizukuOS chooser. `C` and
`S`, or the two actual shell buttons, select the palette for the desktop, Files
and Editor client surfaces. Classic remains the initial default and preserves
its existing colors. Each selection attempts to persist an exact versioned
18-byte record in `D:\SHZTHEME.CFG`, after exclusive temporary creation, complete
write/flush/close, strict readback and rename. Failed saving applies the palette
only to this session and reports the failure; it retains the previous setting.
Missing/invalid settings use Classic. No writes target the shipped ISO.

Run `python3 shizukudos/win64/tests/test_shzdesk_theme_host.py` to check the real
palette/record/persistence routines with GCC and ASan/UBSan and compile the
AMD64 shell. These host controls do not certify a visible guest interaction or
cold-boot persistence. Native Windows98 UXTHEME/Explorer integration, non-client
captions, other applications and system-wide theme acceptance remain separate
required work for ShizukuOS 1.0.0, currently a development candidate. See
`docs/SHIZUKUOS_TARGET.md` for the Windows98 component and release scope.
