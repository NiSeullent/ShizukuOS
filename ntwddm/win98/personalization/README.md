# Shizuku Personalization for Windows 98

This original native Win32 application adds a settings window and wallpaper
scenes to Windows 98. Explorer continues to own the desktop, icons and taskbar.
The preview reuses the existing NTWDDM Win98 DIB adapter; this is not a desktop
replacement or the Kernel64 framebuffer shell.

Choose Aurora or Starlight, 5/10/20 frames per second, English or Korean, pause,
and the battery policy. **Save settings** persists the selected options.
**Apply animated** writes a small offline HTML wallpaper and asks the installed
ActiveDesktop COM interface to apply it. An actual API error is displayed; if
possible, the application applies a generated static BMP instead. **Apply
static** applies that BMP through ActiveDesktop, with `SPI_SETDESKWALLPAPER` as
the fallback. ActiveDesktop options are read before enabling its desktop flag,
preserving the unrelated components' enable setting. Opening the settings window
does not change the wallpaper.

Korean captions use the real Windows system code page through ANSI USER32. A
system whose code page cannot represent Korean displays English and an explicit
notice. The offline HTML uses UTF-8 and supplies Korean or English controls.
Accounts and elevation are shown as an unconfigured NTW64 companion connection;
this Win98 process does not claim successful authentication or invoke PE64 code.

The animated wallpaper contains only 24 procedural points, one pending timer,
and no external URLs, ActiveX, media, fonts, downloads or network requests. Its
timer stops after 300 seconds or the bounded frame budget. Reapply restarts it.
The local Pause/Resume control cannot bypass the five-minute limit. While the
settings application is open, pause, suspend, battery or unknown power with the
default battery policy select a static wallpaper; AC/resume may restart a
requested animation. Minimized preview rendering pauses. Closing the application
attempts to freeze the wallpaper; a failure is reported and the offline HTML has
its own finite timer. Power transitions after an abnormal application exit are
not monitored. The native preview is 320×180 and a static BMP is limited to
1920×1080 / 8 MiB of pixel data.

The application stores `preferences.pz`, `wallpaper.bmp` and `wallpaper.htm` in
`Shizuku-Personalization` beside the executable. Install it in a writable local
directory. Settings are a versioned 16-byte validated record. Saves hold an
exclusive Windows file handle, write and flush a temporary, close and read it
back byte for byte, and publish with `MoveFileA` using a backup and rollback.
Interrupted saves recover on the next operation. Empty `.lck` files persist;
their live handles provide exclusion. A failed rollback retains `.bak`. These
steps are not an atomic FAT transaction or a guarantee against power-loss disk
corruption. A cleanup failure can leave the new file present while reporting
failure. An unreadable or invalid preferences record keeps defaults and reports
the error. No `MoveFileEx`, registry configuration helper, autorun or installer
change is required by the application.

Build and verify from the repository root with installed GCC, Clang, Node and
the i686 MinGW cross compiler:

```sh
mkdir -p build/personalization-fd5c
python3 -B ntwddm/win98/personalization/verify.py --out build/personalization-fd5c/local-check
```

The output directory must be new. The runner bounds owned output to 16 MiB,
gives each child a 60-second deadline, reaps its own children, records commands,
hashes and project include dependencies, and builds `SHZPERS.EXE` as an i486
PE32 GUI application with subsystem/OS 4.10. Its imports are checked against
the repository's actual Win98 native export inventory and limited to KERNEL32,
USER32, GDI32 and OLE32. Compiler stack probes remain enabled, with the pinned
installed libgcc archive supplying the helper. No Microsoft binary is supplied.

Host tests execute production preferences/render/power-policy code and the
production storage module with file-boundary mocks, under GCC and Clang
ASan/UBSan. Node executes the actual generated HTML script with DOM, timer and
clock boundaries modeled. The existing adapter regression also runs separately.
The receipt explicitly records that Windows 98, ActiveDesktop, wallpaper
application, Korean rendering and Explorer preservation have **not been
executed**. Export presence proves a link boundary, not API behavior. Installed
SDK headers, import libraries and all internal compiler/runtime dependencies
are not a fully sealed toolchain closure.

Native acceptance still needs Windows 98 booted on ShizukuDOS: open the settings
window beside Explorer; verify both languages and persistence across restart;
apply both animated scenes and static fallback; inspect API failure status,
local pause, five-minute stop and battery/suspend/minimize/close behavior; verify
Explorer icons/taskbar and unrelated ActiveDesktop components remain usable.
No VM, private Windows media or ISO is created by this component's build.

The API contract follows Microsoft's [Active Desktop interface description](https://learn.microsoft.com/en-us/windows/win32/lwef/active-desktop-interface),
[SetWallpaper method](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-iactivedesktop-setwallpaper),
[ApplyChanges method](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-iactivedesktop-applychanges),
[SystemParametersInfoA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa)
and [MoveFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefile)
documentation. The current Microsoft method pages' minimum-client tables list
later Windows versions; the older ActiveDesktop description and installed
legacy SDK interfaces support this compatibility implementation, and actual
Win98 HTML-wallpaper behavior remains an explicit native acceptance item.
