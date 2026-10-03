# Shizuku Personalization for Windows 98

This original native Win32 application adds a settings window and wallpaper
scenes to Windows 98. Explorer continues to own the desktop, icons and taskbar.
The preview reuses the existing NTWDDM Win98 DIB adapter; this is not a desktop
replacement or the Kernel64 framebuffer shell.

Choose Aurora or Starlight, 5/10/20 frames per second, English or Korean, pause,
and the battery policy. **Classic** and **ShizukuOS** also select the actual
Windows 98 system-color theme in this settings window. These buttons reuse
the existing [theme transaction](../theme_selector/README.md), including its
saved Classic baseline, complete palette/profile/startup readbacks and checked
rollback. Both executables coordinate through the same named Win98 mutex.
The installed personalization app needs no separate theme executable.
Invalid or unreadable saved theme settings disable these buttons, and errors
are displayed. Fonts, metrics and Explorer's ownership remain unchanged.
**Save settings** persists the wallpaper options.
**Apply animated** writes a small offline HTML wallpaper and asks the installed
ActiveDesktop COM interface to apply it. An actual API error is displayed; if
possible, the application applies a generated static BMP instead. **Apply
static** applies that BMP through ActiveDesktop, with `SPI_SETDESKWALLPAPER` as
the fallback. ActiveDesktop options are read before enabling its desktop flag,
preserving the unrelated components' enable setting. Opening the settings window
does not change the wallpaper or system colors. Only selecting a theme applies
and saves colors. The theme is a system palette, not an XP visual-style loader.

A successful theme selection writes the existing HKCU theme profile and
`Run\ShizukuOSTheme` value, quoting this application's actual local executable
path with exact `/restore`. That startup mode restores and verifies the saved
palette before any COM initialization, profile-folder lookup, wallpaper write,
preview, timer or window creation. It performs no registry writes. Missing,
corrupt, unreadable or incompatible settings fail with a nonzero process exit
and debug diagnostic. The application accepts only no arguments or the exact
unquoted `/restore` option. Palette operations require actual Windows 98.

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
`Shizuku-Personalization` under the current Windows shell's Application Data
folder. Windows profile selection supplies this folder through native
`SHGetSpecialFolderPathA(CSIDL_APPDATA)`, independently of the executable location
or inherited environment variables. Enabled Windows user profiles therefore
keep their settings and wallpapers separate when launching the same installed
application. Lookup, local-path, length, creation or directory-validation errors
disable writes; mapped network drives and unavailable/unknown drive types also
fail before directory creation. Paths reserve space for the store's temporary,
backup and lock suffixes. There is no fallback to a shared application directory. Existing
settings beside the executable are not automatically imported into every user.
The executable may reside in a read-only installation directory.

Windows98 without enabled user profiles can return a common Application Data
folder. Profile paths provide preference separation, not NT-style ACL protection,
a secure login system or protection from other legacy Windows98 processes.
Settings are a versioned 16-byte validated record. Saves hold an
exclusive Windows file handle, write and flush a temporary, close and read it
back byte for byte, and publish with `MoveFileA` using a backup and rollback.
Interrupted saves recover on the next operation. Empty `.lck` files persist;
their live handles provide exclusion. A failed rollback retains `.bak`. These
steps are not an atomic FAT transaction or a guarantee against power-loss disk
corruption. A cleanup failure can leave the new file present while reporting
failure. An unreadable or invalid preferences record keeps defaults and reports
the error. No `MoveFileEx` or external registry helper is used. Wallpaper
preferences remain in these files; the native theme uses its separate HKCU
profile and startup value only after an explicit theme selection.

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
USER32, GDI32, OLE32, SHELL32 and ADVAPI32. Actual system-color setter and
registry write/readback/flush imports are required. Compiler stack probes remain enabled, with the pinned
installed libgcc archive supplying the helper. No Microsoft binary is supplied.

Host tests execute production preferences/render/power-policy code and the
production storage, profile-path and shared theme backend modules with modeled
file/shell/Win32 boundaries, under GCC and Clang ASan/UBSan. The native theme
boundary tests cover actual platform/path admission, corruption, coordinated
baseline capture, two settings instances, partial writes with compensation,
restore without registry writes, failed waits and failed mutex release.
Node executes the actual generated HTML script with DOM, timer and
clock boundaries modeled. The existing adapter regression also runs separately.
The receipt explicitly records that Windows 98, ActiveDesktop, wallpaper
application, native palette changes, cold-start theme restoration, Korean
rendering and Explorer preservation have **not been
executed**. Export presence proves a link boundary, not API behavior. Installed
SDK headers, import libraries and all internal compiler/runtime dependencies
are not a fully sealed toolchain closure.

Native acceptance still needs Windows 98 booted on ShizukuDOS: launch the shared
application from two enabled Windows profiles, verify independent preferences
and wallpaper files without executable-directory writes; open the settings
window beside Explorer; verify both languages, both system themes and persistence across restart;
independently observe startup `/restore` exit and all 25 colors/profile/Run
values; exercise errors and the standalone selector beside personalization;
apply both animated scenes and static fallback; inspect API failure status,
local pause, five-minute stop and battery/suspend/minimize/close behavior; verify
Explorer icons/taskbar and unrelated ActiveDesktop components remain usable.
No VM, private Windows media or ISO is created by this component's build.

The API contract follows Microsoft's [shell profile-folder lookup](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetspecialfolderpatha),
[Active Desktop interface description](https://learn.microsoft.com/en-us/windows/win32/lwef/active-desktop-interface),
[SetWallpaper method](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-iactivedesktop-setwallpaper),
[ApplyChanges method](https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-iactivedesktop-applychanges),
[SystemParametersInfoA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa)
and [MoveFile](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefile)
documentation. The current Microsoft method pages' minimum-client tables list
later Windows versions; the older ActiveDesktop description and installed
legacy SDK interfaces support this compatibility implementation, and actual
Win98 HTML-wallpaper behavior remains an explicit native acceptance item.
