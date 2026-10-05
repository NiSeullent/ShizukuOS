# ShizukuOS — Absolute Architecture Definition

## 0. SYSTEM IDENTITY — NON-NEGOTIABLE

The operating system is:

> **ShizukuOS**

ShizukuOS is the operating system itself.

Do NOT describe, model, document, or implement ShizukuOS as a modification, distribution, shell replacement, skin, compatibility pack, or derivative edition of another operating system.

Historical implementation origins are irrelevant to the current architecture and MUST NOT be used to determine system boundaries.

All architecture diagrams, source directories, documentation, UI strings, package metadata, boot messages, APIs, subsystem names, and implementation decisions MUST treat **ShizukuOS as the root platform**.

The architecture begins with:

```text
                    ShizukuOS
                        │
                ShizukuOS Core
                        │
     ┌──────────────────┼──────────────────┐
     │                  │                  │
 ShizukuDOS        Kernel Layer       Driver Layer
     │                  │                  │
     ├── DOS Mode       ├── Kernel32      ├── Native
     ├── Protected      ├── Kernel64      ├── Legacy
     ├── Long Mode      ├── SHZLB.sys     └── Wrapped
     └── v8086          └── VM Services
                        │
        ┌───────────────┼────────────────┐
        │               │                │
    ShizukuVM     Linux Subsystem    Native Runtime
        │               │                │
    VM Guests        ShizukuLB       Applications
                        │
                       Nix
                        │
                      pkgs
```

---

# 1. SHELL DEFINITION

ShizukuOS MUST provide its **own executable-based desktop shell**.

The shell is a first-class ShizukuOS component.

It MUST NOT be implemented as a theme or modification of another shell.

Implementation may reuse or adapt suitable components from:

- Wine
- ReactOS
- other license-compatible open-source projects
- portable GUI/toolkit libraries
- ShizukuOS native components

but the resulting shell MUST be built, packaged, executed, and maintained as a **ShizukuOS executable**.

Example conceptual structure:

```text
ShizukuShell.exe
ShizukuDesktop.exe
ShizukuTaskbar.exe
ShizukuStart.exe
ShizukuExplorer.exe

ShellCore.dll
ShellUI.dll
ThemeEngine.dll
DesktopHost.dll
WindowEffects.dll
ShizukuUX.dll
```

These names are architectural examples; reuse an existing implementation if equivalent components already exist.

**DO NOT create duplicate components merely because this specification lists a possible filename.**

Before implementing anything:

1. inspect the repository;
2. locate existing shell implementations;
3. identify reusable code;
4. extend the existing architecture;
5. create a new component only when no appropriate implementation exists.

---

# 2. SHELL THEMING

The theme system belongs directly to ShizukuOS Shell.

```text
ShizukuShell
      │
 ThemeEngine
      │
 ┌────┼────┐
Slade Flute Jade
```

### Slade

Default ShizukuOS visual identity.

Design inspiration:

- Aero Glass
- translucent/liquid surfaces
- Longhorn-era depth
- restrained glass effects
- modern typography
- lightweight animation

It must NOT simply clone another existing desktop.

### Flute

Modern, clean, restrained desktop appearance.

Rounded surfaces, simplified hierarchy and contemporary interaction patterns.

### Jade

Longhorn-era experimental aesthetic.

This should be the strongest retro/experimental theme of the three.

---

# 3. THEME CUSTOMIZATION

Themes MUST NOT consist only of hardcoded skins.

Provide a theme definition system supporting at minimum:

```text
Window metrics
Title bar
Borders
Backgrounds
Transparency
Blur
Typography
Icons
Buttons
Taskbar
Start interface
Menus
Selection states
Animations
Sound scheme
Wallpaper
Cursor
```

Suggested conceptual layout:

```text
/System/Themes/
    Slade/
    Flute/
    Jade/
    Custom/
```

Theme changes should propagate through the shell without requiring replacement of system executables.

---

# 4. ShizukuVM

Implement **ShizukuVM**, a native ShizukuOS kernel virtualization subsystem.

QEMU may be used as an implementation/reference foundation.

However:

> ShizukuVM defines its own ShizukuOS-facing VM architecture.

Do NOT spend development effort attempting to reproduce KVM, Hyper-V, VMware, or another hypervisor's external API.

Conceptually:

```text
Application
    │
ShizukuVM API
    │
VM Service
    │
Kernel VM Interface
    │
CPU Virtualization
    │
Guest
```

Hardware virtualization should be used when available.

Software emulation may provide fallback functionality where practical.

---

# 5. chkrnl

Provide:

```text
chkrnl /mode <parameter>
```

Initial parameters:

```text
chkrnl /mode linux
chkrnl /mode msdos
```

Only these two modes are initially defined.

They are NOT shell emulation presets.

They represent kernel-supported execution environments.

---

# 6. Linux Subsystem

Linux Subsystem is part of **ShizukuOS Core**.

It is NOT a complete Linux OS bundled inside ShizukuOS.

Target:

> Linux-kernel sandbox + POSIX-compatible execution environment.

Kernel integration should be provided through:

```text
SHZLB.sys
```

Conceptually:

```text
ShizukuOS Kernel
       │
    SHZLB.sys
       │
Linux Sandbox
       │
POSIX Environment
       │
ShizukuLB
```

---

# 7. ShizukuLB

Official name:

> **ShizukuLB — Shizuku Linux Basebuild**

ShizukuLB is a ShizukuOS Core component rather than an independent general-purpose distribution.

Use **Nix** as the underlying package mechanism.

Provide `pkgs` as the simplified user interface.

Examples:

```text
pkgs install firefox
pkgs update firefox
pkgs remove firefox
pkgs search firefox
pkgs add-repo <repository>
pkgs list
pkgs upgrade
```

`pkgs` MUST translate/synchronize these operations with the underlying Nix environment rather than implementing an unrelated second package database.

---

# 8. Linux GUI Integration

When an application requests an X session:

```text
Linux Application
       │
    X Session
       │
    SHZLB.sys
       │
Shizuku Window Bridge
       │
ShizukuOS Desktop Window
```

Linux GUI applications therefore appear as ordinary managed windows inside the ShizukuOS desktop.

Do NOT create an entire secondary Linux desktop merely to display one Linux GUI application.

---

# 9. Native Applications

The finished ShizukuOS installation must include a usable baseline application ecosystem.

### Terrasphere

Native lightweight web browser.

Use a WebKit-based rendering architecture.

Design objective:

> traditional browser usability + modern Chromium-class UX + ShizukuOS native visual language.

### Muzik

Music/video application.

Design direction:

> media-library-centric desktop player with rich metadata, playlists and visualization.

### Sapphire

Combined:

- photo viewer
- basic image editor
- drawing/paint environment

Simple viewing should remain lightweight while editing capabilities load as required.

### Folio

Reuse the existing open-source Folio implementation where appropriate.

Adapt its interface to the ShizukuOS family design rather than unnecessarily rewriting the entire word-processing engine.

---

# 10. SOUND IS MANDATORY

Sound is a required part of the desktop experience.

Primary source:

```text
NAS:
volume1/shizukuossound
```

Search the available NAS source before generating replacements.

Use appropriate assets for:

- startup
- shutdown
- login
- logout
- error
- warning
- notification
- device connect/disconnect
- shell navigation where appropriate

If required assets are genuinely absent, create suitable replacements rather than shipping a silent desktop.

---

# 11. DRIVER COVERAGE

Broad standard hardware support is a core success criterion.

Prioritize common hardware classes:

```text
ACPI
PCI / PCIe
USB
USB HID
USB Storage
NVMe
SATA / AHCI
IDE
Ethernet
Wi-Fi
Audio
Bluetooth
GPU / framebuffer
UEFI GOP
PS/2
Keyboard
Mouse
Touchpad
Display
Storage
Filesystem
```

Driver work must use a layered architecture whenever possible.

Do NOT duplicate an entire driver merely to handle minor device variations.

---

# 12. DEFINITION OF SUCCESS

The project is NOT complete merely when the kernel boots.

Success requires a system that can realistically be used as an operating system:

**Boot → drivers → shell → themes → sound → networking → filesystem → applications → browser → media → graphics → Linux subsystem → virtualization → games.**

The final milestone is reached when ShizukuOS provides:

- stable boot
- usable desktop
- Slade / Flute / Jade themes
- customizable theme engine
- mandatory sound system
- broad standard drivers
- ShizukuVM
- `chkrnl`
- Linux Subsystem
- ShizukuLB
- Nix + `pkgs`
- Linux GUI window integration
- Terrasphere
- Muzik
- Sapphire
- Folio integration
- system utilities
- bundled games
- coherent family UX across applications

At that point:

> **ShizukuOS is not merely bootable. It is a complete desktop operating environment.**

---

# FINAL IMPLEMENTATION RULE

Before writing new code, inspect the existing repository and classify every requested feature as:

```text
EXISTS
PARTIAL
MISSING
BROKEN
REUSABLE
REQUIRES REFACTOR
```

Never create a parallel implementation when an existing ShizukuOS subsystem can be extended.

Prefer:

> inspect → understand → integrate → implement → build → test → fix

over:

> assume → rewrite → duplicate → mock.

Mocks, screenshots, placeholder executables and UI-only demonstrations DO NOT count as feature completion.

Every feature marked complete must have an executable implementation path and must be tested inside the actual ShizukuOS environment.