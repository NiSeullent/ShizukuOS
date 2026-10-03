# ShizukuOS architecture and delivery contract

ShizukuOS is the operating system and the root platform. **ShizukuOS Core**
contains ShizukuDOS, the kernel and driver layers, VM services, the Linux
subsystem and the native runtime. The user's current authoritative definition
is [ShizukuOS — Absolute Architecture Definition](docs/SHIZUKUOS_ARCHITECTURE_CONTRACT.md).
That definition supersedes earlier platform identity and hierarchy rules.
Historical implementation origins do not define system boundaries.

Use the current workspace and its existing build conventions. The public
repository is <https://github.com/NiSeullent/ShizukuOS>. Existing directory and
executable names remain valid implementation locations; do not rename files,
replace shared ABIs or create parallel kernels merely to match conceptual names.
Inspect every requested feature and classify it as EXISTS, PARTIAL, MISSING,
BROKEN, REUSABLE or REQUIRES REFACTOR before coding. Extend an appropriate
existing subsystem instead of duplicating it. Details and current source
relationships are in `docs/INTEGRATED_ARCHITECTURE.md` and
`docs/SHIZUKU_HYBRID_TRANSITION.md`; the latter filename is retained for links.

## Shell and Core implementation

Extend the existing executable-based native shell at
`shizukudos/win64/apps/shizuku_shell`, packaged as
`\SHZ\SYS64\SHIZUKU_SHELL.EXE` and selected by `kernel64/autorun.c`.
The conceptual shell filenames in the architecture definition are examples,
not a request for duplicate executables. The shell owns the Slade (default),
Flute and Jade theme system. Implement theme data and propagation for metrics,
painting, effects, typography, icons, controls, taskbar/start, animation,
sounds, wallpaper and cursors; a hardcoded palette is an intermediate component.
The user requires Noto Sans or Pretendard for UI typography. Ship the actual
licensed font and use its glyphs and metrics; renaming another bitmap face does
not satisfy this rule. The official website self-hosts Pretendard. Native GUI
font replacement requires its own build and actual ShizukuOS verification.

ShizukuVM is a native kernel virtualization subsystem with its own ShizukuOS
API. Reuse suitable VM foundations. `chkrnl /mode linux` and `/mode msdos`
select kernel-supported environments. SHZLB.sys, the Linux sandbox, POSIX,
ShizukuLB, Nix-backed `pkgs` and the managed X-window bridge are Core components.
The native application baseline includes WebKit-based Terrasphere, Muzik,
Sapphire and integration of the existing open-source Folio implementation.
Before creating sound assets, inspect the available `volume1/shizukuossound`
NAS source; record access and asset provenance honestly. These are required
implementation goals, not claims that the current sources already supply them.

Preserve existing Kernel32/Kernel64, Supervisor, runtime, driver and bridge
providers while migrating concrete services and their authority. Windows 98
USER/GDI/Explorer and VxD paths remain an optional legacy compatibility profile
with their original evidence. Their historical ownership applies to those
paths and does not establish the ShizukuOS architecture. The native Win32
x86/x64 target includes actual Windows 10 API behavior; reporting a version
number does not establish compatibility. ReactOS, Wine and other compatible
open-source code may be reused with file-level provenance and licensing.
Private Microsoft source, installation media and installed guest images must
never enter public source or packages.

## Production correctness and acceptance

Implement real callers, providers, exports and build wiring. Preserve Windows
x86/x64 calling conventions, kernel no-red-zone requirements, explicit pointer
and length bounds, resource ownership, generations and teardown. Never infer
authority from a saved receipt or a JSON boolean. An absent or revoked provider
returns an honest error; do not retry a side effect with a different backend.
Keep existing strict installation profiles when adding an explicit new route.

[Full acceptance](docs/SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md) retains boot,
installation, recognized working drivers, accounts, elevation, permissions,
sandboxing, filesystem, modern apps, acceleration, Dead Screen and public
website requirements, alongside the complete new architecture. Only an
executable path tested inside actual ShizukuOS counts as feature completion.
Host checks, static audits, a built image, screenshots, synthetic providers
and boot alone have narrower scopes. Preserve failed and historical evidence;
do not relabel old Windows 98 control runs as ShizukuOS system acceptance.

## Parallel implementation and continuation

Use useful parallel coding agents with one writer per source area. Preserve
other sessions' working files, index, running VMs and private media. Coordinate
shared ABI, authority and lifetime changes with one owner. Use Sonnet 5.5 or
Opus 5.5 and effort appropriate to complexity, recording the model that actually
responds. Implement code, compile affected production units and run inexpensive
meaningful controls, then coordinate a current integrated ShizukuOS VM cohort.
Model selection and the number of agents do not prove feature quality.

For long tasks keep a short private `.codex/task-state.md` with changed paths,
actual checks, failures and next integration. The project skill is
`.claude/skills/shizuku-production/SKILL.md`; continuation instructions are in
`docs/CLAUDE_CONTINUATION.md`. Runtime credentials, local permission settings,
machine paths and private coordination notes are never committed.

The final installer is ShizukuOS's own installation system. ISO distribution
is through nginx at <https://m98.nyase.kr/> after the applicable release gates
pass. GitHub carries public development sources and permitted patches. Verify
the public homepage and downloads externally; private VM consoles must not
replace the official website. Do not publish private media or credentials.
