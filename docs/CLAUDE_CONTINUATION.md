# Continue ShizukuOS implementation with Claude Code

Read AGENTS.md and docs/SHIZUKUOS_ARCHITECTURE_CONTRACT.md, the authoritative
Absolute Architecture Definition, then the implementation/acceptance documents.
ShizukuOS is the root platform; ShizukuOS Core is its common execution base.
Historical origins do not determine system boundaries. Classify requested
features before coding and extend existing implementations. Start
from the current source in an isolated checkout; preserve another session's
working files, index and live VMs. The project includes the
`shizuku-production` skill, automatically discovered under `.claude/skills/`.
Additional ABI/assembly skills may be installed for the actual toolchain; generic
Linux examples do not override Windows x86/x64 calling conventions.

## Task routing

| Work | Model / effort starting point |
| --- | --- |
| Kernel, installation, authority and native GUI protocols | Opus5.5 / high |
| Difficult Chromium, Electron, Office or Steam port blockers | Opus5.5 / high |
| Bounded driver adapters and API providers | Sonnet5.5 / medium |
| Simple source checks, documentation and small fixes | Sonnet5.5 / low |

Adjust these choices to the actual complexity. Models and authentication must be
available in that environment. These names are `claude-opus-5-5` and
`claude-sonnet-5-5`; record the model that actually responds. Project subagents can
set `model`, `effort`, `skills` and `maxTurns` in frontmatter. Do not infer that a
configured role or submitted request proves an agent executed.

See the official [subagent configuration](https://code.claude.com/docs/en/sub-agents),
[CLI flags](https://code.claude.com/docs/en/cli-reference) and
[model/effort configuration](https://code.claude.com/docs/en/model-config).
Use local untracked permission settings for the operator-authorized mode.
Claude Code rejects bypass-permissions execution as root; an existing appropriate
non-root account can run it with the permissions the operator has authorized.
Never publish authentication or local machine configuration.

## Implementation handoff

Allocate independent source scopes for Core and installation, actual driver
binding/GOP, laptop power/input, native GUI and the existing shizuku_shell,
data-driven Slade/Flute/Jade themes and sound, ShizukuVM, chkrnl,
SHZLB.sys/Linux/POSIX/ShizukuLB, Nix-backed pkgs and managed X windows,
Terrasphere/Muzik/Sapphire/Folio, modern app ports, ShizukuFS and safe fatal
error handling. Preserve the optional legacy profile and its exact evidence. Coordinate one owner for shared ABI, dispatch,
security and lifetime changes. Workers implement production code with actual
caller/export/build wiring; the coordinator integrates shared hooks.

Code first. Check affected production files and meaningful boundary controls
instead of repeatedly running whole suites. Bound expensive commands, serialize
compilation when the host is busy and prevent accidental shared-index commits.
Leave exact source hashes, checks actually run and next required integration in
private `.codex/task-state.md`. Keep the full goal open while required work remains.

Feature completion requires production execution inside actual ShizukuOS.
Acceptance includes actual64-bit firmware boot, installation to a disposable
claimed target, sector/file readback, detached target cold boot and real device
operations. Useful native Chromium/Discord/Office/Steam behavior remains a
separate required application gate, together with the full native desktop,
Linux, virtualization, sound and native application goals. Coordinate owned VM runs and preserve their
source/artifact/media and process-exit evidence. Ship the final release through
nginx at m98.nyase.kr only when its installation/boot/driver gates pass. User
Windows media and installed guest images stay private.
