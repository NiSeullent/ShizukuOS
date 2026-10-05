# Dead Screen — Shizuku Kernel64

Fatal Shizuku Kernel errors can show a black screen with original monochrome Sad Mac silhouettes, Korean **오류!!!!** or English **Halted!!!!**, captured traceback, and two playable games. The menu asks **테트리스 게임을 할래? 수박 게임을 할래?**. Press 1 or 2; arrows or A/D/W/S move, rotate or drop, Space drops, R restarts, Escape returns to the menu, L switches Korean/English, and T switches traceback/item legend. Tetris has all seven tetrominoes, bounded wall kicks, collision, line clearing and game over. Suika uses bounded fixed-point gravity, two collision passes, merging, a ceiling limit and game over. Items are Sad Mac and labeled Windows 2000, XP, 8.1, 10 and 11 BSOD tiles. Those tiles are game art, not reports from those operating systems.

The normal `kbuild.py` links the four production units into both Kernel64 profiles. Seven small kernel hooks capture fatal diagnostics, retain successfully probed GOP/BGA mappings and prepared input, and expose explicitly selected startup controls. The installer, desktop, Kernel32 peer gate, driver bugcheck callbacks, recoverable paging/driver/user exceptions and normal exits retain their existing paths. The separate source-build command never writes these default files; it snapshots the source and exports clearly labeled **host renders**, not VM screenshots. It admits either seven bare seams or a coherent already integrated source tree, refusing partial or duplicate integration. In the latter case baseline and candidate both link the same four units, the integration patch is empty, and the result says `already-default-integrated`.

## Severity and ownership

The caller owns severity classification. `DS_RECOVERABLE` returns without changing fault state. Recoverable Win98 errors must continue through their ordinary Win98 application/system dialog or error handling; this module provides no Win98/VMM exception hook or dialog replacement. The private integration uses only Shizuku `kpanic` and the final **kernel-mode** exception path. Existing kernel demand/file paging, user paging, and `user_fault` handling run before that hook. Unhandled user exceptions retain the existing exit behavior. Boot admission failures, normal exits and test failure exits are unchanged. No arbitrary Win98 or VMM fault is swallowed.

A fatal state never resumes the damaged kernel. The first trusted record is copied and held immutable. The games change only their own bounded static state. On graphics/load prerequisite failure or recursive fatal handling, the first line is exactly:

```text
Your computer was trashed.
```

An English traceback follows on COM1/the console. If a valid retained framebuffer remains, a separate minimal ASCII renderer writes the same first record directly to it, even after the full game renderer has failed. Small framebuffers clip text and return a truncation result; serial output still carries the complete record. If drawing that fallback itself faults, one further serial-only takeover is allowed; another recursive fault halts immediately. The first record is never replaced. If the output device also fails, the adapter halts rather than claiming an error report was written. There is no heap allocation, file I/O, IPC, compositor lock, scheduling operation, GPU command submission or interrupt re-enable in the fatal module. If the kernel/module itself never loads or the CPU cannot execute it, it cannot provide a fallback; no bootloader interception is claimed.

The native adapter claims one verified physical CPU using a lock-free atomic
compare-and-exchange before modifying the captured reason or static fault
record. A fatal entry from another CPU halts that CPU locally without changing
the first record, fallback depth, serial output or framebuffer. Unknown physical
CPU identity also halts before those writes. The owning CPU may continue from
panic text capture into the panic handler. Its recursive exception before the
record has latched halts safely; after the latch, its bounded fallback retains
the original record. Only the owner may append captured panic text. This gate
protects module-owned fatal state: it does not stop other CPUs running ordinary
kernel code, quiesce all devices, or establish general SMP panic recovery.

## Nyan fatal fallback

The native fallback now renders an original small rainbow cat directly into a
retained framebuffer when the game controller cannot run, or when the explicit
`shz.nyan-control` fault-control token is supplied. It keeps the first real fault
record and never resumes the main kernel. No GUI, compositor, filesystem or
allocation is used after the fatal boundary. CPU metadata uses the verified
physical identity of the fatal owner. Cached scheduler PID/TID are included only
when the cached CPU matches that owner; otherwise task context remains unknown.

Audio levels describe measured output facilities: previously prepared AC97
retained DMA pages with observed progress, verified PIT channel-2 pitched output,
verified fixed-tone counter/gate transitions, or silent. PCM progress is checked
again during playback; a stalled or halted engine demotes to primitive output.
Loss of a previously verified fixed-tone gate demotes to silent, rerenders and
reports the unavailable output, then halts. Stopping an unresponsive primitive
speaker is best effort; the silent level means no output remains verified.
There is no panic-time codec enumeration or DMA allocation. Neither register
readback nor DMA progress proves a physical speaker is audible. Missing output
cannot establish a specific processor defect. `shz.nyan-beep`,
`shz.nyan-fixed`, and `shz.nyan-silent` constrain this explicit control; they do
not alter ordinary boot or automatically force a process teardown. The optional `shz.nyan-pcm-prepare` control readies the real backend during
healthy execution before inducing the fatal fault. It is not a panic-time
probe. Host hardware
models test selection and demotion separately from real native execution.

## Actual capture and limits

An unhandled Kernel64 exception supplies its real `struct regs` IP/SP/BP, flags, vector, CPU error, all integer registers and sampled CR2/CR3. A panic supplies its actual caller return address, the panic function's current SP/BP and flags after CLI, sampled CR2/CR3, and the bounded text produced by the existing formatter. That is a panic snapshot, not a complete interrupted register frame. CR2 is the sampled CPU register and may describe an earlier page fault. The first frame is the actual captured IP; further unwinding is explicitly unavailable. No arbitrary stack pointer is dereferenced, no fake OS stack frames are synthesized, and no claim is made that register capture survives memory corruption or every double fault. Existing panic formatting and exception diagnostic console/evidence writes remain prerequisites before handoff and can themselves fault. The immutable first-record guarantee starts at `ds_latch`; it does not cover a fault before that boundary.

Rendering requires a retained, already mapped BGRX/RGBX framebuffer at least 640×480, at most 4096×4096, with checked stride/span/pointer arithmetic. Normal GOP/BGA probe binds the real mapping only after probe succeeds. It remains mapped for the kernel lifetime. Unsupported virtio submission, early faults, a small/unusable framebuffer or a fault in the drawing path use the textual fallback. The renderer writes the visible framebuffer only; padding is untouched. Drawing and input execute exclusively on the fatal owner. The local secondary-CPU halt gate provides first-record protection; peer-CPU stop, general SMP recovery and corrupted page tables/mappings remain unsupported.

The existing i8042 setup must have established translated set-1 input and received the keyboard scanning ACK before the fatal adapter reads keys. Mouse and parity/timeout bytes are discarded. USB-only keyboards are unsupported. COM1 also accepts 1/2, A/D/W/S in lowercase, Space, R/L/T and Escape. COM1 output has a finite ready wait and propagates timeout. Under the Supervisor profile there is no direct device input/GOP binding; the adapter falls back to the existing console hypercall with static image storage.

The standalone game's pacer latches the already running PIT channel-0 down-counter. It does not change timer mode/divisor or enable interrupts. Existing `sa_timer_set(VEC_TIMER, TICK_US=1000)` uses divisor 1193. Delayed polls can miss counter wraps, so pacing can slow during a large framebuffer copy; it is conservative pacing, not a claim of exact wall-clock 60 Hz. A fatal before timer preparation still has keyboard/manual Tetris controls but automatic gravity is unavailable. Physical hardware behavior remains untested.

The renderer uses the existing public-domain ASCII VGA font and an original stroke font for the 13 requested Hangul syllables. Other Korean text is not a general font service. No proprietary icon or BSOD image is included. The reference attachment informed the monochrome pile arrangement; it is never changed, shipped as OS evidence or substituted for a guest screenshot.

## Reproducible source build

The explicit startup controls are exactly `shz.dead-screen-panic-control`, `shz.dead-screen-ud-control` and `shz.dead-screen-text-control` (select one). They prepare the actual existing window manager/input during normal initialization, then deliberately invoke the own-kernel panic, a real ring-0 `ud2`, or forced minimal-text handling of an own-kernel panic. The private `gfx_wm.c` wrapper calls its unchanged `wm_init`, avoiding an invented GUI registration or null input-table initialization. Without any of these tokens the control returns immediately. These are synthetic native acceptance controls, never evidence of a real Win98 crash. Their guest execution requires a separately pinned and owned VM control run; the source build does not run them.

Run `python3 shizukudos/dead_screen/build.py --out build/dead-screen-candidate-<new-version>` from a fresh checkout. The source build requires Python 3.9 or newer, Pillow, GCC, Clang with ASan/UBSan, NASM, GNU binutils (`ld`, `nm`, `objcopy`, `objdump`, `as`) and `ldd`. It does not require previous build outputs, Windows media or private lab receipts. An existing output directory is refused. Every failure writes a separate result and retains logs. Optimized GCC controls and Clang controls with ASan/UBSan call the actual core/renderer. A separate host build calls actual `native.c` with compile-time modeled port/CLI/HLT services, proving source control flow without executing privileged hardware instructions. Real native compilation contains none of those host hooks. Tests cover unchanged recoverable state, first-record ownership, recursive refusal, fallback/write failures, malformed surface bounds, row padding/RGBX, collision/wall kicks/line clears/top-out, Suika merges/crowding/bounds, input sequences, prolonged gameplay, real adapter fallback/timeout/reentry and immutable trace across both games. Compiler/source/dependency/log/whole-kernel/artifact/ABI hashes are frozen. This source-build command touches no VM, guest disk, current display driver, target application or system setting.

For the original lab's historical chain only, add `--verify-history`. This requires all four original `build/dead-screen-candidate-20261001T{1035-v1,1040-v2,1045-v3,1100-v4}/result.json` receipts and their exact recorded SHA256 values. Missing or changed receipts fail the build; existing receipts are never rewritten. The result and manifest separately record `build_scope: source-build-and-host-controls`, `history_verification.requested` and its `NOT_REQUESTED`, `VERIFIED` or `FAILED` status. A source-build `PASS`, including one with verified history, does not establish native execution or Win98/VMM acceptance; those fields remain false and native acceptance remains pending.

The focused 2026-10-05 fatal-owner check executed the actual native adapter in
19 host I/O/CPU-model modes with 10,997 assertions, and compiled its production
translation unit using the existing Kernel64 flags. These checks covered
cross-CPU reentry without diagnostic writes, actual-owner CPU metadata,
unavailable CPU identity, pre-latch recursion, owner-only text capture and
fixed-tone gate loss. The native object contains a lock-free `lock cmpxchg`
instruction and no external `libatomic` dependency. These results prove the
tested source branches and production compilation; they do not prove real SMP
fault behavior, audio hardware, a full kernel link or native guest execution.

The RPC lifecycle observer and its outer fixture under `ntwin32/rpc_lifecycle_observer/` retain the original lab's fixed receipt and licensed-input identity checks. Their builders need the separately supplied matching private lab inputs; they are not part of this fresh-checkout Dead Screen source build. Those inputs and Windows original binaries must not be added to the public repository.

The Windows 2000/XP game artwork uses original miniature STOP/text lines, 8.1 a cyan face, 10 a face and decorative checker, and 11 a distinct framed label. The checker is not a scannable QR code. These are original game symbols and labels, not OS screenshots or licensed system icons.

## Separate historical guest evidence

On 2026-10-01, the three V6 standalone controls (panic, actual ring-0 `ud2`, and forced text fallback) ran in owned cold QEMU VMs against the separately held 664,026-byte candidate SHA256 `d050560d5c535482c08d442b05fdc7db2650b86f6b3a7290ac5d5f3131ab9114`. The panic and exception controls observed real PS/2 Korean/English selection, Tetris and Suika play/restart, immutable first trace, and direct framebuffer output; the text control observed exactly `You session got wasted` followed by an English traceback. This historical candidate is distinct from a freshly linked current-main image. The current image requires another pinned three-control run, as described in [the current integration notes](../../docs/DEAD_SCREEN_CURRENT_INTEGRATION.md). These are own Kernel64 component controls. Windows 98 MS-DOS replacement, VMM fault interception, recoverable Windows dialogs, Supervisor games and modern Windows applications remain unaccepted. Historical frozen source/receipts are not changed by the default integration.
