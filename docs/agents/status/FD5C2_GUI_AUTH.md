# FD5C2 — Kernel64 GUI subject gates

Owner: `/root/display_audit`, with final bounds validation and integration by root; shared isolated checkout
`/root/Win98-Modern-laptop-security-fd5c-20261002`, initial HEAD `5e2f125`.
Root owns commits/index and the accounts/token policy. This lane changes only
`shizukudos/kernel64/{gfx_wm.c,gfx_msg.c,gfx_input.c}`, creates `gfx_auth.h`,
`shizukudos/tests/test_gfx_auth.{c,py}`, and this receipt. The personalization
receipt has a wording-only correction: its executed variants were GCC strict
and Clang ASan/UBSan. Frozen personalization sources and artifacts are unchanged.
GUI production sources are frozen; final validation is recorded below. No git
staging/commit, full kernel/runtime build, VM, media, download or global
configuration change was performed by this lane.

The production gate uses the actual window's queue, process and thread:
queue/process liveness, saved thread ID, thread process binding, PID/TID binding,
and `shz_auth_process_access`. Window user data and names do not establish
authority. Queries for title/class/extra/window relationships, enumeration,
hit testing, send/post/thread-post, Present and read-only window operations
deny or filter inaccessible owners. Class GETLONG/GETNAME also require the live
window gate; SETLONG requires both window and class owner PID. Existing
`wm_owner_ok` and the window mutation ownership checks remain strict same-PID.
Present preserves drawing by an authorized worker in the same subject, as used
by Chromium's GPU process. No public handle ABI or gfx.h structure changed.

Explicit and implicit activation require authority over the current foreground.
A fresh verified LOGIN/ELEVATE child can enter through root's kernel-only
`shz_auth_gui_take_entry` once, at an actual caller-owned activation. Invalid,
foreign and invisible SETFOREGROUND windows do not consume that entry. Root
owns proof of minting, successful reply copyout, lifetime binding and absence
of an unprivileged grant opcode; this fixture mocks that callback only.
ShowWindow/SetWindowPos may change an owned background window while suppressing
unauthorized activation. A foreground that disappears uses the existing
activation repair path and clears the shared screen for a different authority.

The screen compositor and physical hit/capture selection include only windows
with mutual access between the foreground subject and the window owner. Thus
a lower-integrity window cannot become an overlay merely because a higher
subject can read it. The occlusion optimization applies the same filter, so a
hidden foreign opaque window cannot leave old pixels in the backbuffer.
PrintWindow uses its authorized caller when composing its offscreen target.
On a change of foreground authority the backbuffer, saved layered background,
shared desktop surface, pressed-key history, queue key snapshots, raw-record
IDs and foreign captures are discarded before the full screen is rendered.
Per-window private surfaces stay kernel-owned and are filtered on composition.

Global async-key, cursor-position, injection, clipping and input-information
operations require a live authorized foreground recipient. With no foreground,
only desktop metadata is permitted; global input/mutation is denied. Local
queue key state remains local. Background hotkey dispatch and raw INPUTSINK
delivery require foreground authority. Raw IDs are bound to their live queue
and saved thread identity; RAWGET checks that recipient's authority before
copyout, and queue teardown/foreground transitions invalidate those IDs.
Processes authorized to the same recipient can read its raw record; this is
the existing subject trust boundary, not an exact-PID raw-input boundary.

Behavioral RED logs are under ignored `build/gfx-auth-fd5c/`:

* Initial actual unmodified caller execution failed 17 of 27 assertions in
  `red/`, including foreign queries, messages, Present and global input.
* `entry-red/` failed one of 84 assertions: an invisible SETFOREGROUND consumed
  an entry despite returning STATUS_UNSUCCESSFUL. Moving the entry check after
  visibility validation fixes that actual caller path.
* `class-red/` failed five authorization assertions for class metadata/extra
  read and mutation, plus one positive-case assertion whose input depended on
  the unauthorized preceding mutation. The positive input is now independent.

These RED binaries/logs are retained but are not sealed reproducible source
snapshots of every initial fixture version. A missing mock kzalloc link and
initial Present fixture layout setup were corrected before their behavioral
RED execution; failed compilation is not treated as a behavioral RED.
`final-v3` was stopped and its compiler group reaped at the runner's 60-second
compile deadline, with no compiler diagnostics. The final runner allows a
bounded 120 seconds per owned command, 512 KiB command logs and 16 MiB total
output, snapshots both bridge and standalone project include closures before
and after, checks compiler/binary/source hashes and reaps owned process groups
on failure. External SDK/toolchain dependencies are not a sealed closure.

Executed validation:

```sh
python3 -B shizukudos/tests/test_gfx_auth.py --out build/gfx-auth-fd5c/final-v4
python3 -B shizukudos/tests/test_display_contract.py --cc gcc --out build/gfx-auth-fd5c/display-gcc
env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1 python3 -B shizukudos/tests/test_display_contract.py --cc clang --sanitize --out build/gfx-auth-fd5c/display-clang-san
```

Final-v4 historical GUI verdict: **PASS91**, before the final class bound change. Earlier final-v2 passed 84 actual production
route checks on GCC strict and Clang ASan/UBSan plus twelve separately compiled
GCC/Clang bridge/standalone objects, before the additional class gate.
GCC ASan/UBSan is **BLOCKED_NOT_RUN**: its installed linker scripts refer to
missing `/usr/lib64/libasan.so.8.0.0` and `libubsan.so.1.0.0`. No package was
installed and no failed/blocked variant is counted as an execution.
Existing display regression is PASS in both the GCC strict and Clang sanitizer
variants: 63 production boot-framebuffer and 156,579 framebuffer clipping/
statistics checks each, with source/compiler hashes unchanged in their receipts.

The fixture includes the actual WM, message and input C sources and links
actual `accounts/account.c` subject policy. It exercises real syscall selectors,
queue/window tables, pixel composition and input delivery; user copy,
allocator, locks/IRQ, clock, identity binding, launch-entry callback and display
boundary are mocked. It does not execute the scheduler, hardware, a GUI guest,
the root grant implementation or native Windows 98 USER/GDI. A full image link
and guest acceptance remain separate requirements.

Root final acceptance uses `/dev/shm/fd5c2-gui-host-final/result.json`, copied
unchanged into `build/fd5c2-delivery-validation/gui.json`. Actual GCC strict and
Clang ASan/UBSan each pass97 route checks, with all27 source pins stable and
matching the delivered source. This run explicitly uses `--host-only`; it does
not claim twelve new standalone/bridge object builds. Separate current
`build/fd5c2-delivery-validation/integration.json` records GCC and Clang compiling
each of18 actual routing units using production K64_FLAGS, followed by one
partial relocatable link each:38 zero exits,60 matching source pins, external
runtime symbols retained. The independent account reviewer read both final
records and admitted this limited scope.

The final class-extra bound is `index >= 0 && index <= (int64_t)cb_cls - 8`.
Actual `shz_classop_t.index` is int64_t; the earlier INT32_MAX diagnosis was
wrong, and its passing test is not a RED. The final fixture rejects INT64_MAX
GET/SET without modifying the backing, and checks valid index0 accesses.
The final source SHA256 is
`30d056a66a2e868e4edbdd0273fd21fa7efc29ef0f19fd1728d3e627536d8d00`.
The prior `final-v5` remains failed at a120-second compiler deadline. The later
full RAM runner ended with exit143 before a final receipt and is not credited.
The separate bounded host run and current combined compilation above provide
the delivered component evidence; no environmental cause is asserted for143.

Security limits: this remains one shared Kernel64 desktop. Ordinary masked
elevate UI in the anonymous realm trusts other anonymous processes: same-subject
query, messaging and injection authority remains, so it is not a SecureDesktop
or a credential isolation boundary against those processes. The production
account policy's unrestricted elevated-admin access remains unchanged. Global
registration/resource tables are not separate per account; no resource-DoS or
complete covert-channel isolation claim is made. Native Windows 98 is a
separate realm and its account/desktop boundary is not implemented by this
patch. Separate desktops, a protected credential prompt, real native/frontend
acceptance and actual hostile-realm guest testing remain pending.
