# ShizukuOS theme: native acceptance

The committed appearance application and profile provider have host, sanitizer,
PE/OEM and full executable-byte i486 evidence. They still require actual Windows
98 execution. The earlier Classic/Modern probe and its native verifier cannot
certify ShizukuOS style 3, profile storage or application restart.

The additive `SHZTPRO.EXE` profile probe is intended for a source-pinned private
Windows 98 SE guest. Its provider is the exact matching adjacent `M98THEME.DLL`.
The probe must reject a different reported platform/version before saving any
setting. That API check is a prerequisite; the operator must also establish the
guest's actual provenance independently. Compiler success and a compatibility
version override are not proof of Windows 98 execution.

The shared VM owner runs separate processes for the following phases, retaining
each command, full output, exit status and exact source/artifact hashes:

1. With this test user's profile key/value absent, load the default ShizukuOS
   selection. Do not erase a real user's saved setting merely to obtain this
   case; use the isolated test guest or an explicitly prepared test user.
2. Save Classic 1, load it through the production provider and independently
   read the real `ThemeStyle` registry DWORD. Check real GDI/DIB fill and border
   pixels against the literal Classic palette, then close the process.
3. Start a fresh process and verify the saved Classic selection and pixels.
4. Save ShizukuOS 3 and verify the typed registry value and literal ShizukuOS
   palette through actual GDI painting, then close the process.
5. Start another fresh process and verify the saved ShizukuOS selection and
   pixels. Preserve complete termination evidence for every owned child.

Give every probe child an inherited file output handle and wait for its actual
termination. The probe flushes that file before accepting its log. Bind its
compiled nonce, ordered checks and final status to the same uploaded EXE/DLL;
a PASS line without successful process termination is insufficient.

Only the explicit save phases may change this test user's appearance setting.
Checks must fail on unsupported selectors, registry errors/wrong type or size,
invalid handles, a mismatched palette, failed GDI operations or a different OS.
The new helper host tests validate argument parsing, the platform/version
predicate and bounded adjacent DLL paths. They do not simulate registry/GDI
success or produce native acceptance.

The appearance GUI requires a separate actual input sequence. Start
`SHZAPPEAR.EXE`, select Classic, Apply, Close; start it again and verify Classic
is loaded and painted. Select ShizukuOS, Apply, Close; start it again and verify
ShizukuOS is loaded and painted. Exercise mouse and Tab/Space/Enter/Escape,
retain source-bound screenshots and input/exit records, and independently read
the real saved registry DWORD. The command-line profile probe cannot certify
these GUI actions.

Cross-process loading is separate from reboot and OS-wide integration. The
installer must include the same provider/application/source closure; the shell,
common controls, nonclient painting, AMD64 provider and Kernel64 compositor must
consume the profile and actually repaint. Verify them again after an actual
cold boot. No existing test result should be relabeled as evidence for these
new operations.

The current Kernel64 registry performs real key/value operations in volatile
memory and has no disk hive. Its successful Save does not establish cold-boot
persistence. The existing desktop stores a separate file and internal theme
selector; integrate that durable preference or a real registry backend with
the shared Classic 1/ShizukuOS 3 contract while preserving legacy Modern 2.
The AMD64 provider still needs style 3, profile exports and its matching build
gate. Its NT version report belongs to its own execution path; use separate
acceptance for it rather than changing the version to satisfy this Win98 probe.

BOOT owns the shared guest, installer, unified ISO and final boot epoch. This
preparation starts no guest and claims no native acceptance. ShizukuDOS must
replace MS-DOS in the actual Windows 98 installation and boot chain; a Microsoft
`IO.SYS` chain boot is not replacement evidence. Kernel32 and Kernel64 are for
the Windows 98 ShizukuDOS path. The public final ShizukuOS 1.0.0 ISO belongs only
at https://m98.nyase.kr, and private original Windows media stays separate.
