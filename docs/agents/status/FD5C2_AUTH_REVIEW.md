# FD5C2 independent account authority review

Scope: read-only production review in the shared laptop/security worktree on
baseline `5e2f125ad1de9f5e2d47fae432e5c0d97c49f359`. Root owns all production
account changes and Git/index integration. Reviewer owns only the new
`shizukudos/tests/test_auth_admission.py`, the newly assigned
`shizukudos/tests/test_auth_creation.c`/`.py`, and this report. Token implementation
and its six-file handoff are recorded separately in `FD5C2_TOKEN.md`.

Reviewed portable accounts/KDF, whole kernel authority dispatcher, auth policy
and account wire structs, process/loader/syscall hooks, process/thread handle
admission, general duplicate access ceilings, file/section/IPC routing, and
masked credential frontend. PBKDF2-HMAC-SHA256 round count, constant-time digest
comparison, throttling, nonwrapping session IDs, immutable kernel subject roles,
fresh-child credential launch, bootstrap enrollment capability and request
clearing have concrete source. Accounts remain volatile. Native Windows98 login,
protected credential UI, full NT object DACL semantics and native VMM isolation
are unqualified.

Findings sent to root: global named IPC admitted cross-account opens/collisions;
raw block/setup reads bypassed profile confidentiality; loader mapping read
resolved nodes without subject admission; file-backed sections bypassed the new
node admission; old device/pipe handles needed activated policy; fixed user SID
and ImpersonateSelf grants needed frontend updates. Root applied namespace
prefixes by UID/session/current integrity, reserved public `@` names before and
after enrollment to prevent pre-seeding, raw-read/device gates, canonical loader
and section gates, file admission before IRP preparation, and explicit pipe and
clipboard restrictions. Those edits belong to root, not this reviewer.

Correction: an initial claim that IPC file I/O never reached the sysfile gate
was incorrect. Whole `file_rw` calls `sysfile_dispatch`. The earlier pre-IRP gate
addresses preparation side effects; existing actual file content access already
reached the sysfile guard. The first review fixture also asserted syscall-level
named pipe creation refusal, whereas the implemented contract denies handle use
through `shz_auth_special_allowed`. That preliminary RED is preserved under
`build/fd5c2-auth-review/policy-red` but is not credited as a production regression.

Actual independent `policy-green-1` GCC and Clang ASan/UBSan pass. The complete
production auth dispatcher and account sources are compiled using root's actual
host fixture boundary adapters, extended privately with raw-read/setup-read/
device/driver/registry normal/elevated/sandbox comparisons, administrator label
lowering, subject namespace equality/difference, prefix capacity/output
preservation, Global refusal, reserved-prefix denial before/after enrollment,
canonical own/alien profile nodes and invalid alias/stream paths. Local quoted
source/header closure is captured before consumption and compared afterward.
Receipt `build/fd5c2-auth-review/policy-green-1/result.json` reports stable inputs;
tested dispatcher SHA256 is
`bddae766d5932d22452f891e70b3e1c0fbe024ed7a34aafa93e565557fa3604f`.
This tests admission policy, not actual filesystem/graphics/IPC routing,
physical IRQ races, SMP or Windows98 execution.

Creation/lifetime findings are now addressed in root-owned production source:
an IRQ-protected reservation protects a process slot across VM/heap/object
allocation, pending subject admission exists before `used` publication, and
loader/flat-process ready hooks admit foreign accesses only after preparation.
Real centralized `handle_lookup`/`handle_ref` invoke subject admission. Subject
bindings persist through teardown until the real final process-object free hook,
so retained terminated objects preserve their identity. Anonymous pending
bindings explicitly use the nonzero default auth ID `0x4e7`.

Actual `process_create_empty` is extracted unchanged into the new creation host
fixture. A deterministic VM-allocation callback reenters the production
constructor: immutable baseline `5e2f125` fails3 of4 checks (same slot, duplicated
CID/name, missing pending publication), preserved in `creation-original-red`.
Current constructor passes12 checks with both GCC and Clang ASan/UBSan in
`build/fd5c2-auth-review/creation-final-green/result.json`: distinct reserved slots and
CIDs, pending publication before return, restored IRQ state, failure/retry cleanup
for VM, both heap allocation sizes, object creation and pending-authority failure.
Tested constructor source SHA256:
`3f0eb920383207b9a7298141c740901ea598797e195bf56456bbefeb5e7b930e`.
The constructor source remained unchanged after `creation-green`; this final
run refreshes the receipt after root's `auth_policy.h`/`k64.h` declarations changed.
The preliminary directory named `creation-red` consumed the already corrected
live constructor and passed; only the pinned baseline failure is credited RED.

Final independent policy fixture `pending-final-free-green` also passes GCC and
Clang ASan/UBSan with stable source closure. It tests actual pending/ready hooks,
denial before fresh-child binding, self access, process/thread object admission,
same-subject ready admission, cross-subject denial, bootstrap refusal while a
different live process exists, and anonymous sandbox launch against a strict
nonzero auth-ID bind adapter. The complete unchanged `ipc_object_free` function
is extracted from production: early free before completed teardown retains
identity/resources; completed teardown releases VAD/handles, subject and process
slot once. Other object-free branches are explicitly unused boundary adapters.
Tested dispatcher SHA256:
`848960a48aee450ec7a9f54ccfccf6eeb8bbb464de419da1e56a748b0ec1ca15`;
tested final-free source SHA256:
`b8ede11691085a221d6b3007971cff879c002df53f717ac52e1758919743db3b`.
These tests use controlled loader/IRQ/VM/heap boundaries; they do not execute the
real scheduler, full loader, physical races, or native Windows98.

Initial review gate: global GUI input observation/injection and window queries
needed subject admission or explicit unsupported behavior. Cross-process send
messages already reject foreign owners; mutation routes enforce PID ownership,
but a masked dialog alone is not a secure desktop. The display agent owns the new
GUI gates. Final account-isolation acceptance requires that lane and root's fresh
combined compilation/routing checks; no full isolation claim is made here.

Separate source import review: exact
`ded7b8b4880a156d2b82d2b81a9407c8504d229f` restricted persistent AP service
matches all17 committed hashes in the shared source handoff. Read actual original
GCC7 receipt `44bf53023da4033703499d6c672ff7a6d328376cb7c318693621025c0ebd3cc2`
and Clang4 receipt
`e653957d15ca1d4f3441c4a8d0de4b59049a57715e97ff08fa16719de0ddab3e`:
both PASS, stable,47 commands,16 passing result groups, guest false. Source
admission is scoped to copied fixed-operation work, nonwrapping cookies,
restricted class2 lifetime, saved-stack migration, real request/ACK drain and
retention on failures. It is disjoint from these account hooks except imported
`k64.h` declarations. Fresh combined compilation/validation remains root-owned;
this is not physical AP, generic user/AP scheduling, native Windows or SMP proof.

Independent pre-enrollment sandbox follow-up: the former account-count-zero
shortcuts bypassed flagged anonymous sandbox restrictions. Root's actual RED
has 50 checks with 24 failures under each of GCC and Clang. The reviewed fix
retains ordinary pre-enrollment behavior while enforcing sandbox flags in path,
resolved-node, device/pipe, privilege, namespace and syscall admission. Every
network opcode from 0x80 through 0x8f is denied before dispatch for a sandbox,
including before the first account is enrolled. Fresh sandbox processes inherit
no old handles. No socket-handle I/O bypass was found in the reviewed typed
OB_FILE routing.

Reviewer independently ran:
`python3 -B shizukudos/tests/test_auth_sandbox.py --label independent-final`.
GCC and Clang ASan/UBSan each pass all 50 actual dispatcher-policy checks, with
stable/current project inputs. Receipt SHA256:
`0be999f61f9ce33458862933e9f12e08fbc9fb839474148693de3cf76f2e6140`;
tested `sysk32_auth.c` SHA256:
`2241fbd53af431ec56535e1f67a76e98fff8a91339a5204846d9f63c179e9da7`.
The fixture controls binding, loader, filesystem and IRQ boundaries and does
not execute network handlers, real device drivers or native Windows98.

Independent GUI source follow-up covers the actual shared authority helpers,
window/class queries, messages, input observation/injection, raw-input records,
hotkeys, foreground launch-capability consumption and compositor transitions.
Live queue/process/thread admission guards global input and foreign windows;
class mutation additionally requires caller ownership. Invalid or invisible
activations do not consume the kernel launch grant. Different foreground
authorities clear shared desktop/backbuffer state and old input records;
composition and physical input targeting use mutual foreground admission.
No additional concrete authorization blocker was found in that scope.

Correction to the preliminary reviewer note: the class ABI's index is already
signed 64-bit. INT32_MAX rejection was not a behavioral RED, and casting the
existing addition to int64_t was insufficient. Root's final source uses
`index >= 0 && index <= (int64_t)cb_cls - 8`, with registered cb_cls restricted
to 0..4096. This avoids signed addition and rejects INT64_MAX before memory
access. The current production fixture checks maximum-index GET/SET refusal
without changing class extra storage, plus valid offset-zero GET/SET.
Reviewed `gfx_wm.c` SHA256:
`30d056a66a2e868e4edbdd0273fd21fa7efc29ef0f19fd1728d3e627536d8d00`;
`gfx_auth.h` SHA256:
`cb603c0e445d5ee7ea550c106a01b7ef874dc267dca49c9eeb8441046f846af3`;
`gfx_msg.c` SHA256:
`f547578e8504ea561318b4b6262de970ee5f8ad0df07c9ff202cb7bbd19e1f6f`;
`gfx_input.c` SHA256:
`037cd4bee5e1578d638a55bbaf43d44a9fb4bb6f8432244fd0cf8ad7e5eef0b7`;
current `test_gfx_auth.c` SHA256:
`72ea47912e35187eb8c0c83cb0dc15c4d65b8b383e928b69fe0290909d1f83f2`.

The inspected historical GUI final-v5 receipt pins the earlier class addition
source and reports failure after a 120-second standalone Clang compile deadline.
Its 96 passing host checks do not validate the final subtraction source.

Final scoped acceptance: reviewer independently read root's original
`/dev/shm/fd5c2-gui-host-final/result.json`, SHA256
`e6055c7fdbf3c53b943a4bc292ddb2f9a39452807a261d22ffa313c882aaa557`.
The final subtraction source and fixture hashes above are pinned, all 27 project
input hashes match current files, and the recorded before/after comparison
passes. GCC strict and Clang ASan/UBSan each execute 97 actual production GUI
route checks with zero failures. GCC sanitizer execution is explicitly
`BLOCKED_NOT_RUN` because the installed GCC sanitizer runtime files are missing;
it is not credited as a sanitizer pass. The bounded RAM-output `--host-only`
runner is pinned as SHA256
`345fc867d1c12f7e1e80c5d162ec29b57f5192c515bffe94d72a4811a6426acd`.
This validates host source routes with controlled kernel boundaries.

Reviewer also independently read root's original
`/dev/shm/fd5c2-integration-final-v2/result.json`, SHA256
`dfe2b7302ca286fa2c6f4ae87a5653f3695c625b5d1e1a1d55e744e51dc189e3`.
All 60 pinned project inputs match current files, source stability is true,
and all 38 commands exit zero: the 18 account/token/process/filesystem/IPC/GUI
units compile with each of GCC and Clang using the captured production
Kernel64 flags, followed by one relocatable partial link per compiler.
Undefined external runtime symbols are retained and explicitly reported.
These receipts close the scoped host and combined-unit review gates. Root owns
preserving the unchanged receipt files for delivery; reviewer did not duplicate
the builds or tests.

A shared desktop, aggregate resource metadata, ordinary same-realm peers and
the existing broader administrator policy remain explicit limits. The final
checks do not qualify a full kernel/image build, standalone profile, guest boot,
protected credential desktop, native Windows98 isolation, physical races or
SMP. External toolchain dependency closure is explicitly incomplete.

Commit SHA: pending root coordinator commit.
