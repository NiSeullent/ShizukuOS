# Root status — fada

Assigned scope: preserve Windows 98 architecture, coordinate other chats,
review implementation and peer changes, run fresh verification and publish.

Implementation commit: `d4615296c27a0ccb27ce1ab344bbd2ed322ce4c8`.
Branch: `codex/pma-bridge-fada-20261002`.
Worktree: `/root/Win98-Modern-pma-bridge-fada-20261002`.

Root independently reviewed/imported the IPC geometry/private-snapshot and
three display corrections. Final imported display alias follow-up is d71ec6c;
its GCC/Clang ASan host contracts pass 63 handoff and 156579 clipping checks.
All four profiles freshly build after final IPC and alias correction, with a
207-source manifest bound to the receipt.

Final IPC host suite passes 3665554 GCC and 3665540 ASan/TSan checks, i386/x64/
MinGW syntax and 6000 independent C/Python frames. Fresh VxD build plus all 12
host test groups pass, including 234 bridge and 2504 WIN64 bridge assertions.
Delegated independent service/transport/rundown replay is source-bound and PASS.

Actual supported-display no-NIC KVM guest at the PMA commit passes all 38 gates:
16 PMA fixtures, 48 legacy loopback fixtures and all 151 ordinary apps exit 0.
218.27 s, limit 240 s, guest exit 0, expected QEMU exit 1. Manifest 206 entries,
kernel/stub/initrd and five runner/evaluator helper hashes remain unchanged.
The prior no-display FAIL is preserved and explained, not promoted to PASS.
The final merged alias guest also passes all 38 checks in 212.08 s,
with its 207-source manifest, guest inputs and evaluator sources unchanged.
Guest/runner exit 0, actual expected QEMU status 1. Kernel64S SHA256
`c4473ffbb3a29b56127bd35763263a5060a07f4f0a1db943880fd09ca8cc8fe8`.
The narrow Python-runner stale-output/abnormal-exit fix supplied by c957 is
reviewed/imported as 21badda. Root passes five modeled controls and rechecks
the preserved actual native data against expected status1 and unchanged
207-source manifest/binaries. No additional guest is claimed for that recheck.

Other chats use shared ownership records, tested scoped commits and reciprocal
reviews in `/srv/shizukudos-session-coordination/`. Published exact source and
actual scope there. Follow-on read-only Windows endpoint audit is handed to
163f's exclusive VxD/DOS lane; no ordinals or native identity authority invented.

Broader unverified gates: authoritative Windows identities/lifecycle callbacks,
actual VMM wait delivery, ShizukuDOS→WIN.COM→VMM→Windows desktop and SMP.
