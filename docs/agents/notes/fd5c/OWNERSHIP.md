# Ownership — fd5c integration

Shared worktree: `/root/Win98-Modern-pma-integration-fd5c-20261002`.
Agents edit disjoint source files; the coordinator alone stages/commits.

| Agent/chat | Owned files or lane |
|---|---|
| fd5c coordinator | these master documents; native_win98/tests/run_host.py regression integration; combined validation; shared coordination record |
| compat_audit | `shizukudos/abi/shz_ipc.h`, `test_abi.c`, status/FD5C_ABI.md; follow-up `ntwin32/win64/ntw64.c`, new `tests/{handle_lifetime_host.c,test_handle_lifetime.py,mock/windows.h}`, status/FD5C_HANDLES.md |
| core_audit | `supervisor/src/domain.c`, new doorbell host fixtures, status/FD5C_DOORBELL.md |
| display_audit | `supervisor/src/video.c`, minimal supervisor/build.py CP437 link, new video host fixtures, status/FD5C_VIDEO.md |
| 163f / 문서화 Win98 통합 아키텍처 | peer tree: Kernel64 priority/quantum, UEFI EDID/mode selection, ntwrapper/vxd bridge concurrency |
| c957 / Integrate ShizukuDOS 10 PMA | peer trees: native synchronization helpers, GOP handoff robustness, wrapper capability manifest; actual DOS executor remains unassigned |
| fada / Win98 현대화 구조 병렬 구현 | peer tree: new abi/shz_vmm_pma.h, pma_bridge/, kernel64/subsys64.c integration, run_k64_pma_bridge.py |

Peer ownership is read from their chats and shared records, not permission to
edit peer working trees. Cross-chat responses/commits are tracked in
`/srv/shizukudos-session-coordination/PMA-fd5c-20261002.md`.

Follow-up reservations published to all peers: core_audit owns only
`ntwrapper/vxd/test.py`, new `tests/test_receipt_inputs.py` and
`status/FD5C_VXD_RECEIPT.md`; display_audit owns the narrow fatal-display
AUTO guard in `supervisor/loader/loader.c`, new focused caller fixtures and
`status/FD5C_GOP_AUTO.md`. compat_audit retains its ABI files for one private
message snapshot and a deterministic CRC-collision regression. No peer
worktree/index is edited; coordinator alone imports reviewed tested commits.

Final peer imports include PMA service/lifecycle, UP Kernel64 scheduler and
Kernel32 finite deadline arithmetic. Canonical163f retains scheduler/test
production ownership; our agents' final reviews are read-only. c957 owns the
bridge guest fresh-output/exit-status fix; canonical core/c957 coordinate complete
kernel source closure. Root's disposable focused guests/builds write only its
own build directories. Existing VM/private media and peer indexes stay untouched.
