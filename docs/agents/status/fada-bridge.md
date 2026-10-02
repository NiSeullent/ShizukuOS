# Fada PMA bridge service checkpoint

- Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52`.
- Worktree: `/root/Win98-Modern-pma-bridge-fada-20261002`.
- Branch: `codex/pma-bridge-fada-20261002`.
- Ownership: `shizukudos/abi/shz_vmm_pma.h`,
  `shizukudos/pma_bridge/{service.h,README.md,test.py,tests/test_service.c}`.
- Independent transport validation in the same bridge directory belongs to the
  `bridge_validation` agent; runtime integration belongs to `shizukudos_survey`.
- Source state: committed as `d4615296c27a0ccb27ce1ab344bbd2ed322ce4c8`; independently reviewed and host/native component tested.
- Implemented: fixed64-byte PMA payload ABI over unchanged IPC1.1; QUERY including
  monotonic clock snapshot; process-private auto/manual events; deferred WAIT;
  SIGNAL/RESET/CLOSE; cancellation; thread/process exit; idempotent shutdown; generation/identity
  validation; bounded admission; completion retention and peek/ack transmission.
- Validated locally: GCC and Clang ASan/UBSan each 3,429 behavior checks; i486 and
  x86-64 freestanding layout builds. Exact receipts are in
  `build/pma-bridge/result.json`, with source guards, commands and UTC times.
- Acceptance scope: the host service is exercised. Kernel64 real-ring standalone
  integration passes 16 PMA and 48 legacy service checks; actual Windows VMM/PMA event delivery and
  lifecycle identity binding remain pending. No VMM ordinals were fabricated.
- Final teardown regression: 64 admitted infinite waits plus 64 ready replies occupy all 128 completion slots; shutdown cancels waits without a new allocation, preserves existing successes, rejects admission, and newer restart reopens. Process cleanup also works after its last thread exits or the thread registry fills.
- Constraints: safe tombstones limit distinct PID/TID identity churn; exhausted
  registries fail explicitly until documented epoch reuse or coordinated newer
  channel restart. The README records all capacities and the clock contract.
- Preserved: Windows 98/VMM/USER/GDI/Win16/Win32 ownership, existing boot paths,
  frozen historical evidence and private Windows media boundaries.
