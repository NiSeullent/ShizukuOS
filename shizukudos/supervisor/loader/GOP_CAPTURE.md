# Current UEFI GOP observation

`shz_gop_capture()` executes the real firmware protocol interfaces before the
final memory-map/ExitBootServices sequence. It captures values only: no device
admission, epoch, persisted proof, driver load or default Display mutation.

The selected GOP pointer must appear on exactly one enumerated GOP handle. Its
complete single-instance DevicePath must have a unique closest enumerated PCI
ancestor. The final PCI node agrees with actual GetLocation device/function;
PCI config supplies current display identity, command and BAR values. All six
BAR slots are examined without writes or sizing probes; 64-bit upper slots are
handled together. The framebuffer's complete extent must fit exactly one
current memory resource with actual host/device translation and matching BAR.
Two fresh complete observations surrounding actual EFI_RNG_PROTOCOL.GetRNG
must agree. Missing/unsupported/non-PCI/ambiguous/drifting sources fail closed.
The RNG output is just a captured random value, not independently verified
entropy quality, freshness across firmware rollback or an authorization token.

UEFI table14.10 defines Address Range Maximum as the end address. EDK2's actual
PciIoGetBarAttributes writes `PciBar.Alignment` there. Both explicit forms are
retained (`maximum_encoding`1 end,2 power-of-two BAR alignment mask); the actual
range is always bounded by base+AddrLen and compared with real BAR values.
No other maximum form is accepted. Translation addition and range arithmetic
are checked. Each BAR list is bounded to seven QWORD descriptors plus End Tag;
a nonzero End checksum must validate. Firmware-allocated lists and handle
arrays are freed on every path, including failures. Failed FreePool refuses
capture; firmware failure cannot prove that the buffer was freed.

Firmware-provided DevicePath/resource pointers are trusted UEFI protocol
allocations, not arbitrary untrusted host input. These APIs provide no buffer
length for a path or BAR descriptor allocation: byte/node caps bound parsing,
but cannot prove a malicious firmware allocation's extent. Protocol calls may
block inside firmware; the bounded number of calls is not a firmware watchdog.
The caller must run this before EBS and reserve/copy output into a separately
protected Supervisor handoff before considering a physical boot issuer.

Run `python3 shizukudos/supervisor/loader/tests/test_gop_capture.py` from the
repository. It compiles actual capture C and existing uefi/boot.c with strict
warnings, then executes modeled UEFI callbacks. The host cases include exact
and ambiguous handles, PCI ancestry, identity and resource drift, missing/
failed/zero RNG, geometry change, invalid config/paths/descriptors, overflow,
checksum, host/device64-bit translation, EDK2 alignment form and cleanup.
These are component tests, not actual firmware, installed Windows or GOP
rendering evidence.

Integration still required (other owners): add this C file to the loader build;
call immediately after sd_gop_select and before final GetMemoryMap; extend a
versioned protected handoff; post-EBS resource/writer admission and domain/VMCS
binding; separately versioned physical issuer query; real guest locator and
framebuffer provider; same-boot DOS observation and supported Windows startup.
Do not change or bypass the current HC14 v1 VM HostGrant contract.

Primary definitions:
- https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html
- https://uefi.org/specs/UEFI/2.10/14_Protocols_PCI_Bus_Support.html
- https://uefi.org/specs/UEFI/2.10/37_Secure_Technologies.html
- https://github.com/tianocore/edk2/blob/master/MdeModulePkg/Bus/Pci/PciBusDxe/PciIo.c
