# Supervisor constructor device gate

This candidate puts a mandatory gate before either optional native VGA or
persistence initializer. The absent-device RAM branch performs no fw_cfg,
COM2 or PCI access and does not consume the static gate. A selected optional
device requires a policy and current grant; refusal does not fall back to RAM.
`VGACFG.BIN`136B, `W98PERS.BIN`192B, WIN98CFG and shz_info ABIs are unchanged.

The native constructor calls the gate after RAM-only ATA initialization and
before VGA initialization, persistence initialization or RUNNABLE publication.
Supervisor startup creates this domain before the Kernel32/Kernel64 domains
and scheduler. This gate does not change their foundation policy or lifetime.
It cannot prevent OVMF's earlier firmware device accesses.

The production object is static, exclusive and never reset or reused. The
whole-object API requires the same lifetime discipline from its caller. A
second attempt refuses and revokes admission, including after a successful
first attempt. The protocol helper remains byte-unchanged. No actual owned
host grant counterpart is wired yet: **optional runtime promotion is blocked**.

The Supervisor reads the sole `opt/shizuku/native-device-epoch` fw_cfg item
through PIO selector0x510/data0x511. It verifies the QEMU signature, the BE
directory count and all observed entries; at most128 entries/8192 row bytes
are read. Reserved fields, invalid or repeated selectors, non-ASCII/nonterminated
names, duplicate target names, wrong target size and dirty target-name padding
refuse. The target has exactly256 bytes. No fw_cfg DMA/data write occurs.
The signature and namespace are parser observations, not host authority.
[QEMU's fw_cfg specification](https://www.qemu.org/docs/master/specs/fw_cfg.html)
documents the PIO registers, BE directory and read-only external items.

Policy wire fields are little endian; there is no native-struct padding:

| Offset | Extent | Field |
| --- | --- | --- |
| 0 | 4 | WDEP magic0x50454457 |
| 4 | 2 | version1 |
| 6 | 2 | extent256 |
| 8 | 4 | role mask: VGA1, storage2; exactly the selected blobs |
| 12 | 4 | zero |
| 16 | 32 | fresh nonzero per-attempt host nonce |
| 48 | 32 | full136B VGACFG SHA256; zero when unselected |
| 80 | 32 | full192B W98PERS SHA256; zero when unselected |
| 112 | 32 | full65536B VGAROM SHA256; zero when VGA unselected |
| 144 | 8 | original host monotonic deadline, integer nanoseconds |
| 152 | 4 | local gate budget10000ms; no other value admitted |
| 156 | 2 | COM2 base0x2f8 |
| 158 | 2 | zero |
| 160 | 2 | VGA BDF; zero when unselected |
| 162 | 2 | storage BDF; zero when unselected |
| 164 | 4 | zero |
| 168 | 24 | six VGA raw BAR DWORD expectations |
| 192 | 24 | six storage raw BAR DWORD expectations |
| 216 | 40 | zero |

Full config/ROM bytes are copied into retained Supervisor buffers before
hashing. Generic bounded SHA256 handles0..65536 bytes, including arbitrary
config lengths and two-block padding. VGA shape/BDF/LFB and storage
shape/BDF/vendor/device/geometry/BAR type/base are validated against those
copies. Raw expectations are also checked by the unchanged readonly PCI
protocol. Unselected hashes/BDFs/BARs must be zero. The original selected blob
identities and full bytes, and the retained copies' full bytes, are rechecked
after transport. Only an admitted snapshot accessor supplies the later
initializers. Caller memory changed after admission cannot change the copies.
These retained buffers are separate from the virtio request/DMA object and are
never made writable to L2 through the selected-device interface.

There are two clock domains. The local absolute TSC end is bound once, before
fw_cfg lookup, to constructor-start+10*tsc_hz. Every port callback is checked
before/after against that same end and monotonic progress; field drift refuses.
Hashing and final admission are also followed by deadline checks. The host
deadline field is **not** interpreted as TSC or checked against TSC. The future
host owner must verify it equals its actual original deadline and reserve the
whole exchange inside that existing interval, without resetting a boot-wait
or QMP deadline. The fixed local bound supplies an additional refusal bound.

COM2 is exclusively owned by the Supervisor. It is configured115200/8N1 with
FIFO and no UART IRQ. READY48 follows FIFO clearing: WDE1/version1/kind4/
extent48/count0 and the policy nonce at16. The host must receive this exact
READY on the actual owned socket before sending the unchanged CHALLENGE48.
REPORT256/GRANT272 then use the existing helper. RX/TX callbacks return at
most16 bytes, check UART errors and never block for a byte. READY has a finite
4096-call bound; the unchanged helper has its own shared4096 transport-call
bound. All control port operations share32768 calls and the one TSC deadline.
Native pause has both a1ms bound and100000-iteration cap. Readonly PCI reads
select/restore CF8 and read CFC; no CFC/PCI data write, BAR sizing, VGA port,
MMIO/reset or DMA operation is expressible through this gate's implementation.
Deadline failure can prevent a CF8 restore; this leaves only a config-address
selector and never permits either initializer to run. Guest COM2 remains
unhandled by the existing fully trapped L2 PIO path; no forwarding was added.

Root's separate host implementation must supply all of the following before
any actual optional launch:

* Fresh nonce, exact immutable policy bytes/source FD and return-derived pin,
  consumed once by the current guardian attempt; no old receipt or fixture.
* Source/recipe/ESP/cache/ROM lineage, no image or ABI rewrites, and exact
  observed process/pidfd/starttime/executable/argv/cgroup binding through reap.
* One exclusive connected COM2 chardev FD inherited by that QEMU, with the
  guardian's host endpoint and policy source retained; no reconnect/guest path.
* Sole owned QMP observer with fresh SO_PEERCRED and process checks around
  every observation, actual stop/query-status pause, bounded current query-pci,
  FlatView RAM and block/cache observations, and before/after resource checks.
* Exact selected qdev/BDF/type/vendor/device/raw BAR bases plus QMP BAR sizes,
  RAM exclusions, owned writable ESP backing node/FD/cache flags and actual
  exclusive device epoch. No grant for unknown physical devices.
* Grant echo of the exact current report/nonce under the unchanged host
  deadline; resume only that owned paused process. Pause alone is not a DMA
  reset acknowledgement. Storage still needs its existing real reset/flush
  and retained-DMA lifetime rules.

Configs prepared before OVMF are expectations. Mismatched current resources
refuse; an earlier QEMU's addresses never confer current authority. fw_cfg
solves nonce delivery without copying an ESP just to inject a nonce. Exact
host-QEMU fw_cfg/chardev syntax and runtime observations still need actual
owner admission; none were executed by this source task.

Host evidence executes real C hashing, policy parsing, PIO/UART/PCI control and
constructor ordering with modeled firmware/ports/clock/host grant or physical
initializer boundaries. Ordinary component compilation proves linkage only.
Actual process/QMP/device epoch, physical PCI/MMIO/DMA, Windows boot, VGA/GDI,
persistent writes, cold boot, full SMP and installer/public ISO remain false.
Primary compiler binaries are held and pinned in the owned finite host unit;
external compiler subprocesses/includes/runtime dependency closure is incomplete.
