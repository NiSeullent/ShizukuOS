# Native-only PIT2 and keyboard firmware contracts

This isolated source candidate repairs two observed model gaps used by an actual
Windows 98 control. It does not yet demonstrate that either caused ScanDisk to
remain at 99%, a Windows VMM/GUI transition, ShizukuDOS replacing MS-DOS, or modern
application support. The installed control disk still boots original Microsoft
DOS. Existing VM evidence and all original media are preserved.

`win98_domain_create()` alone enables the native profile after ordinary device
initialization. Every `dev_init()` selects the previous default DOS device profile.
The new behavior is therefore confined to the opt-in installed-Windows98 domain;
it is not a default boot-profile change. The existing full 256 KiB SeaBIOS shadow,
MTRR CPUID mask, exact absent-LAPIC page and passive fatal observer are preserved.

PIT2 binary mode0 now has a real terminal OUT boundary driven by the measured host
TSC. Gate-low suspends accumulated counting; gate-high resumes it. A new control
or count restarts the interval. OUT remains high after terminal count while the
16-bit counter wraps, and a latched counter remains stable across its paired
reads. Original split arithmetic and bounded searches avoid overflowing a
64-bit multiplication or requiring a 128-bit freestanding division helper.
Other PIT modes, PIT0 interrupt delivery and PIT read-back remain as before;
this candidate is not a complete 8254 implementation.

The native keyboard has a bounded 16-byte reply FIFO. Reset produces FA then
BAT AA; GETID produces FA AB83. Scan-set query/set, LEDs, typematic, enable,
disable/defaults and echo have defined wire responses and parameter state.
Unknown keyboard commands produce FE rather than a false generic ACK.
Controller configuration, interface/self tests and A20 commands are supported.
There is no auxiliary mouse; its test reports absence and AUX-send emits no
invented ACK. Overflow preserves queued bytes and records dropped replies.
Response IRQ1 edges depend on the command byte and interface-enable state;
existing IRQ14 cascade, masks, priorities and EOI behavior remain intact.

These are keyboard **command** contracts. Host PS/2 sampling, native focus,
physical-key forwarding, scan-code translation, full reset/BAT timing and a
mouse are still unimplemented. This patch sends no host keystrokes. It cannot
claim an interactive Windows keyboard or desktop acceptance.

Passive numeric observation retains up to 32 PIT and 64 KBC records. Repeated
reads coalesce; port61 refresh-bit toggles do not consume the entire PIT buffer.
Actual first/last values, first/last TSC, width/direction, repeat and drop counts
remain available. The device I/O paths contain no logging, allocation, guest
memory access or VMCS writes. A normal diagnostic dump waits until an actual
mode0 terminal OUT read and subsequent port61 restore have both been observed,
no mode0 interval remains open, and at least ten seconds have elapsed. Terminal
triple-fault/VMCS failure diagnostics may dump earlier. This avoids printing inside the
calibration loop; the observation is not an instruction-timing transparency claim.

The documented firmware contracts were checked against primary upstream sources:

- [SeaBIOS rel-1.17.0 TSC calibration](https://github.com/coreboot/seabios/blob/rel-1.17.0/src/hw/timer.c#L55-L90) programs PIT2 mode0 with 0x800 ticks and waits for OUT.
- [SeaBIOS PS/2 command transport](https://github.com/coreboot/seabios/blob/rel-1.17.0/src/hw/ps2port.c#L143-L264) consumes ACK, reset BAT and GETID bytes.
- [QEMU v10.1.0 PIT common model](https://github.com/qemu/qemu/blob/v10.1.0/hw/timer/i8254_common.c#L41-L70) documents mode0 terminal OUT behavior.

This implementation is original repository code; no firmware code or proprietary
Windows code was copied. The upstream references alone do not prove the exact
build/configuration of the privately pinned packaged ROM.

Host verification compiles actual production bodies with strict GCC and Clang
ASan/UBSan. The behavior RED control compiled the old PIT model with the new
opt-in API scaffold and failed its first pre-terminal OUT assertion in both
compilers. GREEN controls cover boundaries, gate pause/resume, counter wrap/latch,
real FIFO replies, overflow, observation bounds and IRQ14. Constructor controls
verify actual native activation; housekeeping controls verify delayed single
logging. These tests model time and VMCS and never execute Windows or a VM.

A separate deterministic 6000-operation default-profile transcript was generated
from the previous actual devices.c (SHA256
`08c9d1ed097edcae1384a9e732fd4dab760de8ff73a541f75da8f1da80beb16e`).
The candidate matches all 97,892 output bytes exactly:
`48b25118cd1fb0f0023aaa6fc3dd9090783ff9d478efae1b60383e6951425df1`.
It covers modeled PIC/PIT/KBC/A20/UART/VGA/CMOS/unknown port operations and timer/
IRQ sampling across three initializations. It verifies those default-profile
protocol cases, not every timing/CPU exception or a Windows boot.

Next acceptance requires a fresh source-bound producer, independent owned ESP and
firmware variables, and actual bounded cold native VM capture using the hardened
controller. Preserve the 17 GiB reserve and all prior receipts. Report actual
PIT/KBC traces, ScanDisk/Windows progression and every guest failure honestly.
