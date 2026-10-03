# Windows98 native HID pointer bridge

The production Supervisor now links the existing portable HID-over-I2C driver,
the shared HID pointer adapter and an i8042 auxiliary endpoint. Actual Windows98
retains its own PS/2 mouse driver, VMM/USER/GDI and Explorer. This connection does
not install a replacement desktop, add a second NT kernel or migrate VMM/Win16
work onto PMA workers.

The trusted serialized native resource manager calls `w98_pointer_bind_i2c`
only after the real `shz_hidi2c_open` has enumerated a verified I2C/GPIO transport.
The binding snapshots owner/generation/address and checks that immutable lease
and READY state before polling and before guest publication/read. The scheduler
calls one bounded production input read from `dev_poll`; it never runs I2C in a
guest port or interrupt callback. Source calibration is explicit descriptor
units per default PS/2-resolution count (4/mm), rather than guessed physical
units. The shared `shz_pointer_adapter` interface also serves native NTDRV class
consumers, preserving one descriptor parser and one contact conversion path.

Until a real source is attached, interface test A9 returns failure and D4 mouse
commands have no reply. After attachment the virtual endpoint supplies standard
ID0 three-byte packets, reset/BAT, reporting enable/disable, sample rate,
resolution,1:1/2:1 scaling, stream/remote mode, status/read-data, wrap and resend.
Unsupported commands return RESEND. Reset/BAT proves this virtual endpoint's
state, not physical hardware reset or a functioning laptop controller. Auxiliary
bytes have status bit5 and use IRQ12/slave cascade; keyboard replies retain
IRQ1. FIFO reservations are atomic across whole packets and command responses.
Large motions remain queued and split into representable signed packets. HID
positive-down Y is inverted for the PS/2 positive-up convention.

Absolute single-contact frames establish a baseline on contact changes/lift;
multitouch gestures, wheels and buttons above three remain unsupported. Source
lease revocation removes queued AUX bytes, retains exact wrapped keyboard FIFO
contents and stops admission. Explicit detach is still required before another
source may attach. The driver never frees, recycles or resets the retained
source, bus callback context or DMA backing. The transport owner separately
calls its real stop/drain path. No force flag bypasses it.

Verification:

```sh
python3 -m unittest shizukudos/supervisor/native_win98/tests/test_pointer_bridge.py
python3 -m unittest shizukudos/supervisor/native_win98/tests/test_native_devices.py
python3 drivers/shz_laptop/test.py --build-dir /absolute/owned-driver-output
python3 shizukudos/supervisor/native_win98/compile.py --out /absolute/new-component-output
```

The bridge test executes real `shz_hidi2c_open/input`, HID descriptor parsing,
shared conversion, source binding and actual Supervisor device/PIC bodies under
GCC and Clang ASan/UBSan; I2C/GPIO, time and privileged hardware boundaries are
modeled. Existing native device tests preserve the exact6000-operation default
profile transcript. Component builds bind source hashes, including the shared
driver sources and headers outside the Supervisor directory.

**Remaining acceptance gate:** no native ACPI namespace enumerator/OEM I2C/GPIO
resource provider is wired to this bind function on a live laptop. No actual
Windows98 VM or physical input device was exercised by these host tests.
Completion requires that real provider, actual source-custodied Win98 boot,
PS/2 mouse-driver enumeration and USER/Explorer pointer/button operation;
source-owner stop/revoke/rebind and suspend/resume must then pass in that same
runtime. An original-DOS Win98 control remains distinct from ShizukuDOS DOS
replacement. Do not classify the compile or modeled protocol tests as either.

The independently written standard PS/2 command/packet behavior follows the
[Infineon/Cypress PS2D device datasheet, mouse command table4](https://www.infineon.com/assets/row/public/documents/30/396/infineon-ps2d-001-13681-software-module-datasheets-en.pdf).
