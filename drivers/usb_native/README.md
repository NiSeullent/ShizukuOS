# Windows 98 Shizuku's Second Edition — USB descriptor foundation

`ntwu_usb.c` is an original freestanding parser for complete USB device and
configuration descriptor buffers. This is preparation for a future xHCI device
path. It does not enumerate devices, submit control transfers, configure pipes,
drive USB classes, or provide a Windows 98 USB driver.

The caller supplies stable input bytes and separate, writable output storage.
Every failure leaves the entire output byte-for-byte unchanged. Successful
results contain fixed-size records and offsets into the original input, never
pointers obtained from device data. Input/output overlap and overflowing address
ranges are rejected. The implementation uses no allocation, libc, hardware I/O,
global mutable state, or external runtime functions. The configuration scratch
record occupies 1,688 bytes plus small local bookkeeping; callers must provide a
suitable stack and serialize access to their own buffers.

The explicit resource limits are 4,096 input bytes, 16 interface numbers,
32 alternate settings, 64 endpoints across all alternates, and 64 opaque records.
Exceeding a limit fails without publishing a partial configuration. Interface
numbers cover zero through the declared count minus one, every interface has
alternate zero, and each interface/alternate pair is unique. Each alternate's
endpoint count must match its declaration. Endpoint addresses cannot repeat in
one alternate or be owned by different interface numbers; alternates of the
same interface can reuse them.
Low-speed configurations permit at most two simultaneously selectable endpoints
beyond EP0, including combinations of alternate settings on different interfaces.

The power field is a declared maximum, bounded to the selected USB 2.0
500 mA envelope. The parser does not authorize that draw or verify port capacity,
configuration state, suspend current, or the device's actual power consumption.

The supported subset uses low, full, and high speed, device versions 1.00,
1.10, or 2.00, exact standard descriptor sizes, and single-transaction bulk or
interrupt endpoints. Packet sizes and interrupt intervals are checked for the
selected speed. EP0 is validated in the device descriptor; non-default control,
isochronous, additional-transaction, USB 3 companion, and SuperSpeed descriptors
are unsupported. High-speed alternate zero interrupt payloads above 64 bytes
are outside the selected USB 2.0 base-revision subset. Zero interrupt payload is
accepted as a descriptor fact, not an operational pipe claim.
Device class zero accepts only the registered class/subclass/protocol triple
00/00/00; other class values are preserved without claiming class validation.

Known records with extensions, nonzero reserved attributes, and unknown standard
descriptor types return `NTWU_UNSUPPORTED`. This is deliberately narrower than a
fully compatible USB host: USB 2.0 permits hosts to ignore certain reserved bits
and standard descriptor extensions. Unsupported is not a declaration that those
devices are universally invalid. Class-specific records (type at least 0x20,
apart from USB 3 companions) and IAD type 11 are retained only as bounded opaque
offsets. Their contents, class relationships, and string indices are not
semantically validated. Opaque preceding indices describe syntax; the preceding
endpoint resets on each interface descriptor. No class-driver support is implied.

Run from the repository root:

```sh
python3 drivers/usb_native/test.py
```

This uses installed GCC, Clang, and `nm`; it writes only `drivers/usb_native/build/`
and launches bounded host test executables. It makes no network requests, USB
accesses, VM launches, service changes, or dependency installations. The receipt
`build/test-result.json` records source hashes, compiler versions, test counters,
sanitizer results, and the independent i486 object hashes. Both freestanding
objects must have zero undefined symbols. The host tests use exact-size buffers,
transactional failure sentinels, independent output invariants, truncations,
cross-interface endpoint collisions, and deterministic input mutations.

The ABI is declared in `ntwu_usb.h`. Diagnostics contain a status and byte offset;
an offset may equal the supplied length when the missing record is at the end.
`NTWU_LIMIT`, `NTWU_UNSUPPORTED`, and malformed-input statuses are distinct, but
when an input violates multiple rules the first reported rule is not a stable
diagnostic-priority contract. Neither parser binds a configuration to a prior
device result: the caller must provide the same observed speed and later check
configuration selection against the device's advertised configurations.

Source provenance: all C, tests, and build logic were independently written for
this project. Only format and protocol facts were consulted from the USB-IF's
*Universal Serial Bus Specification*, revision 2.0, April 27, 2000, sections
5.3.1.2, 5.5.3, 5.7.3, 5.8.3, 7.2.1, 9.5, and 9.6.1–9.6.6. The
[USB-IF specification library](https://www.usb.org/document-library/usb-20-specification)
is the official publication entry; the original primary PDF was read through its
[Bitsavers mirror](https://bitsavers.trailing-edge.com/components/usb/USB_2.0_2000.pdf).
The class-zero triple follows the USB-IF's
[Defined Class Codes registry](https://www.usb.org/defined-class-codes), page dated
September 22, 2023, consulted September 27, 2026.
No USB stack, kernel, SDK, firmware implementation, or external source code was
copied. Later ECNs and USB 3 descriptor semantics are not claimed as implemented.
