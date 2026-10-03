# Process-owned native installer transport

`NtShzSetupNative` (0xb5) is an additive syscall. It accepts exactly one 440-byte
`shz_native_call_v1`, with version 1, matching byte count and zero reserved fields.
It never consumes user process/device pointers, approved-role booleans or producer
hashes. The user buffers are VAs copied through the actual process address space;
source and claim handles are opaque monotonically minted integers, not pointers.
The 472-byte shared boot ABI prefix and `shz_abi.h` are unchanged.

| Operation | Actual authority |
| --- | --- |
| caps | actual transport bounds; independent producer admission availability |
| open/info/read/close | accepted loader archive membership + private PMM snapshot custody |
| review/claim | two independently admitted source snapshots + real block registry/roles/exclusive claim |
| check/read/write/flush/release | retained exact whole ID/generation; actual atomic block authority operation |

Source reads use byte offsets; target reads/writes use LBA offsets, byte lengths
that are a nonzero multiple of 512, and at most 64 KiB per request. Source read
lengths are nonzero and at most 64 KiB. Two sources per process and sixteen live
process ownership records are bounded. All operations serialize through one
service mutex; block authority performs its own atomic validation and backend IO.
Output-copy failure after minting a source or claim performs actual cleanup.

Process teardown releases a safely quiescent claim, closes owned source handles,
and lets retained claim references govern snapshot lifetime. A failed/poisoned
claim retains source pages and its kernel owner record until reboot. That owner
record is retired and cannot be inherited by a reused process pointer or PID.
There is no force-unclaim or unknown-backing exemption.

## Independent producer admission remains absent

Production `setup_native_release.c` deliberately provides no accepted release.
Caps reports zero; pair admission always fails before target claim or IO. Caller
receipt JSON, a caller SHA, RAM snapshot success, an original Microsoft DOS control
boot or a synthetic host fixture do not provide the missing authority. Actual
independently validated producer outputs under final-byte custody are required
before any future build-owned release records can authenticate both inputs.
Their constructor and source/tool closure must also enter the build receipts.

`native_payload_ingest.py` exports a 2304 MiB expanded ESP from actual pinned
private producer inputs. Its encoded `SHZSIMG1` file is exactly 64 header bytes,
16 bytes per run, and 4096 bytes per retained nonzero block. Encoded size is not
the expanded size and cannot be inferred from the original 2 GiB source disk.
No actual completed Windows98 producer/SIM is currently available. Current sealed
snapshot admission rejects individual files above 256 MiB; caps states that exact
limit. A larger genuine SIM needs separately reviewed retained immutable extent
or physical source custody, rather than silently raising a memory bound.

`win64/setup/native_syscall.c` reaches the generated ntdll syscall stub; the
build's export ordinals and transitive source receipt include the new ABI. This
transport is not yet the complete `native_setup_ops_v1` user backend. The actual
installer's native NULL backend is retained pending that connection and genuine
producer admission. No installed Windows98 or guest execution is claimed.

## Verification

```
python3 shizukudos/kernel64/host/test_setup_native_sys.py
NATIVE_HOST_COMPILER=/usr/bin/clang python3 shizukudos/kernel64/host/test_setup_native_sys.py
python3 shizukudos/kernel64/host/test_setup_native_abi.py
```

Tests compile the real service, archive parser/namespace/snapshot, registry,
partition routing and atomic block authority. User copy, PMM, IRQ, driver and
firmware are host models. Production-default tests prove absent admission denies
all target work. Explicitly labelled HOST-ONLY admission substitutes exercise
atomic claim/IO and poison retention; these are not native producer evidence.
