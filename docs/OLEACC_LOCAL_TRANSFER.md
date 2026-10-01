# Actual local accessibility-object transfer

The Wine 11 standard window/client accessibility objects are retained. The
local `LresultFromObject`/`ObjectFromLresult` implementation now transfers an
owned, real COM reference through a process-bound token instead of requiring
the unavailable global-atom/shared-memory RPC provider. It does not encode an
interface pointer or fabricate an accessibility object.

Each token identifies the full 32-bit process ID and a monotonically increasing
24-bit sequence. Both the LRESULT sign bit and HRESULT bit 31 remain clear, so
existing WM_GETOBJECT callers accept successful tokens. Tokens are consumed
once. A failed IID query preserves the reference for a valid later query;
concurrent or recursive consumption of the same token is rejected. COM
callbacks run outside the token-table lock. At most 256 unconsumed references
are retained; allocation, pinning and exhaustion failures remain explicit.
The provider is pinned for the process lifetime to prevent token reuse after
FreeLibrary/reload. Cross-process transfer requires a real RPC implementation
and remains E_NOTIMPL.

The actual production bodies pass strict GCC and Clang ASan/UBSan checks for
reference ownership, all PID boundary bits, invalid inputs, HRESULT-safe
tokens, capacity/sequence bounds, reentry and eight concurrent consumers.
The complete changed Wine main object and actual OLEACC DLL link also pass
using the production flags and existing immutable inputs. The two guest
fixtures compile and link with a newly compiled production CRT. A preliminary
compile exposed Wine's `interface` macro; the final variable names avoid it.
These host and PE checks do not replace execution in the complete GOP VM.

`T_U_OLEACC` retains the real counted WM_GETOBJECT object and child checks.
Its old unsupported-standard-object expectations now check the genuine Wine
window/client objects. `T_OLEACC_LOCAL` retains the five Chromium delay-import
checks and adds real local token transfer, HWND readback and consumed-token
rejection. Neither fixture proves cross-process Chromium accessibility or a
working modern browser. ShizukuDOS remains the MS-DOS replacement foundation
for real Windows 98; these Kernel64 runtime checks are component evidence.

```sh
python3 -B tests/run_oleacc_transfer_host.py --repo "$PWD" --patch-stage "$PWD" --out build/oleacc-transfer-host
```

Use a new output directory. The runner applies the exact public patches to
pinned Wine blobs in that output and leaves the prepared upstream tree alone.
