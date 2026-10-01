# Additive Automation DECIMAL family

This batch adds 26 DECIMAL entry points and `VarUI4FromStr` to the existing
`oleaut32.dll`. It preserves `bstr.c`, `variant.c`, and `safearray.c`. The explicit
27 ordinals follow Wine's pinned `oleaut32.spec`; the module also depends on the
real `ucrtbase.dll` for floating point and UTF-16 helpers.

The selected arithmetic, binary floating point, and number-parser bodies come
from Wine commit `db11d0fe6a169c457e23d007e20404643d067aa8` (Wine 11.0):

- [vartype.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/oleaut32/vartype.c)
- [variant.c](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/oleaut32/variant.c)
- [variant.h](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/oleaut32/variant.h)
- [native reference tests](https://gitlab.winehq.org/wine/wine/-/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/oleaut32/tests/vartype.c)

The imported source is Copyright 2003 Jon Griffiths, under GNU LGPL version 2.1
or later. Each copied file retains its upstream license notice; see the
[complete LGPL 2.1 text](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html).
The host and native fixtures are new GPL-2.0-only code. Per-function original
line ranges and exact pinned source hashes are recorded by the build evidence.

The public wrappers validate pointers, scale (0 through 28), and sign bits,
snapshot an input before writing an aliased output, and publish temporary values
only on success. The selected internal parser functions have private names and
are not exports of general VARIANT conversion APIs. Existing general VARIANT
coercion behavior is preserved.

Small, source-backed corrections are applied to the upstream bodies:

- Signed minimum magnitudes use unsigned subtraction rather than undefined
  signed negation.
- Integer conversion divides the original 96-bit magnitude by powers of ten
  and rounds halfway to even. It preserves values beyond the exact range of
  `double`, accepts signed `-2^63`, and checks unsigned range after rounding.
- Rounding carries are widened before adding one to a 32-bit limb.
- Scale alignment uses an immutable per-call decimal multiplier, removing the
  upstream shared write during concurrent addition and subtraction.
- Exponent scanning consumes all digits and saturates beyond the representable
  range, avoiding signed arithmetic overflow. The DECIMAL output path retains
  significant and discarded digits, chooses a representable 96-bit scale, and
  rounds halfway to even; scale cannot wrap in a byte or exceed 28.
- Failed locale lookup and number formatting return their actual HRESULT error.
  They never turn missing metadata into a default-success string. BSTR
  allocation failure returns `E_OUTOFMEMORY` with a null BSTR result.

The actual NLS provider supplies English, invariant, and default locale
metadata. Unsupported locales, including Korean in the current provider, fail
honestly; this batch adds no locale table or OS service. BSTR allocation and
release use the existing real process-heap implementation. Binary NaN retains
the selected Wine `DISP_E_BADVARTYPE` behavior, infinity returns overflow.

[Microsoft's DECIMAL layout](https://learn.microsoft.com/en-us/windows/win32/api/wtypes/ns-wtypes-decimal-r1)
defines its 96-bit magnitude, sign, and scale. The corresponding API contracts
include [VarDecFromStr](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-vardecfromstr),
[VarI8FromDec](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-vari8fromdec),
[VarBstrFromDec](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-varbstrfromdec), and
[VarUI4FromStr](https://learn.microsoft.com/en-us/windows/win32/api/oleauto/nf-oleauto-varui4fromstr).

Run `python3 shizukudos/win64/tests/test_decimal_host.py --output-dir <owned-output>`
for the host contract. It compiles exact copied production sources with GCC and
Clang ASan/UBSan. Expected integer and arithmetic values come from Python's
independent `Fraction` arithmetic; rounding comes from `round(Fraction)`, not
from these C bodies. The vectors cover signed/unsigned limits, precision beyond
`2^53`, 96-bit limb carries, exact divisions, 28-place string rounding, very
long exponents, aliases, invalid values, NLS/format failures, BSTR ownership and
allocation failure, and two real pthreads synchronized before mismatched-scale
addition and subtraction in both operand orders. Host NLS/BSTR adapters are explicitly
test adapters and are not native backend evidence.

`t_decimal.c` uses actual DLL imports and independently checks all 27 named and
ordinal addresses, each new conversion, arithmetic, provider failures, real NLS
formatting, BSTR lengths/freeing, and two real kernel threads. Its native compile
and complete static import closure are separate claims from running it. Only
the integration owner executes guest fixtures and Office. Neither these host
checks nor a static PE import closure establish that full Office runs.
