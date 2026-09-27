# Original InitOnce implementation

`initonce.h` and `initonce.c` implement the four one-time-initialization
operations for NTWin32Wrapper9x. They were independently authored for
**Windows 98 Shizuku's Second Edition**, under GPL-2.0-only. No KernelEx,
Wine, ReactOS, Microsoft implementation, or other third-party implementation
was copied, translated, or linked. The host test is also original.

The reference contracts are Microsoft's
[BeginInitialize](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initoncebegininitialize),
[Complete](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initoncecomplete),
[ExecuteOnce](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initonceexecuteonce),
[Initialize](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-initonceinitialize),
and [callback](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nc-synchapi-pinit_once_fn)
documentation, read on 2026-09-27. Microsoft's
[asynchronous example](https://learn.microsoft.com/en-us/windows/win32/sync/using-one-time-initialization)
also establishes that losing attempts retrieve the winning context using
CHECK_ONLY and release their own candidates.

## Representation and completion

`ntw_once` occupies exactly one naturally aligned `uintptr_t`. All-zero storage
is the static initializer. The internal low two bits encode empty, synchronous
initialization, asynchronous initialization, or completion; completed storage
contains the caller's context. A context may be NULL or an opaque value with
its low two bits clear. It need not point to readable memory.

The implementation uses original acquire/release atomic operations. A completed
begin observes writes published by the initializer. A failed synchronous
attempt resets the state so another waiting caller can retry. Synchronous
initializers execute serially; asynchronous callers may compute candidates
concurrently, but exactly one successful completion publishes its context.
Losing asynchronous completion returns an error without changing the winner.

There is no allocation, global object registry, CRT dependency, KernelEx hook,
or imported function. Synchronous waiters invoke the supplied yield callback;
the Win32 adapter may use native `Sleep(0)`. This is a yielding wait, without
FIFO ordering, kernel wait objects, or a fairness guarantee. Recursive
synchronous initialization of the same object waits on itself; it is not
reported as successful initialization. CHECK_ONLY is safe inside an initializer.

## Portable API and adapter contract

| Operation | Behavior |
| --- | --- |
| `ntw_once_init` | Reset exclusively owned storage to zero |
| `ntw_once_begin` | On success, `pending=1` permits initialization; `pending=0` retrieves a completed context |
| `ntw_once_complete` | Publish a context, or reset a failed synchronous attempt |
| `ntw_once_execute` | Invoke one synchronous callback at a time; failed callbacks permit retry |

CHECK_ONLY never starts initialization or waits; incomplete objects return
`NTW_ONCE_NOT_READY`. Failed begin calls leave both output locations untouched.
A successful pending begin leaves the context output untouched. A successful
completed begin writes the stored context when an output pointer was supplied.
The Win32 documentation does not promise output contents after failure; these
preservation rules are explicit project behavior rather than native-conformance
evidence.

Begin accepts flags zero, CHECK_ONLY, or ASYNC. Complete accepts zero, ASYNC,
or INIT_FAILED. Other bits and incompatible combinations are rejected.
INIT_FAILED requires a NULL context and cannot cancel asynchronous attempts;
an asynchronous caller abandons its own candidate. Pending synchronous and
asynchronous modes cannot be mixed. Once completed, the published result may
be retrieved in either mode or using CHECK_ONLY.

The callback type in `initonce.h` uses the native C calling convention. The
32-bit Win32 adapter must use a thunk to call a `WINAPI` callback; casting
between calling conventions is unsafe. Parameter and object pointers are
forwarded. This backend forwards its context argument directly, including
NULL. A supplied context location must be assigned an aligned value or NULL
before the callback returns success. Microsoft marks both the callback context
and outer context optional, but the consulted primary documents do not specify
pointer identity or whether Windows substitutes temporary storage when the
outer context is NULL. Exact native behavior of that edge remains unverified;
the host test verifies this backend's forwarding choice.

| Backend status | Proposed Win32 adapter result |
| --- | --- |
| `NTW_ONCE_OK` | TRUE |
| `NTW_ONCE_NOT_READY` | FALSE, `ERROR_GEN_FAILURE` |
| `NTW_ONCE_INVALID` | FALSE, `ERROR_INVALID_PARAMETER` |
| `NTW_ONCE_CONFLICT` | FALSE, `ERROR_GEN_FAILURE` |
| `NTW_ONCE_CALLBACK_FAILED` | FALSE; preserve the callback's last error |

These numeric last-error mappings are project policy and have not been
differentially verified on native Windows. The backend makes no system calls
after a failing callback, so the adapter can preserve its last error.

## Invalid use and limits

The object must not be copied, moved, reinitialized while live, or shared
between processes. Initialization/reset requires exclusive ownership. A
synchronous owner must eventually complete or explicitly fail its attempt;
there is no abandoned-thread recovery. Callers own all contexts, their cleanup,
and their lifetimes. Output storage must be valid and must not alias the object.
The backend cannot validate arbitrary pointers, detect thread ownership, or
recover from callback exceptions, thread exit, or a nonlocal jump.

NULL/misaligned object addresses, unsupported flags, and misaligned context
values return explicit errors before mutation. An invalid successful callback
context is rejected and resets the attempt so waiters can retry. This recovery
is project policy, not a claim about Windows structured-exception behavior.
The backend does not raise or translate SEH exceptions; invalid-input behavior
and exact flags/error-code equivalence require later Windows reference tests.
There is no claim of complete native equivalence or new Win98 guest evidence
from this host implementation alone.

## Reproducible validation

From the repository root, all outputs remain under ignored `ntwin32/build/`:

```sh
mkdir -p ntwin32/build
clang -std=c11 -O2 -g -Wall -Wextra -Werror -Wpedantic -Wconversion \
  -Wsign-conversion -Wshadow -Wstrict-prototypes -pthread \
  ntwin32/initonce.c ntwin32/tests/initonce_test.c -o ntwin32/build/initonce_test
ntwin32/build/initonce_test
clang -std=c11 -O1 -g -Wall -Wextra -Werror -Wpedantic -Wconversion \
  -Wsign-conversion -Wshadow -Wstrict-prototypes -pthread \
  -fsanitize=address,undefined -fno-omit-frame-pointer \
  ntwin32/initonce.c ntwin32/tests/initonce_test.c -o ntwin32/build/initonce_test_sanitize
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 UBSAN_OPTIONS=halt_on_error=1 \
  ntwin32/build/initonce_test_sanitize
clang --target=i486-none-elf -std=c11 -O2 -ffreestanding -fno-builtin \
  -fno-stack-protector -Wall -Wextra -Werror -Wpedantic \
  -c ntwin32/initonce.c -o ntwin32/build/initonce-i486.o
nm -u ntwin32/build/initonce-i486.o
```

The 2026-09-27 strict and ASan/UBSan runs each pass **11,691 assertions**,
including **72 eight-thread contention rounds**. Tests cover release/acquire
publication of ordinary memory, exactly one successful callback, three failed
attempts followed by concurrent retry, asynchronous competing contexts and
loser cleanup, blocking begin/retry, CHECK_ONLY and output preservation,
alignment/flags errors, pointer-width preservation, optional context handling,
and bounded reentry observation without hanging the process. A watchdog fails
the test if wait progress breaks. ASan/UBSan do not themselves prove absence
of every data race. The i486 compile-only object has no undefined symbols;
that check establishes neither a Windows ABI call nor guest execution.
