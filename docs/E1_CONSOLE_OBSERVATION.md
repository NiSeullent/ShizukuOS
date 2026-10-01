# Observe console cells before writing diagnostics

The GOP VM's `T_E1_KERNEL32` reported a failure when testing whether an
attribute fill preserves the character at the final console cell. The preceding
successful assertion printed a diagnostic through the same console. That
print scrolled the screen and replaced the cell before the second operation.

The fixture now saves the first result and observes the second operation before
printing either assertion. Both original conditions and diagnostics remain.
The production console implementation and the check macro are unchanged.

Run the bounded host control with a fresh output directory:

```sh
python3 -B tools/verify_e1_console_logging.py --repo . --out build/e1-console-host
```

The control extracts the actual production cell functions, the two original
guest assertions, and the actual check macro. GCC and Clang with address and
undefined-behavior sanitizers each verify three cases: the original logging
interference fails once, the captured observations pass, and an actual
attribute-fill mutation that corrupts the character still fails once.
The shim supplies one owned handle, host lock boundaries, and ASCII diagnostic
conversion. These controls do not execute a VM or establish Windows 98 support.

The corrected guest source also compiled and linked as an AMD64 PE against the
actual production CRT, DLL import libraries, and version resource. This is a
build check; the full GOP guest suite must be rebuilt and rerun before claiming
that its earlier failure is fixed in a VM. Preserve that earlier VM result.
