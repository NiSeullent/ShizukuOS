# Measured local PDH counters

This original GPL-2.0-only module implements owned live query/counter handles,
collection, removal, closing, raw CPU samples and numeric formatting for the actual
single-CPU `Processor(_Total)` / `Processor(0)` processor-time counter and
`System` uptime counter. The English catalog is deliberately small. Unsupported
remote, Hyper-V host, frequency, log-file and other providers fail explicitly.
These are not a whole PDH, multi-CPU or installed Windows98 acceptance claim.

The scheduler records real idle, kernel and user ticks. `GetSystemTimes` retrieves
an atomic snapshot through private information class `0x102`; kernel time
includes idle. Standard information class8 is unchanged: DPC/interrupt timing is
not advertised. PDH CPU utilization is the measured busy-time delta divided by
the measured total-time delta. A rate needs two samples and a positive interval;
an invalid interval is never reported as a fabricated percentage. Uptime raw
values fail explicitly because no elapsed-counter raw time base is provided.

Chromium running under KVM may select its Hyper-V provider first. That provider
is absent here and returns an explicit error; Chromium may leave compute
pressure unavailable. This is not evidence that Chromium sampled local CPU time.

The latest publisher Chromium157.0.8081.0 actually emits the fixture's JavaScript
DOM result, then fails delay-loading PDH. Its six required entry points are
present here. Its pinned source uses the processor-time counter, and can probe
the Hyper-V provider. The application must still be retried for normal exit.

Primary contract and source review:

- [Microsoft GetSystemTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getsystemtimes)
- [Microsoft collection and two-sample rate calculations](https://learn.microsoft.com/en-us/windows/win32/perfctrs/collecting-performance-data)
- [Microsoft counter status checking](https://learn.microsoft.com/en-us/windows/win32/perfctrs/checking-pdh-interface-return-values)
- [Pinned Chromium CPU probe](https://chromium.googlesource.com/chromium/src/+/fc75daa82260574dd02d7a1e66b58535389aca14/components/system_cpu/cpu_probe_win.cc)
- [Wine11 PDH review](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/pdh/pdh_main.c)

No upstream implementation is copied. Wine's fixed processor sample is
explicitly replaced by genuine scheduler accounting. Concurrent close/remove
uses owned opaque generation tokens, so stale or arbitrary handles are never
dereferenced or confused with a subsequent allocation.
