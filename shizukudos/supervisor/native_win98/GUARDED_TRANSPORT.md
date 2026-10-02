# Guarded native transport

ShizukuDOS replaces MS-DOS beneath Windows 98. Kernel32 and Kernel64 are
backends for that system. These host changes prepare native boot transport;
they do not establish a Windows 98 boot result.

`PrivateListener.accept(..., guard=...)` and `HostGrant(..., guard=...)` require
the actual owner guard. The guard must preserve source, custody, resource and
cancellation checks. Readiness waits check it before and after each bounded
wait under the original deadline. An expired or refused accept closes only
the newly accepted peer and retains listener custody. A failed grant retains
policy and channel custody until the exact child is reaped.

`Client.call(..., pump=...)` and `ordinary(..., pump=...)` accept a local-only
pump. It must not issue another RPC or QMP operation. One timeout covers
sending and receiving; uncertain replies seal subsequent requests. Matched
consumed replies remain aligned for cleanup, and received descriptors close
on a later refusal. The existing guardian still owns child recovery.

The frozen custody module contains its readiness implementation, avoiding
a new runtime project import. This is an alternative to the separately
prepared helper-injected RPC proposal; adopt one coherent implementation.

Run from the repository with Python 3 on Linux:

```sh
python3 -B shizukudos/supervisor/native_win98/tests/test_native_epoch_guard_wiring.py -v
python3 -B shizukudos/supervisor/native_win98/tests/test_custody_rpc_pump.py -v
python3 -B shizukudos/supervisor/native_win98/tests/test_native_epoch_host.py -v
```

The three suites exercise 21 transport controls, 10 real credential-checked
RPC controls, and 36 existing host regressions. Hardware and QMP observations
in the host fixtures are modeled. Guardian admission, sole QMP ownership,
COM2/fw_cfg, observed ESP binding, resume and actual guest boot still need
the native boot owner's coherent runtime integration.
