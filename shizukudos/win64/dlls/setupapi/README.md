# Registered-device SetupAPI provider

This original module supplies the ten SetupAPI delay imports observed in
the actual Chromium 157.0.8081.0 publisher `chrome.dll`. It implements owned
information sets, device/interface enumeration and opening, interface-detail
and device-property retrieval, and device registry-key opening. It reads the
kernel's actual registered PDO/interface graph through private query class
`0x103`; the version-1 wire header is 16 bytes and each row is 1424 bytes.
Snapshots are validated for exact returned byte counts, row type and bounded
count, terminated fields, node identity and interface-to-node association.
The query is bounded to 1024 rows and retries actual snapshot-size changes.

The graph contains PDOs registered by the native driver/PnP subsystem and
their actually registered interfaces. It excludes PCI functions without a
registered devnode, USB devices without a provider, and remembered devices
which were removed. `DIGCF_ALLCLASSES` enumerates this bounded registered
graph; it is not a complete machine hardware inventory. A registered PDO
can be physically present before its function driver starts. Interface
`DIGCF_PRESENT` queries select enabled interfaces. Class/interface GUID,
enumerator-name and instance-ID filters use actual row metadata. Default
interface selection, hardware profiles, enumerator-GUID lookup, root-node
opening, driver-list inheritance and pending-remove cancellation are
unavailable and fail explicitly. Unknown flags are rejected.

HDEVINFO handles and per-set Reserved values are monotonically generated
opaque tokens protected by one mutex. Callers cannot make a private object
pointer into a handle, mix device/interface records from another set, or
reuse a destroyed set. Destroying a set releases all its owned items.
Opening actual nodes/interfaces adds or refreshes the corresponding items.
Caller output-size errors retain the documented opening side effect.
Existing sets enumerate their collected snapshot; detail, property and
registry-key operations query the live catalog again and reject identities
which no longer exist. There is no hotplug notification implementation.

Interface detail copies the actual registered symbolic-link identity. The
`\??\` NT prefix is converted to `\\?\` for Win32 callers; no device path is
invented. Kernel interface registration currently does not publish a usable
namespace link for CreateFile. Successful detail enumeration therefore does
not establish device-path opening, transfers, USB support or a working
hardware provider. This remains a separate integration boundary.

Actual description, manufacturer, driver key, ASCII service converted to
UTF-16, instance ID and class GUID properties come from registered metadata.
Hardware/compatible IDs, class name and friendly name are read from the real
device Enum registry key when set. Missing metadata is `ERROR_NOT_FOUND`;
registry string values are staged and their actual second-query type, even
UTF-16 length, terminators and list structure are validated before publishing
a typed property, including when the value changed during size negotiation.
an absent/malformed class GUID never becomes a successful zero GUID property.
SP_DEVINFO_DATA uses GUID_NULL to denote no associated setup class and DevInst
is the real private catalog node identifier, not a full CfgMgr32 provider.
Unsupported or unset property keys fail. Hardware and driver registry keys
are opened using the actual advapi32 registry API with caller access rights;
missing keys and denied rights propagate and no key is created. The caller
owns the returned registry handle and must close it.

The API behavior and AMD64 structure sizes follow Microsoft's contracts:
[device sets and filters](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw),
[interface enumeration](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinterfaces),
[two-step detail retrieval](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw),
[opening device information](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendeviceinfow),
[opening interfaces](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendeviceinterfacew),
[property types and errors](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdevicepropertyw),
and [real registry-key handles](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey).
No upstream implementation or binary is copied into this source.

`test_setupapi_catalog_host.c` injects explicitly hosted populated/disabled/
removed/invalid catalog snapshots and a hosted registry dependency; it checks
real module lifecycle, filtering, exact UTF-16 sizing, stale/cross-set tokens,
buffer bounds, missing metadata and provider failures under sanitizers and
concurrent set lifecycles. Hosted rows are test input, never guest hardware
or product acceptance evidence. `t_setupapi_catalog.c` instead queries the
actual guest kernel independently, compares enumerated devnode/interface
identities and counts, retrieves real properties and registry handles, and
reports the genuine no-interface case when that is the actual kernel graph.
Host tests, native compilation, guest execution, Chromium/Legcord rendering
and native Windows 98 integration are separate evidence levels.
