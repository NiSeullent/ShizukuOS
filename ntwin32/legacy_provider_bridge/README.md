# Native provider-table bridge

NTWPROV.DLL lets a native Windows98 loader use five source-built project API
providers through their published 32-bit get_api_table ABI. The adapter loads
only explicit M98WRAP/M98SHELL/M98AD2/M98USR1/M98CTL3 files from the caller's
absolute private directory. It does not install KernelEx core or change routes,
registry keys, or application bytes. KernelEx installation is a separate trial.

Before returning any address it validates the complete sorted name/ordinal
table, its zero terminator, every readable string and every executable function
inside the actual loaded DLL's PE sections. Missing functions remain missing;
table presence is not API behavior or application execution proof. It never
returns unsupported modules or arbitrary native stubs as implementations.

The caller owns a context and must keep it alive until all returned pointers
and threads stop using it. This includes threads started by a provider. Joining
and callback teardown are prerequisites to closing the context. Missing or
malformed providers return an actual loader/validation error. GDI's preserved
provider requires a specific KernelEx MSIMG32 backend and is deliberately not
part of this independent adapter. Native Unicode/runtime/TLS and the full app
dependency closure remain separate requirements.

Build and host/parser tests do not establish native load or latest-app success.
The bridge is a new extension stage, not a complete Windows API implementation.
