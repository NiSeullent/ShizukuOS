/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWST_NATIVE_RUNTIME_H
#define NTWST_NATIVE_RUNTIME_H
#ifdef __cplusplus
extern "C" {
#endif

/* Windows 98 ANSI CryptoAPI runtime; same serialization/ownership contract as
 * transport.h. Pair these calls; all connections must be destroyed before fini.
 * Never replace or release the CryptoAPI context while the engine is live. */
int ntwst_native_runtime_init(void);
int ntwst_native_runtime_fini(void);

#ifdef __cplusplus
}
#endif
#endif
