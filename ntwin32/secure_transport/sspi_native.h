/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTWST_SSPI_NATIVE_H
#define NTWST_SSPI_NATIVE_H

/* This DLL is loaded explicitly by an application. It is not an installed
 * Schannel provider and must never replace an original system DLL. */
#if defined(M98SSPI_HOST_TEST)
#include "sspi_native_test_win32.h"
#else
#ifndef SECURITY_WIN32
#define SECURITY_WIN32 1
#endif
#include <windows.h>
#include <security.h>
#include <schannel.h>
#endif

#define M98SSPI_PACKAGE_A "M98TLS 1.3"
#define M98SSPI_PRIVATE_CRED_VERSION 0x4d393831UL
#define M98SSPI_MAX_CA (1UL << 20)
#define M98SSPI_MAX_CREDENTIALS 8u

/* Optional project-specific trust policy. It is deliberately distinct from
 * SCHANNEL_CRED.hRootStore (a server-side field). CA bytes are copied at acquire.
 * PEM includes the trailing NUL; DER does not. Flags and reserved must be zero.
 * NULL pAuthData, or supported SCHANNEL_CRED v4, snapshots the native ROOT store.
 * Native ROOT extraction is implemented, but Windows chain policy, revocation,
 * CTLs, disallowed stores, ALPN and client certificates are not implemented.
 * Requests for those options fail. Do not infer OS-wide provider readiness.
 */
typedef struct M98SSPI_PRIVATE_CRED {
    ULONG dwVersion;
    ULONG cbSize;
    const unsigned char *ca;
    ULONG cbCa;
    ULONG dwFlags;
    ULONG reserved;
} M98SSPI_PRIVATE_CRED;

/* SSPI has no transport-EOF parameter. An explicit-loading client MUST call
 * this extension on actual socket EOF, after consuming all buffered records.
 * It returns SEC_I_CONTEXT_EXPIRED only after authenticated close_notify;
 * unauthenticated EOF fails with SEC_E_ILLEGAL_MESSAGE, never clean closure.
 */
SECURITY_STATUS WINAPI M98SspiEndInput(PCtxtHandle context);

/* Own C-only PE entry, no NT static-TLS/constructor startup. All adapter and
 * linked PSA calls are serialized by one process-local critical section. */
BOOL WINAPI M98SspiDllMain(HINSTANCE instance, DWORD reason, LPVOID reserved);

#endif
