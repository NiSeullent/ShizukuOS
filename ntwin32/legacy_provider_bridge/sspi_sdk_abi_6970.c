/* SPDX-License-Identifier: GPL-2.0-only
 * Compile-only native x86 SDK oracle for NTWPROV's actual production TU.
 * A pointer-width, calling-convention or prefix-layout regression must fail
 * compilation. No Windows DLL, factory, credential or TLS operation is run.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#define SECURITY_WIN32 1

#if !defined(_WIN32) || !defined(__i386__)
#error "This oracle requires a real Windows i686 compiler and SDK"
#endif
#if defined(M98SSPI_HOST_TEST)
#error "Host SSPI shims are not native SDK evidence"
#endif

#include <windows.h>
#include <security.h>
#include <sspi.h>
#include <stddef.h>
#include <stdint.h>

/* Keep the entire production TU, including its actual init_sspi_fn typedef,
 * fixed-width prefix and provider selection/validation code. */
#include "native.c"

_Static_assert(sizeof(void *) == 4 && sizeof(UINT_PTR) == 4,
               "native i686 pointer ABI");
_Static_assert(sizeof(DWORD) == 4 && sizeof(ULONG) == 4 && sizeof(WCHAR) == 2,
               "Windows fixed-width ABI");
_Static_assert(sizeof(FARPROC) == 4 && sizeof(init_sspi_fn) == 4 &&
               sizeof(INIT_SECURITY_INTERFACE_A) == 4,
               "native callable pointers are 32-bit");
_Static_assert(__builtin_types_compatible_p(init_sspi_fn,
                                          INIT_SECURITY_INTERFACE_A),
               "production factory matches SDK typed WINAPI typedef");
_Static_assert(__builtin_types_compatible_p(init_sspi_fn,
                                          __typeof__(&InitSecurityInterfaceA)),
               "production factory matches actual SDK ANSI declaration");

_Static_assert(SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION == 1,
               "SDK original SSPI table version");
_Static_assert(offsetof(SecurityFunctionTableA, dwVersion) == 0 &&
               sizeof(((SecurityFunctionTableA *)0)->dwVersion) == 4 &&
               offsetof(ntwp_sspi32_prefix, version) == 0 &&
               sizeof(((ntwp_sspi32_prefix *)0)->version) == 4,
               "SDK and production version words");
_Static_assert(sizeof(ntwp_sspi32_prefix) == 108 &&
               sizeof(((ntwp_sspi32_prefix *)0)->slot) == 104 &&
               sizeof(SecurityFunctionTableA) >= 108,
               "only the original 26-slot prefix is consumed");
_Static_assert(sizeof(sspi_slots) / sizeof(sspi_slots[0]) == 13,
               "production profile has 13 populated prefix slots");

/* Literal offsets are derived from the real SDK ANSI table. Each assertion
 * binds its named SDK field to the word actually read by production. This
 * checks NULL/reserved fields too; it does not call or populate any slot.
 * The separate full-TU host fixture checks live values and NULL identities.
 */
#define SDK_SLOT(member, index, byte_offset) \
    _Static_assert(offsetof(SecurityFunctionTableA, member) == (byte_offset) && \
                   sizeof(((SecurityFunctionTableA *)0)->member) == 4 && \
                   offsetof(ntwp_sspi32_prefix, slot[index]) == (byte_offset), \
                   "SDK/production SSPI32 slot: " #member)

/* Existing profile values: 13 populated entries and 13 NULL entries. */
SDK_SLOT(EnumerateSecurityPackagesA, 0, 4);    /* Populated. */
SDK_SLOT(QueryCredentialsAttributesA, 1, 8);  /* NULL. */
SDK_SLOT(AcquireCredentialsHandleA, 2, 12);   /* Populated. */
SDK_SLOT(FreeCredentialHandle, 3, 16);        /* Populated. */
SDK_SLOT(Reserved2, 4, 20);                   /* NULL. */
SDK_SLOT(InitializeSecurityContextA, 5, 24);  /* Populated. */
SDK_SLOT(AcceptSecurityContext, 6, 28);       /* NULL. */
SDK_SLOT(CompleteAuthToken, 7, 32);           /* NULL. */
SDK_SLOT(DeleteSecurityContext, 8, 36);       /* Populated. */
SDK_SLOT(ApplyControlToken, 9, 40);           /* Populated. */
SDK_SLOT(QueryContextAttributesA, 10, 44);    /* Populated. */
SDK_SLOT(ImpersonateSecurityContext, 11, 48); /* NULL. */
SDK_SLOT(RevertSecurityContext, 12, 52);      /* NULL. */
SDK_SLOT(MakeSignature, 13, 56);              /* NULL. */
SDK_SLOT(VerifySignature, 14, 60);            /* NULL. */
SDK_SLOT(FreeContextBuffer, 15, 64);          /* Populated. */
SDK_SLOT(QuerySecurityPackageInfoA, 16, 68);  /* Populated. */
SDK_SLOT(Reserved3, 17, 72);                  /* NULL. */
SDK_SLOT(Reserved4, 18, 76);                  /* NULL. */
SDK_SLOT(ExportSecurityContext, 19, 80);     /* Explicit unsupported call. */
SDK_SLOT(ImportSecurityContextA, 20, 84);    /* Explicit unsupported call. */
SDK_SLOT(AddCredentialsA, 21, 88);           /* NULL. */
SDK_SLOT(Reserved8, 22, 92);                 /* NULL. */
SDK_SLOT(QuerySecurityContextToken, 23, 96); /* NULL. */
SDK_SLOT(EncryptMessage, 24, 100);           /* Populated. */
SDK_SLOT(DecryptMessage, 25, 104);           /* Populated. */
#undef SDK_SLOT

_Static_assert(offsetof(SecurityFunctionTableA, DecryptMessage) +
               sizeof(((SecurityFunctionTableA *)0)->DecryptMessage) == 108,
               "production prefix ends after DecryptMessage");
