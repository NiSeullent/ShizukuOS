/* SPDX-License-Identifier: GPL-2.0-only
 * shzwkcompat.dll: Win32 functions that the WebKit dependencies (and later the port) import but that the Shizuku
 * runtime DLLs do not export yet. The W3 toolchain links its import library (libshzwkcompat.a) before every system
 * import library, so these names bind here instead of failing the whole image at load time (c0000139).
 *
 * Every function first asks the real system DLL for the same export (GetProcAddress, cached) and forwards to it when
 * it exists, so a later kernel32/advapi32/ws2_32/iphlpapi export takes over without rebuilding anything. Only when the
 * export is missing does the fallback below run; each fallback is either a faithful implementation over functions the
 * runtime does export, or a documented failure with the Windows error code a caller must already handle.
 * The list is kept in docs/shizukudos10/reports/W3.md under "Needed from K4/K5".
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <string.h>

#define EXPORT __declspec(dllexport)

static FARPROC real(const char *dll, const char *name)
{
    HMODULE m = GetModuleHandleA(dll);
    if (!m) m = LoadLibraryA(dll);
    return m ? GetProcAddress(m, name) : NULL;
}

/* Forward to <dll>!<name> when it exists; cached per function. */
#define REAL(dll, name, type) \
    static type fn_; static int looked_; \
    if (!looked_) { fn_ = (type)(void (*)(void))real(dll, #name); looked_ = 1; } \
    if (fn_)

/* ------------------------------------------------------------------ kernel32 */
typedef BOOL (WINAPI *MoveFileExA_t)(LPCSTR, LPCSTR, DWORD);
EXPORT BOOL WINAPI MoveFileExA(LPCSTR from, LPCSTR to, DWORD flags)
{
    WCHAR wf[MAX_PATH], wt[MAX_PATH];
    REAL("kernel32.dll", MoveFileExA, MoveFileExA_t) return fn_(from, to, flags);
    if (!MultiByteToWideChar(CP_ACP, 0, from, -1, wf, MAX_PATH)) return FALSE;
    if (to && !MultiByteToWideChar(CP_ACP, 0, to, -1, wt, MAX_PATH)) return FALSE;
    return MoveFileExW(wf, to ? wt : NULL, flags);
}

typedef DWORD (WINAPI *GetVersion_t)(void);
typedef LONG (WINAPI *RtlGetVersion_t)(OSVERSIONINFOW *);
EXPORT DWORD WINAPI GetVersion(void)
{
    OSVERSIONINFOW v;
    REAL("kernel32.dll", GetVersion, GetVersion_t) return fn_();
    memset(&v, 0, sizeof v);
    v.dwOSVersionInfoSize = sizeof v;
    {
        RtlGetVersion_t rgv = (RtlGetVersion_t)(void (*)(void))real("ntdll.dll", "RtlGetVersion");
        if (!rgv || rgv(&v)) return 0;
    }
    /* Windows layout: build in the high word (bit 31 clear on NT), minor in bits 8..15, major in bits 0..7 */
    return (v.dwBuildNumber & 0x7fff) << 16 | (v.dwMinorVersion & 0xff) << 8 | (v.dwMajorVersion & 0xff);
}

/* ------------------------------------------------------------------ advapi32: legacy CryptoAPI over bcrypt */
struct shz_hash { DWORD magic; BCRYPT_ALG_HANDLE alg; BCRYPT_HASH_HANDLE h; DWORD len; BYTE digest[64]; BOOL done; };
#define SHZ_PROV ((HCRYPTPROV)0x5348505a)                       /* one pseudo provider: verify contexts only */

typedef BOOL (WINAPI *CryptAcquireContextA_t)(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD);
EXPORT BOOL WINAPI CryptAcquireContextA(HCRYPTPROV *prov, LPCSTR container, LPCSTR provider, DWORD type, DWORD flags)
{
    REAL("advapi32.dll", CryptAcquireContextA, CryptAcquireContextA_t) return fn_(prov, container, provider, type, flags);
    if (!prov) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!(flags & CRYPT_VERIFYCONTEXT) || container) { SetLastError((DWORD)NTE_BAD_KEYSET); return FALSE; }
    *prov = SHZ_PROV;
    return TRUE;
}

typedef BOOL (WINAPI *CryptAcquireContextW_t)(HCRYPTPROV *, LPCWSTR, LPCWSTR, DWORD, DWORD);
EXPORT BOOL WINAPI CryptAcquireContextW(HCRYPTPROV *prov, LPCWSTR container, LPCWSTR provider, DWORD type, DWORD flags)
{
    REAL("advapi32.dll", CryptAcquireContextW, CryptAcquireContextW_t) return fn_(prov, container, provider, type, flags);
    return CryptAcquireContextA(prov, container ? "" : NULL, NULL, type, flags);
}

typedef BOOL (WINAPI *CryptReleaseContext_t)(HCRYPTPROV, DWORD);
EXPORT BOOL WINAPI CryptReleaseContext(HCRYPTPROV prov, DWORD flags)
{
    REAL("advapi32.dll", CryptReleaseContext, CryptReleaseContext_t) return fn_(prov, flags);
    if (prov != SHZ_PROV) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return TRUE;
}

typedef BOOL (WINAPI *CryptGenRandom_t)(HCRYPTPROV, DWORD, BYTE *);
EXPORT BOOL WINAPI CryptGenRandom(HCRYPTPROV prov, DWORD len, BYTE *buf)
{
    REAL("advapi32.dll", CryptGenRandom, CryptGenRandom_t) return fn_(prov, len, buf);
    if (prov != SHZ_PROV) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

typedef BOOL (WINAPI *CryptCreateHash_t)(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH *);
EXPORT BOOL WINAPI CryptCreateHash(HCRYPTPROV prov, ALG_ID alg, HCRYPTKEY key, DWORD flags, HCRYPTHASH *out)
{
    const WCHAR *name;
    struct shz_hash *h;
    REAL("advapi32.dll", CryptCreateHash, CryptCreateHash_t) return fn_(prov, alg, key, flags, out);
    switch (alg) {
    case CALG_MD5: name = BCRYPT_MD5_ALGORITHM; break;
    case CALG_SHA1: name = BCRYPT_SHA1_ALGORITHM; break;
    case CALG_SHA_256: name = BCRYPT_SHA256_ALGORITHM; break;
    case CALG_SHA_384: name = BCRYPT_SHA384_ALGORITHM; break;
    case CALG_SHA_512: name = BCRYPT_SHA512_ALGORITHM; break;
    default: SetLastError((DWORD)NTE_BAD_ALGID); return FALSE;       /* e.g. CALG_MD4 (NTLM) */
    }
    if (prov != SHZ_PROV || key || !out) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    h = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *h);
    if (!h) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    h->magic = 0x48534853;
    if (BCryptOpenAlgorithmProvider(&h->alg, name, NULL, 0) || BCryptCreateHash(h->alg, &h->h, NULL, 0, NULL, 0, 0)) {
        if (h->alg) BCryptCloseAlgorithmProvider(h->alg, 0);
        HeapFree(GetProcessHeap(), 0, h);
        SetLastError((DWORD)NTE_BAD_ALGID);
        return FALSE;
    }
    {
        ULONG got = 0;
        DWORD len = 0;
        BCryptGetProperty(h->alg, BCRYPT_HASH_LENGTH, (PUCHAR)&len, sizeof len, &got, 0);
        h->len = len;
    }
    (void)flags;
    *out = (HCRYPTHASH)h;
    return TRUE;
}

static struct shz_hash *hash_of(HCRYPTHASH x)
{
    struct shz_hash *h = (struct shz_hash *)x;
    return (h && h->magic == 0x48534853) ? h : NULL;
}

typedef BOOL (WINAPI *CryptHashData_t)(HCRYPTHASH, const BYTE *, DWORD, DWORD);
EXPORT BOOL WINAPI CryptHashData(HCRYPTHASH x, const BYTE *data, DWORD len, DWORD flags)
{
    struct shz_hash *h;
    REAL("advapi32.dll", CryptHashData, CryptHashData_t) return fn_(x, data, len, flags);
    h = hash_of(x);
    if (!h || h->done) { SetLastError((DWORD)NTE_BAD_HASH_STATE); return FALSE; }
    (void)flags;
    return BCryptHashData(h->h, (PUCHAR)data, len, 0) == 0;
}

typedef BOOL (WINAPI *CryptGetHashParam_t)(HCRYPTHASH, DWORD, BYTE *, DWORD *, DWORD);
EXPORT BOOL WINAPI CryptGetHashParam(HCRYPTHASH x, DWORD param, BYTE *data, DWORD *len, DWORD flags)
{
    struct shz_hash *h;
    REAL("advapi32.dll", CryptGetHashParam, CryptGetHashParam_t) return fn_(x, param, data, len, flags);
    h = hash_of(x);
    (void)flags;
    if (!h || !len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (param == HP_HASHSIZE) {
        if (data && *len >= 4) memcpy(data, &h->len, 4);
        *len = 4;
        return TRUE;
    }
    if (param != HP_HASHVAL) { SetLastError((DWORD)NTE_BAD_TYPE); return FALSE; }
    if (!data) { *len = h->len; return TRUE; }
    if (*len < h->len) { *len = h->len; SetLastError(ERROR_MORE_DATA); return FALSE; }
    if (!h->done) {
        if (BCryptFinishHash(h->h, h->digest, h->len, 0)) { SetLastError((DWORD)NTE_BAD_HASH); return FALSE; }
        h->done = TRUE;
    }
    memcpy(data, h->digest, h->len);
    *len = h->len;
    return TRUE;
}

typedef BOOL (WINAPI *CryptDestroyHash_t)(HCRYPTHASH);
EXPORT BOOL WINAPI CryptDestroyHash(HCRYPTHASH x)
{
    struct shz_hash *h;
    REAL("advapi32.dll", CryptDestroyHash, CryptDestroyHash_t) return fn_(x);
    h = hash_of(x);
    if (!h) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    BCryptDestroyHash(h->h);
    BCryptCloseAlgorithmProvider(h->alg, 0);
    h->magic = 0;
    HeapFree(GetProcessHeap(), 0, h);
    return TRUE;
}

/* ------------------------------------------------------------------ advapi32: event log -> debug output */
#define SHZ_EVENTLOG ((HANDLE)0x534c4f47)

typedef HANDLE (WINAPI *RegisterEventSourceA_t)(LPCSTR, LPCSTR);
EXPORT HANDLE WINAPI RegisterEventSourceA(LPCSTR server, LPCSTR source)
{
    REAL("advapi32.dll", RegisterEventSourceA, RegisterEventSourceA_t) return fn_(server, source);
    return SHZ_EVENTLOG;
}

typedef HANDLE (WINAPI *RegisterEventSourceW_t)(LPCWSTR, LPCWSTR);
EXPORT HANDLE WINAPI RegisterEventSourceW(LPCWSTR server, LPCWSTR source)
{
    REAL("advapi32.dll", RegisterEventSourceW, RegisterEventSourceW_t) return fn_(server, source);
    return SHZ_EVENTLOG;
}

typedef BOOL (WINAPI *DeregisterEventSource_t)(HANDLE);
EXPORT BOOL WINAPI DeregisterEventSource(HANDLE h)
{
    REAL("advapi32.dll", DeregisterEventSource, DeregisterEventSource_t) return fn_(h);
    return h == SHZ_EVENTLOG;
}

typedef BOOL (WINAPI *ReportEventA_t)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCSTR *, LPVOID);
EXPORT BOOL WINAPI ReportEventA(HANDLE h, WORD type, WORD cat, DWORD id, PSID sid, WORD n, DWORD size, LPCSTR *strs,
                                LPVOID raw)
{
    REAL("advapi32.dll", ReportEventA, ReportEventA_t) return fn_(h, type, cat, id, sid, n, size, strs, raw);
    for (WORD i = 0; strs && i < n; ++i) { OutputDebugStringA(strs[i]); OutputDebugStringA("\n"); }
    return h == SHZ_EVENTLOG;
}

typedef BOOL (WINAPI *ReportEventW_t)(HANDLE, WORD, WORD, DWORD, PSID, WORD, DWORD, LPCWSTR *, LPVOID);
EXPORT BOOL WINAPI ReportEventW(HANDLE h, WORD type, WORD cat, DWORD id, PSID sid, WORD n, DWORD size, LPCWSTR *strs,
                                LPVOID raw)
{
    REAL("advapi32.dll", ReportEventW, ReportEventW_t) return fn_(h, type, cat, id, sid, n, size, strs, raw);
    for (WORD i = 0; strs && i < n; ++i) { OutputDebugStringW(strs[i]); OutputDebugStringW(L"\n"); }
    return h == SHZ_EVENTLOG;
}

/* ------------------------------------------------------------------ ws2_32 */
typedef struct hostent *(WSAAPI *gethostbyaddr_t)(const char *, int, int);
EXPORT struct hostent *WSAAPI gethostbyaddr(const char *addr, int len, int type)
{
    REAL("ws2_32.dll", gethostbyaddr, gethostbyaddr_t) return fn_(addr, len, type);
    WSASetLastError(WSANO_DATA);                                  /* no reverse lookups: as for an unknown address */
    return NULL;
}

typedef struct servent *(WSAAPI *getservbyname_t)(const char *, const char *);
EXPORT struct servent *WSAAPI getservbyname(const char *name, const char *proto)
{
    REAL("ws2_32.dll", getservbyname, getservbyname_t) return fn_(name, proto);
    WSASetLastError(WSANO_DATA);                                  /* no services database */
    return NULL;
}

typedef struct servent *(WSAAPI *getservbyport_t)(int, const char *);
EXPORT struct servent *WSAAPI getservbyport(int port, const char *proto)
{
    REAL("ws2_32.dll", getservbyport, getservbyport_t) return fn_(port, proto);
    WSASetLastError(WSANO_DATA);
    return NULL;
}

typedef SOCKET (WSAAPI *WSASocketA_t)(int, int, int, LPWSAPROTOCOL_INFOA, GROUP, DWORD);
EXPORT SOCKET WSAAPI WSASocketA(int af, int type, int proto, LPWSAPROTOCOL_INFOA info, GROUP g, DWORD flags)
{
    REAL("ws2_32.dll", WSASocketA, WSASocketA_t) return fn_(af, type, proto, info, g, flags);
    if (info) { WSASetLastError(WSAEINVAL); return INVALID_SOCKET; }  /* a protocol-info block needs the real one */
    return WSASocketW(af, type, proto, NULL, g, flags);
}

typedef INT (WSAAPI *WSAStringToAddressW_t)(LPWSTR, INT, LPWSAPROTOCOL_INFOW, LPSOCKADDR, LPINT);
EXPORT INT WSAAPI WSAStringToAddressW(LPWSTR str, INT af, LPWSAPROTOCOL_INFOW info, LPSOCKADDR out, LPINT outlen)
{
    REAL("ws2_32.dll", WSAStringToAddressW, WSAStringToAddressW_t) return fn_(str, af, info, out, outlen);
    (void)info;
    if (!str || !out || !outlen) { WSASetLastError(WSAEFAULT); return SOCKET_ERROR; }
    if (af == AF_INET) {                                          /* numeric addresses only, no port suffix */
        struct sockaddr_in a;
        if (*outlen < (INT)sizeof a) { *outlen = sizeof a; WSASetLastError(WSAEFAULT); return SOCKET_ERROR; }
        memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        if (InetPtonW(AF_INET, str, &a.sin_addr) != 1) { WSASetLastError(WSAEINVAL); return SOCKET_ERROR; }
        memcpy(out, &a, sizeof a);
        *outlen = sizeof a;
        return 0;
    }
    if (af == AF_INET6) {
        struct sockaddr_in6 a;
        if (*outlen < (INT)sizeof a) { *outlen = sizeof a; WSASetLastError(WSAEFAULT); return SOCKET_ERROR; }
        memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6;
        if (InetPtonW(AF_INET6, str, &a.sin6_addr) != 1) { WSASetLastError(WSAEINVAL); return SOCKET_ERROR; }
        memcpy(out, &a, sizeof a);
        *outlen = sizeof a;
        return 0;
    }
    WSASetLastError(WSAEINVAL);
    return SOCKET_ERROR;
}

/* ------------------------------------------------------------------ iphlpapi (not built by the Wine port) */
typedef ULONG (WINAPI *if_nametoindex_t)(PCSTR);
EXPORT ULONG WINAPI if_nametoindex(PCSTR name)
{
    REAL("iphlpapi.dll", if_nametoindex, if_nametoindex_t) return fn_(name);
    return 0;                                                     /* unknown interface name */
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r)
{
    (void)h; (void)reason; (void)r;
    return TRUE;
}
