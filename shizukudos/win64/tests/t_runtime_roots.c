/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated OS trust-store initialization from an immutable public CA bundle.
 * Certificates retain ordinary CryptoAPI verification; no TLS error is hidden.
 * The --steam profile then starts the unchanged publisher client and observes
 * its actual process. The plain profile checks the captured public TLS chain.
 */
#include "k32test.h"
#include <wincrypt.h>

static BYTE *read_file(LPCWSTR path, DWORD *bytes)
{
    HANDLE file;
    BYTE *data;
    DWORD size, read;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return NULL;
    size = GetFileSize(file, NULL);
    if (!size || size > 4u * 1024u * 1024u) { CloseHandle(file); return NULL; }
    data = HeapAlloc(GetProcessHeap(), 0, size);
    if (!data || !ReadFile(file, data, size, &read, NULL) || read != size) {
        if (data) HeapFree(GetProcessHeap(), 0, data);
        CloseHandle(file); return NULL;
    }
    if (!CloseHandle(file)) { HeapFree(GetProcessHeap(), 0, data); return NULL; }
    *bytes = size;
    return data;
}
static DWORD word(const BYTE *p)
{
    return (DWORD)p[0] | (DWORD)p[1] << 8 | (DWORD)p[2] << 16 | (DWORD)p[3] << 24;
}
static int initialize_roots(void)
{
    BYTE *data;
    PCCERT_CONTEXT certificates[512] = {0}, found;
    HCERTSTORE store = NULL;
    DWORD bytes = 0, count = 0, offset = 16, i, added = 0;
    int success = 0;
    data = read_file(L"C:\\SHZ\\CERTS\\ROOTS.BIN", &bytes);
    if (!data) { printf("Public root bundle read failed: %lu\n", (unsigned long)GetLastError()); return 0; }
    if (bytes < 16 || memcmp(data, "SHZCA001", 8) || word(data + 8) != 1 ||
        !(count = word(data + 12)) || count > 512) goto done;
    /* Parse the complete input before changing this disposable guest's store. */
    for (i = 0; i < count; ++i) {
        DWORD size;
        if (offset > bytes || bytes - offset < 4) goto done;
        size = word(data + offset); offset += 4;
        if (!size || size > 65536 || size > bytes - offset) goto done;
        certificates[i] = CertCreateCertificateContext(X509_ASN_ENCODING, data + offset, size);
        if (!certificates[i]) goto done;
        offset += size;
    }
    if (offset != bytes) goto done;
    store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"ROOT");
    if (!store) goto done;
    for (i = 0; i < count; ++i) {
        if (!CertAddCertificateContextToStore(store, certificates[i], CERT_STORE_ADD_REPLACE_EXISTING, NULL)) goto done;
        found = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_EXISTING, certificates[i], NULL);
        if (!found) goto done;
        {
            BOOL identical = found->cbCertEncoded == certificates[i]->cbCertEncoded &&
                             !memcmp(found->pbCertEncoded, certificates[i]->pbCertEncoded, found->cbCertEncoded);
            CertFreeCertificateContext(found);
            if (!identical) goto done;
        }
        ++added;
    }
    success = 1;
done:
    if (store && !CertCloseStore(store, 0)) success = 0;
    for (i = 0; i < count && i < 512; ++i) if (certificates[i]) CertFreeCertificateContext(certificates[i]);
    HeapFree(GetProcessHeap(), 0, data);
    printf("Isolated public trust-store initialization: %lu/%lu actual certificates, result %d\n",
           (unsigned long)added, (unsigned long)count, success);
    return success;
}
static PCCERT_CHAIN_CONTEXT chain(HCERTSTORE extra, PCCERT_CONTEXT leaf, FILETIME *time)
{
    CERT_CHAIN_PARA parameters;
    PCCERT_CHAIN_CONTEXT context = NULL;
    memset(&parameters, 0, sizeof parameters); parameters.cbSize = sizeof parameters;
    if (!CertGetCertificateChain(HCCE_LOCAL_MACHINE, leaf, time, extra, &parameters,
                                 CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &context)) return NULL;
    return context;
}
static DWORD ssl_policy(PCCERT_CHAIN_CONTEXT context, LPCWSTR name)
{
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl;
    CERT_CHAIN_POLICY_PARA parameters;
    CERT_CHAIN_POLICY_STATUS status;
    memset(&ssl, 0, sizeof ssl); ssl.cbSize = sizeof ssl; ssl.dwAuthType = AUTHTYPE_SERVER;
    ssl.pwszServerName = (LPWSTR)name;
    memset(&parameters, 0, sizeof parameters); parameters.cbSize = sizeof parameters;
    parameters.pvExtraPolicyPara = &ssl;
    memset(&status, 0, sizeof status); status.cbSize = sizeof status;
    return CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, context, &parameters, &status)
           ? status.dwError : GetLastError();
}
static int verify_chain(void)
{
    BYTE *der[3] = {0};
    DWORD sizes[3] = {0}, i;
    HCERTSTORE extra = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    PCCERT_CONTEXT certs[3] = {0}, bad = NULL;
    PCCERT_CHAIN_CONTEXT context;
    FILETIME future;
    SYSTEMTIME date;
    CHECK(extra != NULL, "real independent memory store for captured server intermediates");
    if (!extra) return 1;
    for (i = 0; i < 3; ++i) {
        WCHAR path[] = L"C:\\SHZ\\CERTS\\SERVER0.CER";
        path[19] = (WCHAR)('0' + i);
        der[i] = read_file(path, &sizes[i]);
        certs[i] = der[i] ? CertCreateCertificateContext(X509_ASN_ENCODING, der[i], sizes[i]) : NULL;
        CHECK(certs[i] != NULL, "actual captured public server DER certificate decodes");
        if (!certs[i]) goto done;
        if (i) CHECK(CertAddCertificateContextToStore(extra, certs[i], CERT_STORE_ADD_ALWAYS, NULL),
                     "actual supplied intermediate is added only to untrusted supporting store");
    }
    context = chain(extra, certs[0], NULL);
    CHECK(context != NULL, "actual machine-root chain context builds");
    if (context) {
        printf("Actual captured Steam chain trust errors: 0x%08lx\n", (unsigned long)context->TrustStatus.dwErrorStatus);
        CHECK(context->TrustStatus.dwErrorStatus == 0, "actual signatures and complete trusted public root chain validate");
        CHECK(ssl_policy(context, L"client-update.steamstatic.com") == 0, "real SSL policy accepts captured public server hostname");
        CHECK(ssl_policy(context, L"wrong-host.invalid") == (DWORD)CERT_E_CN_NO_MATCH,
              "real SSL policy rejects different hostname");
        CertFreeCertificateChain(context);
    }
    memset(&date, 0, sizeof date); date.wYear = 2050; date.wMonth = 1; date.wDay = 1;
    CHECK(SystemTimeToFileTime(&date, &future), "independent future verification time encoded");
    context = chain(extra, certs[0], &future);
    CHECK(context && (context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_TIME_VALID),
          "actual expired chain retains time-validity failure");
    if (context) CertFreeCertificateChain(context);
    der[0][sizes[0] - 1] ^= 1;
    bad = CertCreateCertificateContext(X509_ASN_ENCODING, der[0], sizes[0]);
    CHECK(bad != NULL, "tampered signature still forms syntactically valid certificate");
    context = bad ? chain(extra, bad, NULL) : NULL;
    CHECK(context && (context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_SIGNATURE_VALID),
          "actual cryptographic signature verification rejects one-bit tampering");
    if (context) CertFreeCertificateChain(context);
done:
    if (bad) CertFreeCertificateContext(bad);
    for (i = 0; i < 3; ++i) {
        if (certs[i]) CertFreeCertificateContext(certs[i]);
        if (der[i]) HeapFree(GetProcessHeap(), 0, der[i]);
    }
    CHECK(CertCloseStore(extra, 0), "actual supporting certificate store closes");
    return k32t_finish("T_RUNTIME_ROOTS");
}
int main(int argc, char **argv)
{
    STARTUPINFOW startup;
    PROCESS_INFORMATION process;
    DWORD result, code = 0, error;
    BOOL exited, thread_closed, process_closed;
    WCHAR update_command[] = L"D:\\steam\\steam.exe -console --no-sandbox -no-cef-sandbox";
    WCHAR preinstalled_command[] = L"D:\\steam\\steam.exe -console --no-sandbox -no-cef-sandbox -skipinitialbootstrap";
    const BOOL preinstalled = argc == 2 && !strcmp(argv[1], "--steam-preinstalled");
    WCHAR *command = preinstalled ? preinstalled_command : update_command;
    if (!initialize_roots()) return 1;
    if (argc == 2 && (!strcmp(argv[1], "--steam") || preinstalled)) {
        memset(&startup, 0, sizeof startup); startup.cb = sizeof startup;
        memset(&process, 0, sizeof process);
        if (!CreateProcessW(L"D:\\steam\\steam.exe", command, NULL, NULL, FALSE, 0, NULL,
                            L"D:\\steam", &startup, &process)) return 1;
        printf("Steam startup scenario: %s\n", preinstalled ? "verified extracted publisher corpus; skip initial bootstrap diagnostic" : "normal publisher updater");
        printf("Unchanged publisher Steam launched after isolated OS trust setup, actual pid %lu\n",
               (unsigned long)process.dwProcessId);
        result = WaitForSingleObject(process.hProcess, INFINITE);
        exited = result == WAIT_OBJECT_0 && GetExitCodeProcess(process.hProcess, &code);
        error = exited ? ERROR_SUCCESS : GetLastError();
        thread_closed = CloseHandle(process.hThread);
        process_closed = CloseHandle(process.hProcess);
        printf("Actual publisher Steam wait: 0x%08lx, error %lu, closed handles %u/%u\n",
               (unsigned long)result, (unsigned long)error, (unsigned)thread_closed, (unsigned)process_closed);
        if (!exited || !thread_closed || !process_closed) return 1;
        printf("Actual publisher Steam OS process exit: 0x%08lx\n", (unsigned long)code);
        return (int)code;
    }
    if (argc != 1) return 1;
    return verify_chain();
}
