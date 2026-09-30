/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libcurl (libcurl.dll over OpenSSL, zlib, brotli and the Shizuku ws2_32): the build's features, a
 * file:// transfer from D:, and a connection attempt to a closed loopback port that must fail cleanly
 * (CURLE_COULDNT_CONNECT). Real HTTP(S) to a host server is milestone R3 (port/, run_wk_net.py). */
#include <string.h>
#include <curl/curl.h>
#include "deptest.h"

static char got[256];
static size_t gotlen;
static size_t sink(char *p, size_t sz, size_t n, void *u)
{
    (void)u;
    size_t k = sz * n;
    if (gotlen + k < sizeof got) { memcpy(got + gotlen, p, k); gotlen += k; }
    return k;
}

int main(void)
{
    CHECK(curl_global_init(CURL_GLOBAL_ALL) == CURLE_OK);
    curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
    printf("curl %s, ssl %s, libz %s, brotli %s\n", vi->version, vi->ssl_version ? vi->ssl_version : "-",
           vi->libz_version ? vi->libz_version : "-", vi->brotli_version ? vi->brotli_version : "-");
    CHECK(vi->ssl_version && strstr(vi->ssl_version, "OpenSSL") && (vi->features & CURL_VERSION_SSL));
    CHECK((vi->features & CURL_VERSION_LIBZ) && (vi->features & CURL_VERSION_BROTLI) && (vi->features & CURL_VERSION_IPV6));
    FILE *f = fopen("t_curl.txt", "wb");
    if (f) { fputs("file transfer through libcurl", f); fclose(f); }
    CURL *c = curl_easy_init();
    curl_easy_setopt(c, CURLOPT_URL, "file:///D:/WK/t_curl.txt");
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink);
    CURLcode rc = curl_easy_perform(c);
    printf("file:// rc=%d \"%.*s\"\n", rc, (int)gotlen, got);
    CHECK(rc == CURLE_OK && gotlen == 29 && !memcmp(got, "file transfer through libcurl", 29));
    curl_easy_reset(c);
    curl_easy_setopt(c, CURLOPT_URL, "http://127.0.0.1:9/");
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, sink);
    rc = curl_easy_perform(c);
    printf("closed port rc=%d (%s)\n", rc, curl_easy_strerror(rc));
    CHECK(rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT);
    curl_easy_cleanup(c);
    remove("t_curl.txt");
    curl_global_cleanup();
    return DONE("t_dep_curl");
}
