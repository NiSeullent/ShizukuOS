/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: URL reference resolution. Expected values: RFC 3986 section 5.4 (normal and abnormal examples with the
 * base "http://a/b/c/d;p?q"), plus file: URLs and the WHATWG backslash rule for special schemes.
 */
#include "host_test.h"
#include "../core/url.h"

static void resolve(const char *base, const char *rel, const char *expected)
{
    char name[256];
    snprintf(name, sizeof(name), "resolve(%s, \"%s\")", base, rel);
    T_STREQ(name, U8take(shz_url_resolve(T(base), T(rel))), expected);
}

int main(void)
{
    static const char *const rfc[][2] = {
        /* 5.4.1 normal examples */
        { "g:h", "g:h" }, { "g", "http://a/b/c/g" }, { "./g", "http://a/b/c/g" }, { "g/", "http://a/b/c/g/" },
        { "/g", "http://a/g" }, { "//g", "http://g" }, { "?y", "http://a/b/c/d;p?y" }, { "g?y", "http://a/b/c/g?y" },
        { "#s", "http://a/b/c/d;p?q#s" }, { "g#s", "http://a/b/c/g#s" }, { "g?y#s", "http://a/b/c/g?y#s" },
        { ";x", "http://a/b/c/;x" }, { "g;x", "http://a/b/c/g;x" }, { "g;x?y#s", "http://a/b/c/g;x?y#s" },
        { "", "http://a/b/c/d;p?q" }, { ".", "http://a/b/c/" }, { "./", "http://a/b/c/" }, { "..", "http://a/b/" },
        { "../", "http://a/b/" }, { "../g", "http://a/b/g" }, { "../..", "http://a/" }, { "../../", "http://a/" },
        { "../../g", "http://a/g" },
        /* 5.4.2 abnormal examples */
        { "../../../g", "http://a/g" }, { "../../../../g", "http://a/g" }, { "/./g", "http://a/g" },
        { "/../g", "http://a/g" }, { "g.", "http://a/b/c/g." }, { ".g", "http://a/b/c/.g" },
        { "g..", "http://a/b/c/g.." }, { "..g", "http://a/b/c/..g" }, { "./../g", "http://a/b/g" },
        { "./g/.", "http://a/b/c/g/" }, { "g/./h", "http://a/b/c/g/h" }, { "g/../h", "http://a/b/c/h" },
        { "g;x=1/./y", "http://a/b/c/g;x=1/y" }, { "g;x=1/../y", "http://a/b/c/y" },
        { "g?y/./x", "http://a/b/c/g?y/./x" }, { "g?y/../x", "http://a/b/c/g?y/../x" },
        { "g#s/./x", "http://a/b/c/g#s/./x" }, { "g#s/../x", "http://a/b/c/g#s/../x" },
    };
    size_t i;
    shz_char *p;
    for (i = 0; i < sizeof(rfc) / sizeof(rfc[0]); ++i) resolve("http://a/b/c/d;p?q", rfc[i][0], rfc[i][1]);
    resolve("http://a/b/c/d;p?q", "  g  ", "http://a/b/c/g");
    resolve("http://a/b/c/d", "img\\x.png", "http://a/b/c/img/x.png");
    resolve("http://example.com", "x.html", "http://example.com/x.html");
    resolve("file:///C:/SHZ/TESTS/A.HTM", "B.PNG", "file:///C:/SHZ/TESTS/B.PNG");
    resolve("file:///C:/SHZ/TESTS/A.HTM", "../FONTS/x.ttf", "file:///C:/SHZ/FONTS/x.ttf");
    resolve("about:blank", "x.html", "x.html");
    resolve("about:blank", "#top", "about:blank#top");
    resolve("http://a/b", "javascript:alert(1)", "javascript:alert(1)");
    resolve("http://a/b", "HTTP://X/./y/../z", "HTTP://X/z");

    p = shz_url_file_path(T("file:///C:/SHZ/TESTS/A%20B.PNG"));
    T_STREQ("file path with a percent escape", U8take(p), "C:/SHZ/TESTS/A B.PNG");
    p = shz_url_file_path(T("file://localhost/C|/x/%C3%A9.htm#frag"));
    T_STREQ("file path: localhost, drive bar, UTF-8 escape, fragment dropped", U8take(p), "C:/x/\xC3\xA9.htm");
    p = shz_url_file_path(T("file:///tmp/a.png"));
    T_STREQ("POSIX file path", U8take(p), "/tmp/a.png");
    T_INTEQ("not a file URL", shz_url_file_path(T("http://a/b")) == NULL, 1);
    T_STREQ("strip fragment", U8take(shz_url_strip_fragment(T("http://a/b#c#d"))), "http://a/b");
    return t_finish("t_url");
}
