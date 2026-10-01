/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: encoding labels, BOM sniffing, the <meta> prescan and the decoders, through parser_begin/feed/end.
 * Expected values: WHATWG Encoding Standard (labels, windows-1252 index, UTF-8 decoder error handling) and WHATWG HTML
 * "determining the character encoding" (BOM > transport layer > prescan of the first 1024 bytes > default).
 */
#include "host_test.h"
#include "../core/charset.h"

/* parse bytes fed in chunks of `chunk` bytes (0 = all at once); returns the text of the first <p> as UTF-8 */
static const char *feed(const char *bytes, size_t n, size_t chunk, const char *channel, const char **charset)
{
    shz_doc *doc = t_new_doc(NULL);
    shz_node *p;
    const char *r;
    size_t i;
    shz_parser_begin(doc, channel ? T(channel) : NULL);
    if (!chunk) chunk = n ? n : 1;
    for (i = 0; i < n; i += chunk) shz_parser_feed(doc, (const uint8_t *)bytes + i, n - i < chunk ? n - i : chunk);
    shz_parser_end(doc);
    for (p = doc->node; p && !shz_is_tag(p, SHZ_TAG_P); p = shz_node_next(p, doc->node)) {}
    r = p ? U8take(shz_node_text_content(p)) : "(no p)";
    if (charset) *charset = U8(doc->charset);
    shz_doc_release(doc);
    return r;
}

static void check(const char *name, const char *bytes, size_t n, const char *channel, const char *text, const char *cs)
{
    const char *got_cs = NULL;
    char buf[300];
    size_t chunk;
    T_STREQ(name, feed(bytes, n, 0, channel, &got_cs), text);
    snprintf(buf, sizeof(buf), "%s: encoding", name);
    T_STREQ(buf, got_cs, cs);
    for (chunk = 1; chunk <= 3; ++chunk) {
        snprintf(buf, sizeof(buf), "%s: fed in %zu-byte chunks", name, chunk);
        T_STREQ(buf, feed(bytes, n, chunk, channel, NULL), text);
    }
}

int main(void)
{
    static const char bom8[] = "\xEF\xBB\xBF<p>\xC3\xA9</p>";
    static const char bom16le[] = "\xFF\xFE<\0p\0>\0x\0\xAC\x20";
    static const char bom16be[] = "\xFE\xFF\0<\0p\0>\0x\x20\xAC";
    static const char meta1252[] = "<meta charset=windows-1252><p>\x80\xE9</p>";
    static const char meta_he[] = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=ISO-8859-1\"><p>\x80</p>";
    static const char meta16[] = "<meta charset=\"utf-16\"><p>\xC3\xA9</p>";
    static const char none[] = "<p>\xC3\xA9</p>";
    static const char latin9[] = "<p>\xA4</p>";
    static const char bad8[] = "<p>a\xC0\x80" "b\xE2\x82" "c\xF0\x9F\x98\x80</p>";
    static const char commented[] = "<!-- <meta charset=utf-16> --><meta charset='windows-1252'><p>\x80</p>";
    static const char content_only[] = "<meta content=\"text/html; charset=windows-1252\"><p>\xC3\xA9</p>";
    char late[1200];
    size_t i;

    T_INTEQ("label ' Latin1 '", shz_charset_from_label(T(" Latin1 "), 8), SHZ_CS_WINDOWS_1252);
    T_INTEQ("label utf8", shz_charset_from_label(T("utf8"), 4), SHZ_CS_UTF8);
    T_INTEQ("label us-ascii is windows-1252", shz_charset_from_label(T("US-ASCII"), 8), SHZ_CS_WINDOWS_1252);
    T_INTEQ("label unicode is UTF-16LE", shz_charset_from_label(T("unicode"), 7), SHZ_CS_UTF16LE);
    T_INTEQ("unknown label", shz_charset_from_label(T("bogus"), 5), SHZ_CS_NONE);
    T_INTEQ("windows-1252 0x80 = U+20AC", shz_cp1252_c1(0x80), 0x20AC);
    T_INTEQ("windows-1252 0x9F = U+0178", shz_cp1252_c1(0x9F), 0x0178);
    T_INTEQ("windows-1252 0x81 = U+0081", shz_cp1252_c1(0x81), 0x0081);

    check("UTF-8 BOM", bom8, sizeof(bom8) - 1, NULL, "\xC3\xA9", "UTF-8");
    check("UTF-16LE BOM", bom16le, sizeof(bom16le) - 1, NULL, "x\xE2\x82\xAC", "UTF-16LE");
    check("UTF-16BE BOM", bom16be, sizeof(bom16be) - 1, NULL, "x\xE2\x82\xAC", "UTF-16BE");
    check("<meta charset=windows-1252>", meta1252, sizeof(meta1252) - 1, NULL, "\xE2\x82\xAC\xC3\xA9", "windows-1252");
    check("<meta http-equiv> ISO-8859-1 decodes as windows-1252", meta_he, sizeof(meta_he) - 1, NULL, "\xE2\x82\xAC",
          "windows-1252");
    check("<meta charset=utf-16> means UTF-8", meta16, sizeof(meta16) - 1, NULL, "\xC3\xA9", "UTF-8");
    check("default UTF-8", none, sizeof(none) - 1, NULL, "\xC3\xA9", "UTF-8");
    check("channel charset iso-8859-15", latin9, sizeof(latin9) - 1, "iso-8859-15", "\xE2\x82\xAC", "ISO-8859-15");
    check("BOM beats the channel charset", bom8, sizeof(bom8) - 1, "windows-1252", "\xC3\xA9", "UTF-8");
    check("UTF-8 decoder errors", bad8, sizeof(bad8) - 1, NULL,
          "a\xEF\xBF\xBD\xEF\xBF\xBD" "b\xEF\xBF\xBD" "c\xF0\x9F\x98\x80", "UTF-8");
    check("prescan skips comments", commented, sizeof(commented) - 1, NULL, "\xE2\x82\xAC", "windows-1252");
    check("content without http-equiv is ignored", content_only, sizeof(content_only) - 1, NULL, "\xC3\xA9", "UTF-8");

    /* a <meta> after the first 1024 bytes does not count */
    memset(late, ' ', sizeof(late));
    memcpy(late, none, sizeof(none) - 1);
    memcpy(late + 1100, "<meta charset=windows-1252>", 27);
    check("meta after 1024 bytes ignored", late, 1100 + 27, NULL, "\xC3\xA9", "UTF-8");
    /* the same bytes with the meta inside the first 1024 */
    for (i = 0; i < sizeof(late); ++i) late[i] = ' ';
    memcpy(late, "<meta charset=windows-1252>", 27);
    memcpy(late + 1000, none, sizeof(none) - 1);
    check("meta inside 1024 bytes", late, 1000 + sizeof(none) - 1, NULL, "\xC3\x83\xC2\xA9", "windows-1252");
    return t_finish("t_charset");
}
