/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: deterministic random tag soup through the parser (under ASan/UBSan/LeakSanitizer). Properties checked:
 *  - no crash, no leak, no sanitizer report on any input;
 *  - the HTML parser's input stream is chunking-independent (HTML 13.2.3: the tokenizer is defined on the code point
 *    stream), so feeding the bytes in random chunks gives exactly the tree of one load_string;
 *  - serialize(body) parses back with parse_fragment;
 *  - DOM mutations on the parsed tree keep live lists consistent with a fresh traversal.
 */
#include "host_test.h"
#include "../core/selectors.h"

static uint32_t rng = 12345;

static uint32_t rnd(uint32_t n)
{
    rng = rng * 1103515245u + 12345u;
    return (rng >> 8) % n;
}

static const char *const pieces[] = {
    "<p>", "</p>", "<div>", "</div>", "<b>", "</b>", "<i>", "</i>", "<a href=x>", "</a>", "<table>", "</table>",
    "<tr>", "<td>", "</td>", "<th>", "<tbody>", "<caption>", "<col>", "<ul>", "<li>", "</ul>", "<dl><dt>", "<dd>",
    "<select>", "<option>", "</select>", "<form>", "</form>", "<input>", "<textarea>", "</textarea>", "<title>",
    "</title>", "<script>", "</script>", "<style>", "</style>", "<!--", "-->", "<!--[if IE]>", "<![endif]-->",
    "<!DOCTYPE html>", "<br>", "</br>", "<img src=a>", "<svg>", "</svg>", "<circle/>", "<math>", "<mi>",
    "<frameset>", "<frame>", "<noscript>", "<plaintext>", "<xmp>", "<iframe>", "</iframe>", "<pre>\n", "&amp;",
    "&lt", "&#x41;", "&#12", "&notin", "&", "<", ">", "\"", "'", "=", " ", "\n", "\r\n", "text", "x y", "\xC3\xA9",
    "\xF0\x9F\x98\x80", "<h1>", "<h2>", "</h1>", "<nobr>", "<button>", "</button>", "<object>", "</object>",
    "<head>", "<body>", "</body>", "</html>", "<html lang=en>", "<meta charset=utf-8>", "<base href=/x/>",
    "<![CDATA[", "]]>", "<?pi?>", "</", "<p id='a' class=b data-x=\"1&amp;2\">", "<template>", "</template>",
};

static void make(char *buf, size_t cap)
{
    size_t len = 0, n = 1 + rnd(40), i;
    for (i = 0; i < n; ++i) {
        const char *p = pieces[rnd(sizeof(pieces) / sizeof(pieces[0]))];
        size_t pl = strlen(p);
        if (len + pl + 1 >= cap) break;
        memcpy(buf + len, p, pl);
        len += pl;
    }
    buf[len] = 0;
}

int main(void)
{
    char html[4096];
    int iter, iters = 8000, chunk_mismatch = 0, frag_failed = 0, list_mismatch = 0;
    /* SHZ_FUZZ_ITER / SHZ_FUZZ_SEED widen a local run; the defaults are what the test suite checks */
    if (getenv("SHZ_FUZZ_ITER")) iters = atoi(getenv("SHZ_FUZZ_ITER"));
    if (getenv("SHZ_FUZZ_SEED")) rng = (uint32_t)atoi(getenv("SHZ_FUZZ_SEED"));
    for (iter = 0; iter < iters; ++iter) {
        shz_doc *a = NULL, *b;
        const char *da, *db;
        size_t n, i;
        shz_node *body;
        make(html, sizeof(html));
        n = strlen(html);

        /* whole string */
        a = t_parse(html, NULL);
        da = t_dump_doc(a);

        /* random chunks of UTF-8 bytes */
        b = t_new_doc(NULL);
        shz_parser_begin(b, T("utf-8"));
        for (i = 0; i < n;) {
            size_t c = 1 + rnd(9);
            if (c > n - i) c = n - i;
            shz_parser_feed(b, (const uint8_t *)html + i, c);
            i += c;
        }
        shz_parser_end(b);
        db = t_dump_doc(b);
        if (strcmp(da, db)) {
            if (!chunk_mismatch) printf("chunk mismatch for [%s]\n--- whole\n%s--- chunked\n%s", html, da, db);
            ++chunk_mismatch;
        }
        shz_doc_release(b);

        /* fragment parsing of the serialization must not fail (HTML parsing is not idempotent for misnested
         * trees, e.g. <h1><nobr><h1>...<h2>, so the result is not compared) */
        body = shz_doc_body(a);
        if (body && shz_is_tag(body, SHZ_TAG_BODY)) {
            shz_char *s1 = shz_serialize(body, 0);
            shz_node *frag = NULL;
            if (!s1 || SHZ_FAILED(shz_parse_fragment(body, s1, shz_strlen(s1), &frag))) ++frag_failed;
            shz_node_release(frag);
            shz_free(s1);
        }

        /* mutations vs live lists */
        {
            shz_list *all = shz_list_collection(a, SHZ_COLL_ALL);
            shz_node *root = shz_doc_element(a), *x;
            uint32_t count = shz_list_length(all), walk = 0;
            if (root && root->first_child) {
                shz_node *victim = shz_list_item(all, rnd(count ? count : 1));
                if (victim && victim != root) {
                    shz_node_addref(victim);
                    shz_node_remove(victim);
                    shz_node_append(root, victim);
                    shz_node_release(victim);
                }
            }
            for (x = a->node->first_child; x; x = shz_node_next(x, a->node))
                if (x->type == SHZ_ELEMENT_NODE) ++walk;
            if (walk != shz_list_length(all)) ++list_mismatch;
            shz_list_release(all);
        }
        shz_doc_release(a);
        if ((iter & 255) == 255) {
            size_t k;                  /* keep the string pool small */
            for (k = 0; k < t_pool_n; ++k) shz_free(t_pool[k]);
            t_pool_n = 0;
        }
    }
    T_INTEQ("random documents: chunked feeding gives the same tree", chunk_mismatch, 0);
    T_INTEQ("random documents: the serialization parses back as a fragment", frag_failed, 0);
    T_INTEQ("random documents: live document.all matches a traversal after mutation", list_mismatch, 0);
    return t_finish("t_fuzz");
}
