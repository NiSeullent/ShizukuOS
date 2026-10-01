/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: serialization. Expected strings follow WHATWG HTML 13.3 "Serializing HTML fragments" (escaping rules,
 * void elements, raw text parents, comments, doctype, foreign elements without self-closing syntax) and, for XML
 * documents, plain XML syntax. Round trips: parse(serialize(parse(x))) has the same tree as parse(x).
 */
#include "host_test.h"

static void body_html(const char *name, const char *html, const char *expected)
{
    shz_doc *doc = t_parse(html, NULL);
    T_STREQ(name, U8take(shz_serialize(shz_doc_body(doc), 0)), expected);
    shz_doc_release(doc);
}

static void round_trip(const char *name, const char *html)
{
    shz_doc *a = t_parse(html, NULL), *b;
    const char *first = t_dump_doc(a);
    const char *markup = U8take(shz_serialize(a->node, 0));
    b = t_parse(markup, NULL);
    T_STREQ(name, t_dump_doc(b), first);
    shz_doc_release(a);
    shz_doc_release(b);
}

int main(void)
{
    shz_doc *doc;
    shz_node *n;

    body_html("escaping in text and attributes",
              "<p title='a\"b&c<d>\xC2\xA0'>x &amp; &lt;y&gt; &nbsp;\"q\"</p>",
              "<p title=\"a&quot;b&amp;c&lt;d&gt;&nbsp;\">x &amp; &lt;y&gt; &nbsp;\"q\"</p>");
    body_html("void elements have no end tag", "<br><img src=x><input><hr><wbr>",
              "<br><img src=\"x\"><input><hr><wbr>");
    body_html("attribute order kept, names lower-case", "<DIV B=1 a=2 C>x</DIV>", "<div b=\"1\" a=\"2\" c=\"\">x</div>");
    body_html("raw text parents are not escaped",
              "<body><script>if (a < b && c) {}</script><style>p>b{}</style><xmp><&></xmp><noscript><b>&amp;</b></noscript>",
              "<script>if (a < b && c) {}</script><style>p>b{}</style><xmp><&></xmp><noscript><b>&amp;</b></noscript>");
    body_html("textarea and title text is escaped", "<textarea>a&amp;b<</textarea>", "<textarea>a&amp;b&lt;</textarea>");
    body_html("pre: no extra newline", "<pre>\n\nx</pre>", "<pre>\nx</pre>");
    body_html("comments", "<body><!--a--><p><!-- b --></p>", "<!--a--><p><!-- b --></p>");
    body_html("foreign elements keep end tags", "<svg viewBox=\"0 0 1 1\"><circle r=\"1\"/></svg>",
              "<svg viewbox=\"0 0 1 1\"><circle r=\"1\"></circle></svg>");
    body_html("implied table sections are serialized", "<table><tr><td>1</table>",
              "<table><tbody><tr><td>1</td></tr></tbody></table>");

    doc = t_parse("<!DOCTYPE html><title>t</title><p id=p>x</p>", NULL);
    T_STREQ("document serialization", U8take(shz_serialize(doc->node, 0)),
            "<!DOCTYPE html><html><head><title>t</title></head><body><p id=\"p\">x</p></body></html>");
    n = shz_doc_get_element_by_id(doc, T("p"));
    T_STREQ("outerHTML", U8take(shz_serialize(n, 1)), "<p id=\"p\">x</p>");
    T_STREQ("innerHTML", U8take(shz_serialize(n, 0)), "x");
    T_STREQ("text node outer", U8take(shz_serialize(n->first_child, 1)), "x");
    shz_doc_release(doc);

    doc = t_parse("<br>", NULL);
    n = shz_doc_body(doc)->first_child;
    T_STREQ("innerHTML of a void element is empty", U8take(shz_serialize(n, 0)), "");
    T_STREQ("outerHTML of a void element", U8take(shz_serialize(n, 1)), "<br>");
    shz_doc_release(doc);

    {
        const shz_char *w = T("<r xmlns=\"urn:x\"><a b=\"1&amp;\"/><c>t&amp;&lt;</c><![CDATA[<d>]]></r>");
        shz_parse_document(w, shz_strlen(w), T("text/xml"), &doc);
        T_STREQ("XML serialization", U8take(shz_serialize(doc->node, 0)),
                "<r xmlns=\"urn:x\"><a b=\"1&amp;\"/><c>t&amp;&lt;</c>&lt;d&gt;</r>");
        shz_doc_release(doc);
    }

    round_trip("round trip: formatting and tables",
               "<!DOCTYPE html><b>1<i>2</b>3</i><table><tr><td>a<td>b</table><p>x<p>y");
    round_trip("round trip: entities and raw text",
               "<p title='&quot;&amp;'>&lt;&amp;&gt;&nbsp;</p><script>a<b</script><textarea>&lt;x</textarea>");
    round_trip("round trip: comments and lists", "<!--c--><ul><li>1<li>2</ul><dl><dt>a<dd>b</dl>");
    round_trip("round trip: select and forms", "<form><select><option>1<option selected>2</select><input value=x></form>");
    return t_finish("t_serialize");
}
