/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: HTML tokenizer + tree builder. Expected trees are derived by hand from the WHATWG HTML parsing algorithm
 * (13.2.5 tokenization, 13.2.6 tree construction), in the html5lib-tests dump format.
 */
#include "host_test.h"

static void tree_case(const char *name, const char *html, const char *expected)
{
    shz_doc *doc = t_parse(html, NULL);
    T_STREQ(name, t_dump_doc(doc), expected);
    shz_doc_release(doc);
}

static int quirks_of(const char *html)
{
    shz_doc *doc = t_parse(html, NULL);
    int q = doc->doctype_quirks;
    shz_doc_release(doc);
    return q;
}

static void test_basic(void)
{
    tree_case("implied html/head/body",
              "<p>Hello",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"Hello\"\n");
    tree_case("doctype, title with charref, implied </p>",
              "<!DOCTYPE html><title>T &amp; U</title><p>a<p>b",
              "| <!DOCTYPE html>\n| <html>\n|   <head>\n|     <title>\n|       \"T & U\"\n|   <body>\n"
              "|     <p>\n|       \"a\"\n|     <p>\n|       \"b\"\n");
    tree_case("li auto-close",
              "<ul><li>one<li>two</ul>",
              "| <html>\n|   <head>\n|   <body>\n|     <ul>\n|       <li>\n|         \"one\"\n|       <li>\n|         \"two\"\n");
    tree_case("dt/dd auto-close",
              "<dl><dt>a<dd>b<dt>c</dl>",
              "| <html>\n|   <head>\n|   <body>\n|     <dl>\n|       <dt>\n|         \"a\"\n|       <dd>\n|         \"b\"\n"
              "|       <dt>\n|         \"c\"\n");
    tree_case("nested lists",
              "<ul><li>a<ul><li>b</ul><li>c</ul>",
              "| <html>\n|   <head>\n|   <body>\n|     <ul>\n|       <li>\n|         \"a\"\n|         <ul>\n|           <li>\n"
              "|             \"b\"\n|       <li>\n|         \"c\"\n");
    tree_case("div closes p",
              "<p><div>x</div>",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|     <div>\n|       \"x\"\n");
    tree_case("meta goes to the implied head",
              "<meta charset=utf-8><p>x",
              "| <html>\n|   <head>\n|     <meta>\n|       charset=\"utf-8\"\n|   <body>\n|     <p>\n|       \"x\"\n");
    tree_case("title in body stays in body",
              "<body><title>x</title>",
              "| <html>\n|   <head>\n|   <body>\n|     <title>\n|       \"x\"\n");
    tree_case("headings do not nest",
              "<h1>a<h2>b",
              "| <html>\n|   <head>\n|   <body>\n|     <h1>\n|       \"a\"\n|     <h2>\n|       \"b\"\n");
    tree_case("stray </p> before <html> is ignored",
              "</p>",
              "| <html>\n|   <head>\n|   <body>\n");
    tree_case("stray </p> in body makes an empty p",
              "<body></p>",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n");
    tree_case("button closes button",
              "<button>a<button>b",
              "| <html>\n|   <head>\n|   <body>\n|     <button>\n|       \"a\"\n|     <button>\n|       \"b\"\n");
    tree_case("option closes option in body",
              "<option>a<option>b",
              "| <html>\n|   <head>\n|   <body>\n|     <option>\n|       \"a\"\n|     <option>\n|       \"b\"\n");
    tree_case("nested form is ignored",
              "<form id=a><form id=b><input></form>",
              "| <html>\n|   <head>\n|   <body>\n|     <form>\n|       id=\"a\"\n|       <input>\n");
    tree_case("void elements and </br>",
              "a<br>b<img src=x>c</br>d<input type=text>",
              "| <html>\n|   <head>\n|   <body>\n|     \"a\"\n|     <br>\n|     \"b\"\n|     <img>\n|       src=\"x\"\n"
              "|     \"c\"\n|     <br>\n|     \"d\"\n|     <input>\n|       type=\"text\"\n");
    tree_case("names lower-cased, values kept, duplicate attribute dropped",
              "<DIV ID=a CLASS=\"B c\" id=z>x</DIV>",
              "| <html>\n|   <head>\n|   <body>\n|     <div>\n|       class=\"B c\"\n|       id=\"a\"\n|       \"x\"\n");
    tree_case("self-closing flag ignored on HTML elements",
              "<div/>x",
              "| <html>\n|   <head>\n|   <body>\n|     <div>\n|       \"x\"\n");
    tree_case("text after </html> goes to body",
              "<p>a</p></body></html>b",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"a\"\n|     \"b\"\n");
    tree_case("comment after </html> goes to the document",
              "<p>a</p></html><!--x-->",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"a\"\n| <!-- x -->\n");
    tree_case("image is img",
              "<image src=a>",
              "| <html>\n|   <head>\n|   <body>\n|     <img>\n|       src=\"a\"\n");
}

static void test_comments_and_doctype(void)
{
    tree_case("conditional comment is one comment node",
              "<!--[if IE]><p>ie</p><![endif]--><p>x",
              "| <!-- [if IE]><p>ie</p><![endif] -->\n| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"x\"\n");
    tree_case("conditional comment inside body",
              "<body>a<!--[if lt IE 9]><script src=x></script><![endif]-->b",
              "| <html>\n|   <head>\n|   <body>\n|     \"a\"\n|     <!-- [if lt IE 9]><script src=x></script><![endif] -->\n"
              "|     \"b\"\n");
    tree_case("comment dashes",
              "<body><!-- a -- b --><!----><!--->x",
              "| <html>\n|   <head>\n|   <body>\n|     <!--  a -- b  -->\n|     <!--  -->\n|     <!--  -->\n|     \"x\"\n");
    tree_case("bogus comments: <? and <![CDATA[ in HTML",
              "<body><?php x ?><![CDATA[y]]>",
              "| <html>\n|   <head>\n|   <body>\n|     <!-- ?php x ? -->\n|     <!-- [CDATA[y]] -->\n");
    tree_case("doctype with public and system ids",
              "<!DOCTYPE html PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\"><p>",
              "| <!DOCTYPE html \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\n| <html>\n"
              "|   <head>\n|   <body>\n|     <p>\n");
    tree_case("doctype name lower-cased, system id only",
              "<!DOCTYPE HTML SYSTEM 'about:legacy-compat'>",
              "| <!DOCTYPE html \"\" \"about:legacy-compat\">\n| <html>\n|   <head>\n|   <body>\n");
    T_INTEQ("no doctype: quirks", quirks_of("<p>x"), SHZ_QUIRKS_FULL);
    T_INTEQ("<!DOCTYPE html>: no-quirks", quirks_of("<!DOCTYPE html><p>x"), SHZ_QUIRKS_NONE);
    T_INTEQ("HTML 4.01 strict: no-quirks",
            quirks_of("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">"),
            SHZ_QUIRKS_NONE);
    T_INTEQ("HTML 4.01 transitional without system id: quirks",
            quirks_of("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">"), SHZ_QUIRKS_FULL);
    T_INTEQ("HTML 4.01 transitional with system id: limited quirks",
            quirks_of("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" "
                      "\"http://www.w3.org/TR/html4/loose.dtd\">"), SHZ_QUIRKS_LIMITED);
    T_INTEQ("XHTML 1.0 transitional: limited quirks",
            quirks_of("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" "
                      "\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"), SHZ_QUIRKS_LIMITED);
    T_INTEQ("HTML 3.2: quirks", quirks_of("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 3.2 Final//EN\">"), SHZ_QUIRKS_FULL);
    T_INTEQ("doctype other than html: quirks", quirks_of("<!DOCTYPE foo>"), SHZ_QUIRKS_FULL);
}

static void test_charrefs(void)
{
    tree_case("named and numeric character references",
              "<p>&lt;&amp;&gt;&quot;&#65;&#x42;&copy;&notin;&noti;&#128;&#0;&#x110000;&#xD800;",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"<&>\"AB\xC2\xA9\xE2\x88\x89\xC2\xACi;\xE2\x82\xAC"
              "\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\"\n");
    tree_case("legacy name without semicolon, unknown name, lone ampersand",
              "<p>&copy2 &ampx &unknown; & a&#; &#x;",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"\xC2\xA9" "2 &x &unknown; & a&#; &#x;\"\n");
    tree_case("attribute: legacy reference before = or alnum is not decoded",
              "<a href=\"?a=1&copy=2&amp;b&copyx&copy;\" title=&lt;x>t</a>",
              "| <html>\n|   <head>\n|   <body>\n|     <a>\n|       href=\"?a=1&copy=2&b&copyx\xC2\xA9\"\n"
              "|       title=\"<x\"\n|       \"t\"\n");
    tree_case("astral numeric reference becomes a surrogate pair",
              "<p>&#x1F600;",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"\xF0\x9F\x98\x80\"\n");
}

static void test_text_modes(void)
{
    tree_case("textarea: RCDATA and the leading newline",
              "<textarea>\n<b>x</b>&amp;</textarea>",
              "| <html>\n|   <head>\n|   <body>\n|     <textarea>\n|       \"<b>x</b>&\"\n");
    tree_case("pre drops one leading newline",
              "<pre>\n\nx</pre>",
              "| <html>\n|   <head>\n|   <body>\n|     <pre>\n|       \"\nx\"\n");
    tree_case("style: RAWTEXT",
              "<style>a<b &amp; </style>",
              "| <html>\n|   <head>\n|     <style>\n|       \"a<b &amp; \"\n|   <body>\n");
    tree_case("script: end tag only for </script>",
              "<script>if (a<b) x=\"</p>\";</script>",
              "| <html>\n|   <head>\n|     <script>\n|       \"if (a<b) x=\"</p>\";\"\n|   <body>\n");
    tree_case("title end tag match is case-insensitive",
              "<title>a</TITLE b>c",
              "| <html>\n|   <head>\n|     <title>\n|       \"a\"\n|   <body>\n|     \"c\"\n");
    tree_case("xmp and iframe are raw text",
              "<xmp><b></xmp><iframe><i></iframe>",
              "| <html>\n|   <head>\n|   <body>\n|     <xmp>\n|       \"<b>\"\n|     <iframe>\n|       \"<i>\"\n");
    tree_case("plaintext swallows everything",
              "<plaintext>a</plaintext><b>",
              "| <html>\n|   <head>\n|   <body>\n|     <plaintext>\n|       \"a</plaintext><b>\"\n");
    tree_case("CR LF normalization",
              "<p>a\r\nb\rc",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"a\nb\nc\"\n");
}

static void test_tables(void)
{
    tree_case("implied tbody and rows",
              "<table><tr><td>1<td>2<tr><td>3</table>",
              "| <html>\n|   <head>\n|   <body>\n|     <table>\n|       <tbody>\n|         <tr>\n|           <td>\n"
              "|             \"1\"\n|           <td>\n|             \"2\"\n|         <tr>\n|           <td>\n|             \"3\"\n");
    tree_case("foster parenting of text",
              "<table>X<tr><td>Y</table>",
              "| <html>\n|   <head>\n|   <body>\n|     \"X\"\n|     <table>\n|       <tbody>\n|         <tr>\n|           <td>\n"
              "|             \"Y\"\n");
    tree_case("foster parenting of an element",
              "<table><b>B</b><tr><td>C</td></tr></table>",
              "| <html>\n|   <head>\n|   <body>\n|     <b>\n|       \"B\"\n|     <table>\n|       <tbody>\n|         <tr>\n"
              "|           <td>\n|             \"C\"\n");
    tree_case("caption, col group and sections",
              "<table><caption>c</caption><col><thead><tr><th>h<tbody><tr><td>1</table>",
              "| <html>\n|   <head>\n|   <body>\n|     <table>\n|       <caption>\n|         \"c\"\n|       <colgroup>\n"
              "|         <col>\n|       <thead>\n|         <tr>\n|           <th>\n|             \"h\"\n|       <tbody>\n"
              "|         <tr>\n|           <td>\n|             \"1\"\n");
    tree_case("td directly in table",
              "<table><td>x</table>",
              "| <html>\n|   <head>\n|   <body>\n|     <table>\n|       <tbody>\n|         <tr>\n|           <td>\n"
              "|             \"x\"\n");
    tree_case("whitespace in table stays in table",
              "<table> <tr> <td>x</td> </tr> </table>",
              "| <html>\n|   <head>\n|   <body>\n|     <table>\n|       \" \"\n|       <tbody>\n|         <tr>\n"
              "|           \" \"\n|           <td>\n|             \"x\"\n|           \" \"\n|         \" \"\n");
    tree_case("nested table in a cell, then back",
              "<table><tr><td><table><tr><td>in</table>out</td></tr></table>",
              "| <html>\n|   <head>\n|   <body>\n|     <table>\n|       <tbody>\n|         <tr>\n|           <td>\n"
              "|             <table>\n|               <tbody>\n|                 <tr>\n|                   <td>\n"
              "|                     \"in\"\n|             \"out\"\n");
    tree_case("standards mode: table closes p",
              "<!DOCTYPE html><p>1<table></table>",
              "| <!DOCTYPE html>\n| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"1\"\n|     <table>\n");
    tree_case("quirks mode: table inside p",
              "<p>1<table></table>",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"1\"\n|       <table>\n");
    tree_case("hidden input stays in the table",
              "<table><input type=hidden><input type=text></table>",
              "| <html>\n|   <head>\n|   <body>\n|     <input>\n|       type=\"text\"\n|     <table>\n|       <input>\n"
              "|         type=\"hidden\"\n");
    tree_case("select with options, select closes select",
              "<select><option>a<option>b<optgroup label=g><option>c</select><select><select>",
              "| <html>\n|   <head>\n|   <body>\n|     <select>\n|       <option>\n|         \"a\"\n|       <option>\n"
              "|         \"b\"\n|       <optgroup>\n|         label=\"g\"\n|         <option>\n|           \"c\"\n"
              "|     <select>\n");
}

static void test_formatting(void)
{
    tree_case("misnested b/i",
              "<b>1<i>2</b>3</i>",
              "| <html>\n|   <head>\n|   <body>\n|     <b>\n|       \"1\"\n|       <i>\n|         \"2\"\n|     <i>\n"
              "|       \"3\"\n");
    tree_case("adoption agency across a block",
              "<a href=x>1<div>2</a>3</div>",
              "| <html>\n|   <head>\n|   <body>\n|     <a>\n|       href=\"x\"\n|       \"1\"\n|     <div>\n|       <a>\n"
              "|         href=\"x\"\n|         \"2\"\n|       \"3\"\n");
    tree_case("a closes a",
              "<a>1<a>2",
              "| <html>\n|   <head>\n|   <body>\n|     <a>\n|       \"1\"\n|     <a>\n|       \"2\"\n");
    tree_case("formatting reconstructed in the next paragraph",
              "<p><b>x<p>y",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       <b>\n|         \"x\"\n|     <p>\n|       <b>\n"
              "|         \"y\"\n");
    tree_case("font color face size",
              "<font color=red face=Arial size=+1>x</font>",
              "| <html>\n|   <head>\n|   <body>\n|     <font>\n|       color=\"red\"\n|       face=\"Arial\"\n"
              "|       size=\"+1\"\n|       \"x\"\n");
}

static void test_frameset_and_foreign(void)
{
    tree_case("frameset document",
              "<frameset cols=\"50%,*\"><frame src=a><frame src=b></frameset>",
              "| <html>\n|   <head>\n|   <frameset>\n|     cols=\"50%,*\"\n|     <frame>\n|       src=\"a\"\n|     <frame>\n"
              "|       src=\"b\"\n");
    tree_case("frameset after text is ignored",
              "<p>x<frameset><frame>",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"x\"\n");
    tree_case("svg subtree with self-closing children",
              "<svg viewBox=\"0 0 1 1\"><circle r=\"1\"/><g><rect/></g></svg><p>after",
              "| <html>\n|   <head>\n|   <body>\n|     <svg svg>\n|       viewbox=\"0 0 1 1\"\n|       <svg circle>\n"
              "|         r=\"1\"\n|       <svg g>\n|         <svg rect>\n|     <p>\n|       \"after\"\n");
    tree_case("unquoted attribute value keeps a trailing slash",
              "<svg><circle r=1/></svg>",
              "| <html>\n|   <head>\n|   <body>\n|     <svg svg>\n|       <svg circle>\n|         r=\"1/\"\n");
    tree_case("html element breaks out of svg",
              "<svg><circle><p>x",
              "| <html>\n|   <head>\n|   <body>\n|     <svg svg>\n|       <svg circle>\n|     <p>\n|       \"x\"\n");
    tree_case("math",
              "<math><mi>x</mi></math>",
              "| <html>\n|   <head>\n|   <body>\n|     <math math>\n|       <math mi>\n|         \"x\"\n");
    tree_case("CDATA in svg",
              "<svg><![CDATA[a<b]]></svg>",
              "| <html>\n|   <head>\n|   <body>\n|     <svg svg>\n|       \"a<b\"\n");
}

static void test_eof_cases(void)
{
    tree_case("EOF in a tag drops the tag", "<p>x<div id=\"a", "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"x\"\n");
    tree_case("EOF in a comment emits it", "<p>x<!--y", "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"x\"\n|       <!-- y -->\n");
    tree_case("lone < and </> ", "<p>a < b </> c</",
              "| <html>\n|   <head>\n|   <body>\n|     <p>\n|       \"a < b  c</\"\n");
    tree_case("empty document", "", "| <html>\n|   <head>\n|   <body>\n");
    tree_case("EOF in script text", "<script>x", "| <html>\n|   <head>\n|     <script>\n|       \"x\"\n|   <body>\n");
}

static void test_fragments(void)
{
    shz_doc *doc = t_parse("<!DOCTYPE html><body><div id=d></div><table id=t></table><select id=s></select>"
                           "<textarea id=ta></textarea><tr id=r>", NULL);
    shz_node *div = shz_doc_get_element_by_id(doc, T("d")), *table = shz_doc_get_element_by_id(doc, T("t"));
    shz_node *sel = shz_doc_get_element_by_id(doc, T("s")), *ta = shz_doc_get_element_by_id(doc, T("ta"));
    shz_node *frag = NULL, *tr;
    const shz_char *w;

    w = T("<b>x</b>y<p>1<p>2");
    T_INTEQ("fragment in div parses", shz_parse_fragment(div, w, shz_strlen(w), &frag), SHZ_OK);
    T_STREQ("fragment in div", t_dump(frag),
            "| <b>\n|   \"x\"\n| \"y\"\n| <p>\n|   \"1\"\n| <p>\n|   \"2\"\n");
    T_INTEQ("fragment has no parent", frag->parent == NULL, 1);
    T_INTEQ("fragment is not connected", shz_in_doc(frag->first_child), 0);
    shz_node_release(frag);

    w = T("<tr><td>1");
    shz_parse_fragment(table, w, shz_strlen(w), &frag);
    T_STREQ("fragment in table", t_dump(frag), "| <tbody>\n|   <tr>\n|     <td>\n|       \"1\"\n");
    shz_node_release(frag);

    tr = shz_create_element(doc, T("tr"), 2);
    w = T("<td>a<td>b");
    shz_parse_fragment(tr, w, shz_strlen(w), &frag);
    T_STREQ("fragment in tr", t_dump(frag), "| <td>\n|   \"a\"\n| <td>\n|   \"b\"\n");
    shz_node_release(frag);
    shz_node_release(tr);

    w = T("<b>x</b></textarea>y");
    shz_parse_fragment(ta, w, shz_strlen(w), &frag);
    T_STREQ("fragment in textarea is RCDATA", t_dump(frag), "| \"<b>x</b></textarea>y\"\n");
    shz_node_release(frag);

    w = T("<option>a<option>b");
    shz_parse_fragment(sel, w, shz_strlen(w), &frag);
    T_STREQ("fragment in select", t_dump(frag), "| <option>\n|   \"a\"\n| <option>\n|   \"b\"\n");
    shz_node_release(frag);

    w = T("<!--[if IE]>x<![endif]--><script>s()</script>");
    shz_parse_fragment(div, w, shz_strlen(w), &frag);
    T_STREQ("conditional comment fragment", t_dump(frag),
            "| <!-- [if IE]>x<![endif] -->\n| <script>\n|   \"s()\"\n");
    T_INTEQ("fragment scripts are already started", (frag->last_child->flags & SHZ_NF_STARTED) != 0, 1);
    T_INTEQ("fragment scripts are not parser-inserted", (frag->last_child->flags & SHZ_NF_PARSER_INSERTED) != 0, 0);
    shz_node_release(frag);

    shz_doc_release(doc);
}

static void test_xml(void)
{
    shz_doc *doc = NULL;
    const shz_char *w = T("<?xml version=\"1.0\"?><Root xmlns=\"urn:x\"><Item A=\"1\"/><Item>t<![CDATA[<c>]]></Item>"
                          "<?pi data?></Root>");
    T_INTEQ("XML parse", shz_parse_document(w, shz_strlen(w), T("application/xml"), &doc), SHZ_OK);
    T_STREQ("XML tree keeps case, self-closing and CDATA", t_dump_doc(doc),
            "| <Root>\n|   xmlns=\"urn:x\"\n|   <Item>\n|     A=\"1\"\n|   <Item>\n|     \"t<c>\"\n|   <?pi data>\n");
    T_INTEQ("XML document is not HTML", doc->is_html, 0);
    T_INTEQ("XML element namespace other", ((shz_element *)shz_doc_element(doc))->ns, SHZ_NS_OTHER);
    shz_doc_release(doc);
}

int main(void)
{
    T_INTEQ("name tables are sorted", shz_names_sorted(), 1);
    test_basic();
    test_comments_and_doctype();
    test_charrefs();
    test_text_modes();
    test_tables();
    test_formatting();
    test_frameset_and_foreign();
    test_eof_cases();
    test_fragments();
    test_xml();
    return t_finish("t_tree");
}
