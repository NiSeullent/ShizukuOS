/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: the DOM. Expected behaviour: WHATWG DOM Standard (pre-insert validity, mutation algorithms,
 * compareDocumentPosition, splitText, textContent), HTML (live HTMLCollections, document.all/forms/links/anchors,
 * namedItem, innerText rules) and the engine.h lifetime contract (a node stays alive while referenced or attached;
 * identity is the pointer; a referenced node keeps its document alive). LeakSanitizer checks that nothing leaks.
 */
#include "host_test.h"
#include "../core/range.h"

static shz_node *byid(shz_doc *doc, const char *id)
{
    return shz_doc_get_element_by_id(doc, T(id));
}

static shz_node *mk(shz_doc *doc, const char *tag)
{
    return shz_create_element(doc, T(tag), strlen(tag));
}

static shz_node *mktext(shz_doc *doc, const char *s)
{
    const shz_char *w = T(s);
    return shz_create_text(doc, w, shz_strlen(w));
}

static void test_tree_mutation(void)
{
    t_host h;
    shz_doc *doc = t_parse("<!DOCTYPE html><body><div id=d><p id=a>A</p><p id=b>B</p></div>", &h);
    shz_node *d = byid(doc, "d"), *a = byid(doc, "a"), *b = byid(doc, "b"), *c, *frag, *t;
    shz_node *html = shz_doc_element(doc);

    h.len = 0;
    h.log[0] = 0;
    c = mk(doc, "SPAN");
    T_STREQ("createElement lower-cases in an HTML document", U8(((shz_element *)c)->qname), "span");
    T_STREQ("nodeName is upper-case", U8take(shz_node_name(c)), "SPAN");
    T_INTEQ("new element is not connected", shz_in_doc(c), 0);
    T_INTEQ("insertBefore(c, b)", shz_node_insert_before(d, c, b), SHZ_OK);
    T_INTEQ("connected after insertion", shz_in_doc(c), 1);
    T_STREQ("order a c b", U8take(shz_serialize(d, 0)), "<p id=\"a\">A</p><span></span><p id=\"b\">B</p>");
    T_STREQ("node_inserted for the new element", h.log, "+span;");
    T_INTEQ("append moves an attached node", shz_node_append(d, a), SHZ_OK);
    T_STREQ("order c b a", U8take(shz_serialize(d, 0)), "<span></span><p id=\"b\">B</p><p id=\"a\">A</p>");
    T_STREQ("move = removed + inserted (per node)", h.log, "+span;-p;-#text(A);+p;+#text(A);");
    T_INTEQ("insertBefore with ref == child is a no-op", shz_node_insert_before(d, b, b), SHZ_OK);
    T_STREQ("unchanged", U8take(shz_serialize(d, 0)), "<span></span><p id=\"b\">B</p><p id=\"a\">A</p>");

    /* validity (DOM "ensure pre-insertion validity") */
    T_INTEQ("HierarchyRequestError: ancestor into descendant", shz_node_append(a, d), SHZ_E_HIERARCHY);
    T_INTEQ("HierarchyRequestError: into itself", shz_node_append(d, d), SHZ_E_HIERARCHY);
    t = mktext(doc, "x");
    T_INTEQ("HierarchyRequestError: text into the document", shz_node_append(doc->node, t), SHZ_E_HIERARCHY);
    T_INTEQ("HierarchyRequestError: second document element", shz_node_append(doc->node, c), SHZ_E_HIERARCHY);
    T_INTEQ("HierarchyRequestError: child of a text node", shz_node_append(t, c), SHZ_E_HIERARCHY);
    T_INTEQ("NotFoundError: ref is not a child", shz_node_insert_before(d, t, html), SHZ_E_NOT_FOUND);
    T_INTEQ("NotFoundError: removeChild of a non-child", shz_node_remove_child(a, b), SHZ_E_NOT_FOUND);
    T_INTEQ("comment into the document is fine", shz_node_append(doc->node, shz_create_comment(doc, T("z"), 1)), SHZ_OK);
    shz_node_release(doc->node->last_child);   /* the creation reference */
    T_INTEQ("the comment stays (tree-owned)", doc->node->last_child->type, SHZ_COMMENT_NODE);

    /* replaceChild */
    h.len = 0;
    h.log[0] = 0;
    T_INTEQ("replaceChild(t, c)", shz_node_replace_child(d, t, c), SHZ_OK);
    T_STREQ("t replaced c", U8take(shz_serialize(d, 0)), "x<p id=\"b\">B</p><p id=\"a\">A</p>");
    T_STREQ("replace notifications", h.log, "-span;+#text(x);");
    T_INTEQ("replaced node is detached", c->parent == NULL, 1);

    /* fragments */
    frag = shz_create_fragment(doc);
    shz_node_append(frag, mk(doc, "i"));
    shz_node_release(frag->last_child);
    shz_node_append(frag, mk(doc, "u"));
    shz_node_release(frag->last_child);
    h.len = 0;
    h.log[0] = 0;
    T_INTEQ("insert a fragment", shz_node_insert_before(d, frag, b), SHZ_OK);
    T_STREQ("fragment children moved", U8take(shz_serialize(d, 0)), "x<i></i><u></u><p id=\"b\">B</p><p id=\"a\">A</p>");
    T_INTEQ("fragment is empty afterwards", frag->first_child == NULL, 1);
    T_STREQ("fragment insertion notifies each child", h.log, "+i;+u;");

    /* removal notifications cover the whole subtree, in tree order */
    h.len = 0;
    h.log[0] = 0;
    shz_node_addref(d);
    shz_node_remove(d);
    T_STREQ("removed subtree notifications", h.log, "-div;-#text(x);-i;-u;-p;-#text(B);-p;-#text(A);");
    T_INTEQ("removed subtree not connected", shz_in_doc(a), 0);
    shz_node_release(d);

    shz_node_release(frag);
    shz_node_release(t);
    shz_node_release(c);
    shz_doc_release(doc);
}

static void test_lifetime(void)
{
    shz_doc *doc = t_parse("<div id=d><p id=p><b id=b>x</b></p></div>", NULL);
    shz_node *p = byid(doc, "p"), *b = byid(doc, "b"), *d = byid(doc, "d");
    shz_doc *doc2;
    shz_node *n, *x;

    shz_node_addref(b);
    shz_node_remove(p);             /* p: parentless, no reference -> freed; b survives (referenced) */
    T_INTEQ("referenced descendant survives as a detached root", b->parent == NULL, 1);
    T_STREQ("and keeps its children", U8take(shz_node_text_content(b)), "x");
    T_INTEQ("div is empty", d->first_child == NULL, 1);
    shz_node_release(b);            /* frees b and its text */

    /* a node keeps its document alive after the document handle is released */
    n = byid(doc, "d");
    shz_node_addref(n);
    shz_doc_release(doc);
    T_INTEQ("document closed but alive", doc->closed == 2 && doc->refs == 0, 1);
    T_STREQ("node usable", U8take(shz_serialize(n, 1)), "<div id=\"d\"></div>");
    T_INTEQ("node_doc still valid", n->doc == doc, 1);
    shz_node_release(n);            /* frees the document (LeakSanitizer checks) */

    /* adoption: moving a node between documents moves its pin */
    doc = t_parse("<p id=a>a</p>", NULL);
    doc2 = t_parse("<p id=b>b</p>", NULL);
    x = byid(doc, "a");
    shz_node_addref(x);
    T_INTEQ("pins: doc 1, doc2 0", doc->pinned == 1 && doc2->pinned == 0, 1);
    shz_node_append(shz_doc_body(doc2), x);
    T_INTEQ("adopted into doc2", x->doc == doc2 && x->first_child->doc == doc2, 1);
    T_INTEQ("pins moved", doc->pinned == 0 && doc2->pinned == 1, 1);
    T_INTEQ("connected in doc2", shz_in_doc(x), 1);
    T_STREQ("doc2 body", U8take(shz_serialize(shz_doc_body(doc2), 0)), "<p id=\"b\">b</p><p id=\"a\">a</p>");
    shz_doc_release(doc);           /* nothing of doc is referenced: freed now */
    shz_node_release(x);
    shz_doc_release(doc2);
}

static void test_attributes(void)
{
    shz_doc *doc = t_parse("<p id=p Title=T data-x=1>", NULL);
    shz_node *p = byid(doc, "p"), *attr = NULL, *attr2 = NULL;
    shz_element *e = (shz_element *)p;
    T_INTEQ("3 attributes", e->attr_count, 3);
    T_STREQ("names are lower-cased by the parser", U8(e->attrs[1].name), "title");
    T_STREQ("getAttribute is case-insensitive on HTML elements", U8(shz_elem_attr_str(p, T("TITLE"))), "T");
    T_INTEQ("known attribute id", e->attrs[1].id, SHZ_ATTR_TITLE);
    T_INTEQ("setAttribute(new)", shz_elem_set_attr(p, T("Lang"), 4, T("en"), 2), SHZ_OK);
    T_STREQ("stored lower-case", U8(e->attrs[3].name), "lang");
    T_INTEQ("invalid name", shz_elem_set_attr(p, T("a b"), 3, T("x"), 1), SHZ_E_INVALID_CHAR);
    T_INTEQ("Attr node", shz_elem_attr_node(p, T("title"), 5, &attr), SHZ_OK);
    T_INTEQ("Attr identity", shz_elem_attr_node(p, T("title"), 5, &attr2) == SHZ_OK && attr == attr2, 1);
    shz_node_release(attr2);
    T_STREQ("Attr nodeName", U8take(shz_node_name(attr)), "title");
    T_STREQ("Attr value", U8take(shz_node_value(attr)), "T");
    shz_elem_set_attr(p, T("title"), 5, T("T2"), 2);
    T_STREQ("Attr value follows the element", U8take(shz_node_value(attr)), "T2");
    T_INTEQ("Attr node set value changes the attribute", shz_node_set_value(attr, T("T3")), SHZ_OK);
    T_STREQ("element sees it", U8(shz_elem_attr(p, SHZ_ATTR_TITLE)), "T3");
    T_INTEQ("removeAttribute", shz_elem_remove_attr(p, T("title"), 5), SHZ_OK);
    T_INTEQ("removeAttribute again: absent", shz_elem_remove_attr(p, T("title"), 5), SHZ_FALSE);
    T_STREQ("detached Attr keeps the last value", U8take(shz_node_value(attr)), "T3");
    T_INTEQ("Attr compare with its (former) owner: disconnected", (shz_node_compare_position(p, attr) & SHZ_POS_DISCONNECTED) != 0, 1);
    shz_node_release(attr);
    T_INTEQ("absent Attr node", shz_elem_attr_node(p, T("nope"), 4, &attr), SHZ_FALSE);
    shz_doc_release(doc);
}

static void test_lists(void)
{
    shz_doc *doc = t_parse("<form name=f id=f1><input name=q><img name=i src=a.png></form><a href=x name=n>l</a>"
                           "<a name=m>m</a><area href=y><div class='A b'>1</div><div class='b'>2</div><script></script>"
                           "<object></object><embed>", NULL);
    shz_node *body = shz_doc_body(doc), *extra;
    shz_list *all = shz_list_collection(doc, SHZ_COLL_ALL), *forms = shz_list_collection(doc, SHZ_COLL_FORMS);
    shz_list *links = shz_list_collection(doc, SHZ_COLL_LINKS), *anchors = shz_list_collection(doc, SHZ_COLL_ANCHORS);
    shz_list *images = shz_list_collection(doc, SHZ_COLL_IMAGES), *scripts = shz_list_collection(doc, SHZ_COLL_SCRIPTS);
    shz_list *applets = shz_list_collection(doc, SHZ_COLL_APPLETS), *embeds = shz_list_collection(doc, SHZ_COLL_EMBEDS);
    shz_list *divs = shz_list_by(doc->node, 0, NULL, T("DIV")), *cls = shz_list_by(doc->node, 1, NULL, T(" b  A "));
    shz_list *named = shz_list_by(doc->node, 2, NULL, T("q")), *kids = shz_list_children(body);
    shz_list *star = shz_list_by(body, 0, NULL, T("*")), *ns = shz_list_by(doc->node, 3, T("http://www.w3.org/1999/xhtml"), T("a"));

    /* html head body form input img a a area div div script object embed = 14 */
    T_INTEQ("document.all", shz_list_length(all), 14);
    T_INTEQ("forms", shz_list_length(forms), 1);
    T_INTEQ("links: a[href], area[href]", shz_list_length(links), 2);
    T_INTEQ("anchors: a[name]", shz_list_length(anchors), 2);
    T_INTEQ("images", shz_list_length(images), 1);
    T_INTEQ("scripts", shz_list_length(scripts), 1);
    T_INTEQ("applets (object)", shz_list_length(applets), 1);
    T_INTEQ("embeds", shz_list_length(embeds), 1);
    T_INTEQ("getElementsByTagName(DIV) in HTML", shz_list_length(divs), 2);
    T_INTEQ("getElementsByClassName(' b  A ')", shz_list_length(cls), 1);
    T_INTEQ("getElementsByName(q)", shz_list_length(named), 1);
    T_INTEQ("getElementsByTagName(*) below body: 11", shz_list_length(star), 11);
    T_INTEQ("getElementsByTagNameNS(xhtml, a)", shz_list_length(ns), 2);
    T_INTEQ("namedItem by id", shz_list_named_item(forms, T("f1")) == shz_list_item(forms, 0), 1);
    T_INTEQ("namedItem by name", shz_list_named_item(forms, T("f")) == shz_list_item(forms, 0), 1);
    T_INTEQ("namedItem by name on an input", shz_list_named_item(all, T("q")) == shz_list_item(named, 0), 1);
    T_INTEQ("item out of range", shz_list_item(all, 99) == NULL, 1);
    T_INTEQ("childNodes of body", shz_list_length(kids), 9);

    extra = mk(doc, "div");
    shz_elem_set_attr(extra, T("class"), 5, T("a B"), 3);
    shz_node_append(body, extra);
    T_INTEQ("live: divs 3", shz_list_length(divs), 3);
    T_INTEQ("live: all 15", shz_list_length(all), 15);
    T_INTEQ("live: childNodes 10", shz_list_length(kids), 10);
    T_INTEQ("quirks mode (no doctype): class names match ASCII case-insensitively", shz_list_length(cls), 2);
    shz_doc_set_mode(doc, SHZ_MODE_IE8);
    T_INTEQ("standards mode (IE8): class names case-sensitive", shz_list_length(cls), 1);
    shz_doc_set_mode(doc, SHZ_MODE_QUIRKS);
    shz_elem_set_attr(extra, T("class"), 5, T("x"), 1);
    T_INTEQ("live after class change", shz_list_length(cls), 1);
    shz_node_remove(extra);
    T_INTEQ("live after removal", shz_list_length(divs), 2);
    shz_node_release(extra);

    shz_list_release(all); shz_list_release(forms); shz_list_release(links); shz_list_release(anchors);
    shz_list_release(images); shz_list_release(scripts); shz_list_release(applets); shz_list_release(embeds);
    shz_list_release(divs); shz_list_release(cls); shz_list_release(named); shz_list_release(kids);
    shz_list_release(star); shz_list_release(ns);
    shz_doc_release(doc);
}

static void test_positions_and_text(void)
{
    shz_doc *doc = t_parse("<div id=r><p id=a>one <b id=b>two</b></p><p id=c>three</p></div>", NULL);
    shz_node *r = byid(doc, "r"), *a = byid(doc, "a"), *b = byid(doc, "b"), *c = byid(doc, "c"), *tail = NULL, *t;
    shz_node *lone = mk(doc, "i"), *clone = NULL;
    T_INTEQ("a vs b: b contained by a, following", shz_node_compare_position(a, b), SHZ_POS_CONTAINED_BY | SHZ_POS_FOLLOWING);
    T_INTEQ("b vs a: a contains b, preceding", shz_node_compare_position(b, a), SHZ_POS_CONTAINS | SHZ_POS_PRECEDING);
    T_INTEQ("a vs c: following", shz_node_compare_position(a, c), SHZ_POS_FOLLOWING);
    T_INTEQ("c vs b: preceding", shz_node_compare_position(c, b), SHZ_POS_PRECEDING);
    T_INTEQ("same node: 0", shz_node_compare_position(a, a), 0);
    T_INTEQ("disconnected has DISCONNECTED|IMPLEMENTATION_SPECIFIC",
            shz_node_compare_position(a, lone) & (SHZ_POS_DISCONNECTED | SHZ_POS_IMPL_SPECIFIC),
            SHZ_POS_DISCONNECTED | SHZ_POS_IMPL_SPECIFIC);
    T_INTEQ("contains (inclusive)", shz_node_contains(r, b) && shz_node_contains(b, b) && !shz_node_contains(b, r), 1);
    T_STREQ("textContent", U8take(shz_node_text_content(r)), "one twothree");
    T_INTEQ("textContent of the document is null", shz_node_text_content(doc->node) == NULL, 1);

    t = a->first_child;
    T_INTEQ("splitText(2)", shz_text_split(t, 2, &tail), SHZ_OK);
    T_STREQ("head part", U8n(((shz_chardata *)t)->data, ((shz_chardata *)t)->len), "on");
    T_STREQ("tail part", U8n(((shz_chardata *)tail)->data, ((shz_chardata *)tail)->len), "e ");
    T_INTEQ("tail inserted after", t->next_sibling == tail && tail->parent == a, 1);
    T_INTEQ("splitText past the end", shz_text_split(t, 9, &clone), SHZ_E_INDEX_SIZE);
    shz_node_release(tail);

    T_INTEQ("deep clone", shz_node_clone(r, 1, &clone), SHZ_OK);
    T_STREQ("clone serializes the same", U8take(shz_serialize(clone, 1)), U8take(shz_serialize(r, 1)));
    T_INTEQ("clone is detached", clone->parent == NULL && !shz_in_doc(clone), 1);
    shz_node_release(clone);
    T_INTEQ("shallow clone", shz_node_clone(a, 0, &clone), SHZ_OK);
    T_STREQ("shallow clone has attributes, no children", U8take(shz_serialize(clone, 1)), "<p id=\"a\"></p>");
    shz_node_release(clone);

    T_INTEQ("textContent setter", shz_node_set_text_content(a, T("new <text>")), SHZ_OK);
    T_STREQ("replaced children", U8take(shz_serialize(a, 0)), "new &lt;text&gt;");
    T_INTEQ("textContent setter with empty string removes children", shz_node_set_text_content(a, T("")), SHZ_OK);
    T_INTEQ("no children", a->first_child == NULL, 1);
    shz_node_release(lone);
    shz_doc_release(doc);
}

static void test_inner_text(void)
{
    shz_doc *doc = t_parse("<div id=d>  Hello   <b>big</b>\n world <p>para</p><div>block<br>line</div>"
                           "<pre>  keep\n  this </pre><script>no()</script><style>no{}</style>"
                           "<table><tr><td>a</td><td>b</td></tr><tr><td>c</td></tr></table>end</div>", NULL);
    shz_node *d = byid(doc, "d");
    /* CSS white-space processing + HTML innerText: p gives 2 required line breaks, blocks 1, <br> "\n", cells "\t",
     * rows 1, pre kept, display:none content skipped */
    T_STREQ("innerText", U8take(shz_node_inner_text(d)),
            "Hello big world\n\npara\n\nblock\nline\n  keep\n  this \na\tb\nc\nend");
    shz_doc_release(doc);
}

static void test_names_and_misc(void)
{
    shz_doc *doc = t_parse("<!DOCTYPE html><title>  A \n  title </title><base href=\"/root/sub/\"><body>", NULL);
    shz_node *svg = shz_create_element_ns(doc, T("http://www.w3.org/2000/svg"), T("svg:Rect"), 8);
    shz_node *frag = shz_create_fragment(doc), *pi = shz_create_pi(doc, T("xml-stylesheet"), T("a"), 1);
    T_STREQ("document title: stripped and collapsed", U8take(shz_doc_title(doc)), "A title");
    T_STREQ("URL resolution uses <base href>", U8take(shz_doc_resolve_url(doc, T("x.png"))), "http://example.com/root/sub/x.png");
    T_STREQ("nodeName of a namespaced element keeps case", U8take(shz_node_name(svg)), "svg:Rect");
    T_STREQ("localName after the prefix", U8(((shz_element *)svg)->local), "Rect");
    T_STREQ("namespace URI", U8take(shz_elem_namespace(svg)), "http://www.w3.org/2000/svg");
    T_STREQ("#document", U8take(shz_node_name(doc->node)), "#document");
    T_STREQ("#document-fragment", U8take(shz_node_name(frag)), "#document-fragment");
    T_STREQ("doctype name", U8take(shz_node_name(shz_doc_doctype(doc))), "html");
    T_STREQ("PI nodeName is the target", U8take(shz_node_name(pi)), "xml-stylesheet");
    T_INTEQ("doc_set_mode rejects an unknown mode", shz_doc_set_mode(doc, 42), SHZ_E_INVALIDARG);
    T_INTEQ("doctype html: no-quirks", shz_doc_quirks(doc), SHZ_QUIRKS_NONE);
    shz_doc_set_mode(doc, SHZ_MODE_IE5);
    T_INTEQ("IE5 mode: quirks", shz_doc_quirks(doc), SHZ_QUIRKS_FULL);
    shz_doc_set_mode(doc, SHZ_MODE_IE7);
    T_INTEQ("IE7 mode: limited quirks", shz_doc_quirks(doc), SHZ_QUIRKS_LIMITED);
    shz_doc_set_mode(doc, SHZ_MODE_IE11);
    T_INTEQ("IE11 mode: standards", shz_doc_quirks(doc), SHZ_QUIRKS_NONE);
    shz_node_release(svg);
    shz_node_release(frag);
    shz_node_release(pi);
    shz_doc_release(doc);
}

static void test_ranges(void)
{
    shz_doc *doc = t_parse("<p id=p>abc<b>def</b>ghi</p>", NULL);
    shz_node *p = byid(doc, "p"), *t1 = p->first_child, *b = t1->next_sibling, *t3 = b->next_sibling, *tail = NULL;
    shz_range *r = NULL, *sel = NULL;
    T_INTEQ("range_create", shz_range_create(doc, &r), SHZ_OK);
    T_INTEQ("setStart(t1, 1)", shz_range_set(r, 0, t1, 1), SHZ_OK);
    T_INTEQ("setEnd(t3, 2)", shz_range_set(r, 1, t3, 2), SHZ_OK);
    T_STREQ("range text across elements", U8take(shz_range_text(r)), "bcdefgh");
    T_INTEQ("offset past the end", shz_range_set(r, 1, t3, 4), SHZ_E_INDEX_SIZE);
    shz_text_split(t1, 2, &tail);        /* start (t1,1) stays: offset 1 <= 2 */
    T_STREQ("range survives splitText", U8take(shz_range_text(r)), "bcdefgh");
    shz_node_release(tail);
    shz_node_remove(b);                  /* nothing inside b is a boundary */
    T_STREQ("range after removing <b>", U8take(shz_range_text(r)), "bcgh");
    T_INTEQ("selection empty", shz_sel_get(doc, &sel), SHZ_FALSE);
    shz_sel_set(doc, r);
    T_INTEQ("selection set", shz_sel_get(doc, &sel) == SHZ_OK && sel == r, 1);
    shz_range_release(sel);
    shz_range_set(r, 0, t3, 3);          /* start after end: collapses */
    T_INTEQ("collapsed range", r->start == t3 && r->end == t3 && r->start_off == 3 && r->end_off == 3, 1);
    shz_range_release(r);
    shz_doc_release(doc);                /* the selection is released with the document */
}

int main(void)
{
    test_tree_mutation();
    test_lifetime();
    test_attributes();
    test_lists();
    test_positions_and_text();
    test_inner_text();
    test_names_and_misc();
    test_ranges();
    return t_finish("t_dom");
}
