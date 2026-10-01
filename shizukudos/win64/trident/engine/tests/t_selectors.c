/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: selectors. Expected values: Selectors Level 3 (grammar, section 9 specificity examples, :nth-child
 * an+b semantics, attribute operators), HTML (case-insensitive attribute values of the legacy list, quirks-mode class
 * and id matching, :link/:checked/:disabled definitions) and DOM querySelector (tree order, root excluded).
 */
#include "host_test.h"
#include "../core/selectors.h"

static shz_doc *doc;

/* ids of the elements querySelectorAll(sel) returns, space separated */
static const char *qsa(const char *sel)
{
    static char buf[512];
    shz_list *l = NULL;
    uint32_t i, n;
    size_t len = 0;
    shz_res hr = shz_query_selector_all(doc->node, T(sel), &l);
    buf[0] = 0;
    if (SHZ_FAILED(hr)) return "SYNTAX";
    n = shz_list_length(l);
    for (i = 0; i < n; ++i) {
        shz_node *e = shz_list_item(l, i);
        const shz_char *id = shz_elem_attr(e, SHZ_ATTR_ID);
        const char *s = id ? U8(id) : U8(((shz_element *)e)->qname);
        len += (size_t)snprintf(buf + len, sizeof(buf) - len, "%s%s", i ? " " : "", s);
    }
    shz_list_release(l);
    return t_strdup(buf);
}

static void q(const char *sel, const char *expected)
{
    char name[256];
    snprintf(name, sizeof(name), "querySelectorAll(%s)", sel);
    T_STREQ(name, qsa(sel), expected);
}

static uint32_t spec(const char *sel)
{
    shz_selector_list *l = NULL;
    uint32_t s;
    if (SHZ_FAILED(shz_selector_parse(T(sel), strlen(sel), &l))) return 0xFFFFFFFF;
    s = shz_selector_specificity(l, 0);
    shz_selector_free(l);
    return s;
}

int main(void)
{
    shz_node *p1, *ul;
    shz_selector_list *l = NULL;
    int r = 0;
    doc = t_parse("<!DOCTYPE html><div id=root>"
                  "<ul id=list><li id=l1 class=\"red level\">1<li id=l2 lang=en-US>2<li id=l3 class=red>3<li id=l4>4</ul>"
                  "<p id=p1 title=\"hello world\" data-x=\"abc-def\">p1</p><p id=p2>p2</p>"
                  "<a id=a1 href=\"http://x/y.html\">a</a> <a id=a2 name=n>b</a>"
                  "<input id=i1 type=checkbox checked> <input id=i2 type=text disabled> <input id=i3 TYPE=CHECKBOX>"
                  "<span id=empty></span><fieldset id=fs disabled><legend><input id=i4></legend><input id=i5></fieldset>"
                  "</div>", NULL);

    /* Selectors Level 3, 9. Calculating a selector's specificity */
    T_INTEQ("specificity *", spec("*"), 0);
    T_INTEQ("specificity LI", spec("LI"), 1);
    T_INTEQ("specificity UL LI", spec("UL LI"), 2);
    T_INTEQ("specificity UL OL+LI", spec("UL OL+LI"), 3);
    T_INTEQ("specificity H1 + *[REL=up]", spec("H1 + *[REL=up]"), 0x101);
    T_INTEQ("specificity UL OL LI.red", spec("UL OL LI.red"), 0x103);
    T_INTEQ("specificity LI.red.level", spec("LI.red.level"), 0x201);
    T_INTEQ("specificity #x34y", spec("#x34y"), 0x10000);
    T_INTEQ("specificity #s12:not(FOO)", spec("#s12:not(FOO)"), 0x10001);
    T_INTEQ("specificity p::before (pseudo-element counts as a type)", spec("p::before"), 2);
    T_INTEQ("specificity a:hover", spec("a:hover"), 0x101);

    q("li", "l1 l2 l3 l4");
    q("LI", "l1 l2 l3 l4");
    q("ul > li:first-child", "l1");
    q("li:last-child", "l4");
    q("li:nth-child(2n+1)", "l1 l3");
    q("li:nth-child(odd)", "l1 l3");
    q("li:nth-child(even)", "l2 l4");
    q("li:nth-child(-n+2)", "l1 l2");
    q("li:nth-child(3)", "l3");
    q("li:nth-last-child(1)", "l4");
    q("li:nth-of-type(3)", "l3");
    q("p:first-of-type", "p1");
    q("p:last-of-type", "p2");
    q(".red", "l1 l3");
    q(".red.level", "l1");
    q("li:not(.red)", "l2 l4");
    q("li:not(.red, #l4)", "l2");
    q("[title]", "p1");
    q("[title=\"hello world\"]", "p1");
    q("[title~=world]", "p1");
    q("[title~=wor]", "");
    q("[data-x|=abc]", "p1");
    q("[title^=hel]", "p1");
    q("[title$=rld]", "p1");
    q("[title*=\"o w\"]", "p1");
    q("[title=\"HELLO WORLD\" i]", "p1");
    q("[lang|=en]", "l2");
    q(":lang(en)", "l2");
    q("input[type=checkbox]", "i1 i3");
    q("p + p", "p2");
    q("p ~ a", "a1 a2");
    q("#root p", "p1 p2");
    q("div > p", "p1 p2");
    q("ul p", "");
    q("ul > li + li ~ li", "l3 l4");
    q(":link", "a1");
    q("a:any-link", "a1");
    q(":checked", "i1");
    q("input:disabled", "i2 i5");
    q("input:enabled", "i1 i3 i4");
    q("span:empty", "empty");
    q(":root", "html");
    q("#p1, #l1", "l1 p1");
    q("p::before", "");
    q("*|p", "p1 p2");
    q("#ROOT", "");
    q("", "SYNTAX");
    q("a >", "SYNTAX");
    q("..x", "SYNTAX");
    q("[x", "SYNTAX");
    q(":nosuch", "SYNTAX");
    q("a::before b", "SYNTAX");
    q("p:nth-child(x)", "SYNTAX");
    q("p,", "SYNTAX");

    p1 = shz_doc_get_element_by_id(doc, T("p1"));
    ul = shz_doc_get_element_by_id(doc, T("list"));
    T_INTEQ("matches(p1, div p)", shz_element_matches(p1, T("div p"), &r) == SHZ_OK && r, 1);
    T_INTEQ("matches(ul, #root > ul)", shz_element_matches(ul, T("#root > ul"), &r) == SHZ_OK && r, 1);
    T_INTEQ("matches(ul, li)", shz_element_matches(ul, T("li"), &r) == SHZ_OK && !r, 1);
    T_INTEQ("matches with a syntax error", shz_element_matches(ul, T("<"), &r), SHZ_E_SYNTAX);
    T_INTEQ("querySelector returns the first in tree order", shz_query_selector(doc->node, T("p, li"), &p1) == SHZ_OK
            && p1 == shz_doc_get_element_by_id(doc, T("l1")), 1);

    T_INTEQ("parse a list", shz_selector_parse(T("  ul   >  li.red ,a:hover"), 25, &l), SHZ_OK);
    T_INTEQ("two selectors", shz_selector_count(l), 2);
    T_STREQ("selectorText normalized", U8take(shz_selector_list_text(l)), "ul > li.red, a:hover");
    shz_selector_free(l);
    shz_doc_release(doc);

    /* quirks mode: class and id selectors ASCII case-insensitive */
    doc = t_parse("<p id=Foo class=Bar>x</p>", NULL);
    q(".bar", "Foo");
    q("#FOO", "Foo");
    shz_doc_set_mode(doc, SHZ_MODE_IE8);
    q(".bar", "");
    q(".Bar", "Foo");
    shz_doc_release(doc);
    return t_finish("t_selectors");
}
