/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: random DOM operation sequences across two documents (insert, remove, replace, fragments, clone,
 * attributes, character data, splitText, textContent, adoption, extra references taken and dropped at random) and
 * random document.write from parser-inserted scripts. After every step the tree invariants must hold (links
 * consistent, SHZ_NF_IN_DOC exactly on connected nodes, owner documents consistent); at the end LeakSanitizer checks
 * that every node and document was freed. DOM errors (HierarchyRequestError, ...) are expected and ignored; crashes,
 * sanitizer reports, broken invariants and leaks are failures.
 */
#include "host_test.h"

static uint32_t rng = 777;

static uint32_t rnd(uint32_t n)
{
    rng = rng * 1103515245u + 12345u;
    return (rng >> 8) % (n ? n : 1);
}

#define MAXH 64
static shz_node *held[MAXH];       /* nodes we hold a reference on */
static int nheld;
static int broken;

static void hold(shz_node *n)
{
    if (!n) return;
    if (nheld == MAXH) {
        int k = (int)rnd(MAXH);
        shz_node_release(held[k]);
        held[k] = n;
        return;
    }
    held[nheld++] = n;
}

static shz_node *any_held(void)
{
    return nheld ? held[rnd((uint32_t)nheld)] : NULL;
}

/* a random node of the tree rooted at root (including root) */
static shz_node *pick(shz_node *root)
{
    shz_node *n, *choice = root;
    uint32_t count = 1;
    for (n = root->first_child; n; n = shz_node_next(n, root)) {
        ++count;
        if (!rnd(count)) choice = n;
    }
    return choice;
}

static void check_tree(shz_node *root, int connected)
{
    shz_node *n;
    for (n = root; n; n = shz_node_next(n, root)) {
        shz_node *c, *prev = NULL;
        if (!!(n->flags & SHZ_NF_IN_DOC) != connected) broken |= 1;
        if (n->doc != root->doc) broken |= 2;
        for (c = n->first_child; c; c = c->next_sibling) {
            if (c->parent != n || c->prev_sibling != prev) broken |= 4;
            prev = c;
        }
        if (n->last_child != prev) broken |= 8;
    }
}

static void check_held(void)
{
    int i;
    for (i = 0; i < nheld; ++i) {
        shz_node *r = shz_node_root(held[i]);
        if (held[i]->refs == 0) broken |= 16;
        check_tree(r, r->type == SHZ_DOCUMENT_NODE && r == r->doc->node);
    }
}

static void step(shz_doc *docs[2])
{
    shz_doc *d = docs[rnd(2)];
    shz_node *a = rnd(3) ? pick(d->node) : any_held(), *b = rnd(2) ? pick(docs[rnd(2)]->node) : any_held(), *n = NULL;
    static const char *const tags[] = { "div", "p", "b", "table", "tr", "td", "script", "title", "svg", "select" };
    if (!a) a = d->node;
    if (!b) b = d->node;
    /* like a real host, hold references on the nodes an operation is given */
    shz_node_addref(a);
    shz_node_addref(b);
    switch (rnd(14)) {
    case 0: { const char *tag = tags[rnd(10)]; n = shz_create_element(d, T(tag), strlen(tag)); break; }
    case 1: n = shz_create_text(d, T("txt"), 3); break;
    case 2: n = shz_create_comment(d, T("c"), 1); break;
    case 3: n = shz_create_fragment(d); break;
    case 4: shz_node_insert_before(a, b, rnd(2) ? a->first_child : NULL); break;
    case 5: if (b->parent) shz_node_remove_child(b->parent, b); break;
    case 6: if (a->first_child) shz_node_replace_child(a, b, a->first_child); break;
    case 7: shz_node_clone(a, (int)rnd(2), &n); break;
    case 8: if (a->type == SHZ_ELEMENT_NODE) shz_elem_set_attr(a, T("id"), 2, T("x"), 1);
            else if (shz_is_chardata(a)) shz_chardata_append(a, T("+"), 1);
            break;
    case 9: if (a->type == SHZ_ELEMENT_NODE) shz_elem_remove_attr(a, T("id"), 2); break;
    case 10: if (shz_is_text(a)) { shz_node *tail = NULL; shz_text_split(a, rnd(4), &tail); n = tail; } break;
    case 11: if (a != d->node && a->type == SHZ_ELEMENT_NODE) shz_node_set_text_content(a, T("t"));
             break;
    case 12: if (a->type == SHZ_ELEMENT_NODE) shz_elem_attr_node(a, T("id"), 2, &n); break;
    case 13:
        if (nheld) {
            int k = (int)rnd((uint32_t)nheld);
            shz_node_release(held[k]);
            held[k] = held[--nheld];
        }
        break;
    }
    if (n) hold(n);
    if (rnd(4) == 0 && a != a->doc->node) { shz_node_addref(a); hold(a); }
    shz_node_release(b);
    shz_node_release(a);
    check_tree(docs[0]->node, 1);
    check_tree(docs[1]->node, 1);
    check_held();
}

/* ---- document.write fuzz */
static const char *const soup[] = {
    "<p>", "</p>", "<b>", "</b>", "<table>", "<td>", "x", "<script>w</script>", "<div>", "</div>", "<!--", "-->",
    "<select><option>", "<svg>", "<title>", "</title>", "&amp", "<", "</", "<br>", "<li>", "\n",
};
static int writes;

static void on_script(t_host *h, shz_doc *doc, shz_node *script, int parser_inserted)
{
    char buf[256];
    size_t len = 0;
    int i, n = 1 + (int)rnd(6);
    (void)h;
    (void)script;
    (void)parser_inserted;
    if (++writes > 400) return;           /* bound the recursion of scripts that write scripts */
    for (i = 0; i < n; ++i) {
        const char *s = soup[rnd(sizeof(soup) / sizeof(soup[0]))];
        size_t sl = strlen(s);
        if (len + sl >= sizeof(buf)) break;
        memcpy(buf + len, s, sl);
        len += sl;
    }
    buf[len] = 0;
    {
        const shz_char *w = T(buf);
        shz_doc_write(doc, w, shz_strlen(w), (int)rnd(2));
    }
}

int main(void)
{
    int round, i, rounds = 3000;
    /* SHZ_FUZZ_ITER (x200 / x300 rounds) and SHZ_FUZZ_SEED widen a local run; the defaults are what the suite checks */
    if (getenv("SHZ_FUZZ_ITER")) rounds = atoi(getenv("SHZ_FUZZ_ITER"));
    if (getenv("SHZ_FUZZ_SEED")) rng = (uint32_t)atoi(getenv("SHZ_FUZZ_SEED"));
    for (round = 0; round < rounds; ++round) {
        shz_doc *docs[2];
        docs[0] = t_parse("<div><p>a</p><b>b</b></div><table><tr><td>1</table>", NULL);
        docs[1] = t_parse("<ul><li>x<li>y</ul>", NULL);
        for (i = 0; i < 60; ++i) step(docs);
        /* drop everything in random order */
        if (rnd(2)) {
            shz_doc_release(docs[0]);
            shz_doc_release(docs[1]);
            while (nheld) shz_node_release(held[--nheld]);
        } else {
            while (nheld) shz_node_release(held[--nheld]);
            shz_doc_release(docs[1]);
            shz_doc_release(docs[0]);
        }
        if ((round & 31) == 31) {
            size_t k;
            for (k = 0; k < t_pool_n; ++k) shz_free(t_pool[k]);
            t_pool_n = 0;
        }
    }
    T_INTEQ("tree invariants held through the random DOM operations", broken, 0);

    for (round = 0; round < rounds * 3 / 2; ++round) {
        t_host h;
        shz_doc *doc;
        char html[512];
        size_t len = 0;
        int n = 1 + (int)rnd(12);
        memset(&h, 0, sizeof(h));
        doc = t_new_doc(&h);
        h.on_script = on_script;
        writes = 0;
        for (i = 0; i < n; ++i) {
            const char *s = soup[rnd(sizeof(soup) / sizeof(soup[0]))];
            size_t sl = strlen(s);
            if (len + sl >= sizeof(html)) break;
            memcpy(html + len, s, sl);
            len += sl;
        }
        html[len] = 0;
        {
            const shz_char *w = T(html);
            shz_doc_load_string(doc, w, shz_strlen(w));
        }
        check_tree(doc->node, 1);
        if (h.parse_done != 1) broken |= 32;
        shz_doc_release(doc);
        if ((round & 31) == 31) {
            size_t k;
            for (k = 0; k < t_pool_n; ++k) shz_free(t_pool[k]);
            t_pool_n = 0;
        }
    }
    T_INTEQ("document.write from scripts: invariants and one parse_done per load", broken, 0);
    return t_finish("t_fuzz_dom");
}
