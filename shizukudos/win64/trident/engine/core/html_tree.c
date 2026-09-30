/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - HTML tree builder (a simplified WHATWG HTML 13.2.6 "tree construction").
 *
 * Implemented as the specification describes: every insertion mode except "in template" and "in head noscript"
 * (<template> is an ordinary element; scripting is always on, so <noscript> is raw text), the stack of open elements
 * with the element scopes, the list of active formatting elements with reconstruction, the Noah's Ark clause and the
 * adoption agency algorithm, foster parenting for misplaced table content, implied end tags, <frameset>, quirks
 * detection from the DOCTYPE, the fragment case (context element), and SVG/MathML subtrees in their namespaces with the
 * HTML break-out rule (element and attribute names are not case-adjusted). Parse errors are not reported.
 */
#include "html_int.h"
#include "observe.h"

enum { SCOPE_DEFAULT, SCOPE_LIST_ITEM, SCOPE_BUTTON, SCOPE_TABLE, SCOPE_SELECT };

static void process(shz_parser *p, token *t, int mode);
static void process_mode(shz_parser *p, token *t, int mode);

/* ---------------------------------------------------------------------------------------------------- helpers */

static shz_node *cur(shz_parser *p)
{
    return p->stack.len ? p->stack.items[p->stack.len - 1] : NULL;
}

static shz_node *adjusted_cur(shz_parser *p)
{
    if (p->fragment && p->stack.len == 1) return p->context;
    return cur(p);
}

static int tag_of(shz_node *n)
{
    return shz_tag_of(n);
}

static int is_html_elem(shz_node *n)
{
    return n && n->type == SHZ_ELEMENT_NODE && ((shz_element *)n)->ns == SHZ_NS_HTML;
}

static int cur_is(shz_parser *p, int tag)
{
    return shz_is_tag(cur(p), tag);
}

static int cur_is_any(shz_parser *p, const int *tags)
{
    int tg = tag_of(cur(p));
    if (!tg) return 0;
    for (; *tags; ++tags)
        if (*tags == tg) return 1;
    return 0;
}

static int tag_in(int tag, const int *tags)
{
    if (!tag) return 0;
    for (; *tags; ++tags)
        if (*tags == tag) return 1;
    return 0;
}

static void push(shz_parser *p, shz_node *n)
{
    if (shz_vec_push(&p->stack, n)) shz_node_addref(n);
    if (shz_is_tag(n, SHZ_TAG_TITLE) && !p->fragment) p->title_open = 1;
}

static void title_closed(shz_parser *p, shz_node *n)
{
    shz_doc *doc = p->doc;
    if (!shz_is_tag(n, SHZ_TAG_TITLE) || p->fragment) return;
    p->title_open = 0;
    if (shz_in_doc(n) && doc->hooks && doc->hooks->title_changed) doc->hooks->title_changed(doc->hooks_ctx, doc);
}

static void pop(shz_parser *p)
{
    shz_node *n;
    if (!p->stack.len) return;
    n = p->stack.items[--p->stack.len];
    title_closed(p, n);
    shz_node_release(n);
}

static void remove_from_stack(shz_parser *p, shz_node *n)
{
    size_t i = shz_vec_index(&p->stack, n);
    if (i == (size_t)-1) return;
    shz_vec_remove_at(&p->stack, i);
    title_closed(p, n);
    shz_node_release(n);
}

static int in_stack(shz_parser *p, shz_node *n)
{
    return shz_vec_index(&p->stack, n) != (size_t)-1;
}

static void pop_until_tag(shz_parser *p, int tag)
{
    while (p->stack.len) {
        int done = cur_is(p, tag);
        pop(p);
        if (done) break;
    }
}

static void pop_until_node(shz_parser *p, shz_node *n)
{
    while (p->stack.len) {
        int done = cur(p) == n;
        pop(p);
        if (done) break;
    }
}

static int is_scope_boundary(shz_node *n, int scope)
{
    shz_element *e = shz_elem(n);
    if (!e) return 0;
    if (scope == SCOPE_SELECT) return !(shz_is_tag(n, SHZ_TAG_OPTGROUP) || shz_is_tag(n, SHZ_TAG_OPTION));
    if (e->ns == SHZ_NS_HTML) {
        switch (e->tag) {
        case SHZ_TAG_HTML: case SHZ_TAG_TABLE: case SHZ_TAG_TEMPLATE:
            return 1;
        case SHZ_TAG_APPLET: case SHZ_TAG_CAPTION: case SHZ_TAG_TD: case SHZ_TAG_TH: case SHZ_TAG_MARQUEE:
        case SHZ_TAG_OBJECT:
            return scope != SCOPE_TABLE;
        case SHZ_TAG_OL: case SHZ_TAG_UL:
            return scope == SCOPE_LIST_ITEM;
        case SHZ_TAG_BUTTON:
            return scope == SCOPE_BUTTON;
        default:
            return 0;
        }
    }
    if (scope == SCOPE_TABLE) return 0;
    if (e->ns == SHZ_NS_MATHML)
        return shz_streq_ascii(e->local, "mi") || shz_streq_ascii(e->local, "mo") || shz_streq_ascii(e->local, "mn")
               || shz_streq_ascii(e->local, "ms") || shz_streq_ascii(e->local, "mtext")
               || shz_streq_ascii(e->local, "annotation-xml");
    if (e->ns == SHZ_NS_SVG)
        return shz_strieq_ascii(e->local, "foreignobject") || shz_streq_ascii(e->local, "desc")
               || shz_streq_ascii(e->local, "title");
    return 0;
}

static int in_scope(shz_parser *p, int tag, int scope)
{
    size_t i = p->stack.len;
    while (i--) {
        shz_node *n = p->stack.items[i];
        if (shz_is_tag(n, tag)) return 1;
        if (is_scope_boundary(n, scope)) return 0;
    }
    return 0;
}

static int node_in_scope(shz_parser *p, shz_node *target, int scope)
{
    size_t i = p->stack.len;
    while (i--) {
        shz_node *n = p->stack.items[i];
        if (n == target) return 1;
        if (is_scope_boundary(n, scope)) return 0;
    }
    return 0;
}

static int heading_in_scope(shz_parser *p)
{
    size_t i = p->stack.len;
    while (i--) {
        shz_node *n = p->stack.items[i];
        if (is_html_elem(n) && (shz_tag_flags(tag_of(n)) & SHZ_TF_HEADING)) return 1;
        if (is_scope_boundary(n, SCOPE_DEFAULT)) return 0;
    }
    return 0;
}

static void generate_implied_end_tags(shz_parser *p, int except)
{
    static const int implied[] = { SHZ_TAG_DD, SHZ_TAG_DT, SHZ_TAG_LI, SHZ_TAG_OPTGROUP, SHZ_TAG_OPTION, SHZ_TAG_P,
                                   SHZ_TAG_RB, SHZ_TAG_RP, SHZ_TAG_RT, SHZ_TAG_RTC, 0 };
    while (cur_is_any(p, implied) && !cur_is(p, except)) pop(p);
}

static void close_p(shz_parser *p)
{
    generate_implied_end_tags(p, SHZ_TAG_P);
    pop_until_tag(p, SHZ_TAG_P);
}

/* ---------------------------------------------------------------------------------------------------- insertion */

static void insert_location(shz_parser *p, shz_node *override, shz_node **parent, shz_node **before)
{
    shz_node *target = override ? override : cur(p);
    *before = NULL;
    if (!target) target = p->fragment ? p->root : p->doc->node;
    if (p->foster && (shz_is_tag(target, SHZ_TAG_TABLE) || shz_is_tag(target, SHZ_TAG_TBODY)
                      || shz_is_tag(target, SHZ_TAG_TFOOT) || shz_is_tag(target, SHZ_TAG_THEAD)
                      || shz_is_tag(target, SHZ_TAG_TR))) {
        size_t i = p->stack.len;
        while (i--) {
            shz_node *n = p->stack.items[i];
            if (shz_is_tag(n, SHZ_TAG_TABLE)) {
                if (n->parent) {
                    *parent = n->parent;
                    *before = n;
                } else {
                    *parent = i ? p->stack.items[i - 1] : n;
                }
                return;
            }
        }
        *parent = p->stack.len ? p->stack.items[0] : target;
        return;
    }
    *parent = target;
}

static shz_node *create_for_token(shz_parser *p, token *t, int ns)
{
    shz_node *n;
    size_t i;
    if (ns == SHZ_NS_HTML && !p->xml) n = shz_create_element_in(p->doc, SHZ_NS_HTML, t->name.s, t->name.len);
    else n = shz_create_element_in(p->doc, ns, t->name.s, t->name.len);
    if (!n) return NULL;
    for (i = 0; i < t->nattrs; ++i) {
        tok_attr *a = &t->attrs[i];
        if (a->dup || !a->name.len) continue;
        shz_elem_add_attr_raw(n, a->name.s, a->name.len, a->value.s ? a->value.s : a->name.s, a->value.len);
    }
    n->flags |= SHZ_NF_CREATED_BY_PARSER;
    if (shz_is_tag(n, SHZ_TAG_SCRIPT)) {
        if (p->fragment) n->flags |= SHZ_NF_STARTED;
        else n->flags |= SHZ_NF_PARSER_INSERTED;
    }
    return n;
}

static void insert_node_at(shz_parser *p, shz_node *n, shz_node *override)
{
    shz_node *parent, *before;
    insert_location(p, override, &parent, &before);
    shz_dom_insert_raw(parent, n, before);
}

/* insert an element for the token and push it; returns it (reference owned by the stack) */
static shz_node *insert_element_ns(shz_parser *p, token *t, int ns)
{
    shz_node *n = create_for_token(p, t, ns);
    if (!n) return NULL;
    if (shz_is_tag(n, SHZ_TAG_TITLE) && !p->fragment) p->title_open = 1;    /* reported once, at </title> */
    insert_node_at(p, n, NULL);
    push(p, n);
    shz_node_release(n);
    return n;
}

static shz_node *insert_element(shz_parser *p, token *t)
{
    return insert_element_ns(p, t, SHZ_NS_HTML);
}

static void insert_void(shz_parser *p, token *t)
{
    if (insert_element(p, t)) pop(p);
}

static shz_node *insert_tag(shz_parser *p, int tag)
{
    shz_node *n = shz_create_element_tag(p->doc, tag);
    if (!n) return NULL;
    n->flags |= SHZ_NF_CREATED_BY_PARSER;
    insert_node_at(p, n, NULL);
    push(p, n);
    shz_node_release(n);
    return n;
}

static void insert_chars(shz_parser *p, const shz_char *s, size_t n)
{
    shz_node *parent, *before, *prev;
    if (!n) return;
    insert_location(p, NULL, &parent, &before);
    if (parent->type == SHZ_DOCUMENT_NODE) return;
    prev = before ? before->prev_sibling : parent->last_child;
    if (prev && prev->type == SHZ_TEXT_NODE) {
        shz_chardata_append(prev, s, n);
    } else {
        shz_node *text = shz_create_text(p->doc, s, n);
        if (!text) return;
        shz_dom_insert_raw(parent, text, before);
        shz_node_release(text);
    }
}

static void insert_comment(shz_parser *p, token *t, shz_node *parent)
{
    shz_node *c = shz_create_comment(p->doc, t->data.s, t->data.len);
    if (!c) return;
    if (parent) shz_dom_insert_raw(parent, c, NULL);
    else insert_node_at(p, c, NULL);
    shz_node_release(c);
}

/* ---------------------------------------------------------------------------------------------------- formatting */

static void fmt_push_marker(shz_parser *p)
{
    shz_vec_push(&p->fmt, NULL);
}

static void fmt_clear_to_marker(shz_parser *p)
{
    while (p->fmt.len) {
        shz_node *n = p->fmt.items[--p->fmt.len];
        if (!n) break;
        shz_node_release(n);
    }
}

static size_t fmt_index(shz_parser *p, shz_node *n)
{
    return shz_vec_index(&p->fmt, n);
}

static void fmt_remove(shz_parser *p, shz_node *n)
{
    size_t i = fmt_index(p, n);
    if (i == (size_t)-1 || !n) return;
    shz_vec_remove_at(&p->fmt, i);
    shz_node_release(n);
}

static int same_attrs(shz_node *a, shz_node *b)
{
    shz_element *ea = (shz_element *)a, *eb = (shz_element *)b;
    uint32_t i;
    if (ea->attr_count != eb->attr_count) return 0;
    for (i = 0; i < ea->attr_count; ++i) {
        shz_attr *x = shz_elem_find_attr(b, ea->attrs[i].name, shz_strlen(ea->attrs[i].name));
        if (!x || !shz_streq(x->value, ea->attrs[i].value)) return 0;
    }
    return 1;
}

static void fmt_push(shz_parser *p, shz_node *n)
{
    size_t i = p->fmt.len, count = 0, earliest = (size_t)-1;
    /* Noah's Ark: at most three identical entries after the last marker */
    while (i--) {
        shz_node *e = p->fmt.items[i];
        if (!e) break;
        if (tag_of(e) == tag_of(n) && ((shz_element *)e)->ns == ((shz_element *)n)->ns
            && shz_streq(((shz_element *)e)->qname, ((shz_element *)n)->qname) && same_attrs(e, n)) {
            ++count;
            earliest = i;
        }
    }
    if (count >= 3) {
        shz_node *e = p->fmt.items[earliest];
        shz_vec_remove_at(&p->fmt, earliest);
        shz_node_release(e);
    }
    if (shz_vec_push(&p->fmt, n)) shz_node_addref(n);
}

static shz_node *clone_element(shz_parser *p, shz_node *src)
{
    shz_element *e = (shz_element *)src;
    shz_node *n = shz_create_element_in(p->doc, e->ns, e->qname, e->qname_len);
    uint32_t i;
    if (!n) return NULL;
    for (i = 0; i < e->attr_count; ++i)
        shz_elem_add_attr_raw(n, e->attrs[i].name, shz_strlen(e->attrs[i].name), e->attrs[i].value, e->attrs[i].value_len);
    n->flags |= SHZ_NF_CREATED_BY_PARSER;
    return n;
}

static void reconstruct_formatting(shz_parser *p)
{
    size_t i;
    if (!p->fmt.len) return;
    i = p->fmt.len - 1;
    if (!p->fmt.items[i] || in_stack(p, p->fmt.items[i])) return;
    while (i > 0) {
        shz_node *e = p->fmt.items[i - 1];
        if (!e || in_stack(p, e)) break;
        --i;
    }
    for (; i < p->fmt.len; ++i) {
        shz_node *old = p->fmt.items[i], *n = clone_element(p, old);
        if (!n) return;
        insert_node_at(p, n, NULL);
        push(p, n);
        p->fmt.items[i] = n;          /* the list keeps the creation reference */
        shz_node_release(old);
    }
}

/* returns 1 when the token must be handled as "any other end tag" */
static int adoption_agency(shz_parser *p, token *t)
{
    int subject = t->tag, outer;
    shz_node *c = cur(p);
    if (shz_is_tag(c, subject) && fmt_index(p, c) == (size_t)-1) {
        pop(p);
        return 0;
    }
    for (outer = 0; outer < 8; ++outer) {
        shz_node *fe = NULL, *fb = NULL, *ca, *node, *last, *ne;
        size_t i, fe_idx, fb_idx, bookmark, node_idx;
        int inner;
        i = p->fmt.len;
        while (i--) {
            shz_node *e = p->fmt.items[i];
            if (!e) break;
            if (shz_is_tag(e, subject)) { fe = e; break; }
        }
        if (!fe) return 1;
        fe_idx = shz_vec_index(&p->stack, fe);
        if (fe_idx == (size_t)-1) { fmt_remove(p, fe); return 0; }
        if (!node_in_scope(p, fe, SCOPE_DEFAULT)) return 0;
        for (i = fe_idx + 1; i < p->stack.len; ++i) {
            shz_node *n = p->stack.items[i];
            if (is_html_elem(n) ? (shz_tag_flags(tag_of(n)) & SHZ_TF_SPECIAL) != 0 : is_scope_boundary(n, SCOPE_DEFAULT)) {
                fb = n;
                break;
            }
        }
        if (!fb) {
            pop_until_node(p, fe);
            fmt_remove(p, fe);
            return 0;
        }
        shz_node_addref(fe);
        shz_node_addref(fb);
        ca = p->stack.items[fe_idx - (fe_idx ? 1 : 0)];
        shz_node_addref(ca);
        bookmark = fmt_index(p, fe);
        node_idx = shz_vec_index(&p->stack, fb);
        last = fb;
        shz_node_addref(last);
        for (inner = 1;; ++inner) {
            size_t fmt_i;
            shz_node *nn;
            --node_idx;
            node = p->stack.items[node_idx];
            if (node == fe) break;
            fmt_i = fmt_index(p, node);
            if (inner > 3 && fmt_i != (size_t)-1) {
                if (fmt_i < bookmark) --bookmark;
                fmt_remove(p, node);
                fmt_i = (size_t)-1;
            }
            if (fmt_i == (size_t)-1) {
                shz_vec_remove_at(&p->stack, node_idx);
                title_closed(p, node);
                shz_node_release(node);
                continue;
            }
            nn = clone_element(p, node);
            if (!nn) break;
            /* replace node by nn in both lists (the lists hold one reference each) */
            p->fmt.items[fmt_i] = nn;
            shz_node_addref(nn);
            shz_node_release(node);
            p->stack.items[node_idx] = nn;          /* takes the creation reference */
            shz_node_release(node);
            node = nn;
            if (last == fb) bookmark = fmt_i + 1;
            shz_dom_insert_raw(node, last, NULL);
            shz_node_release(last);
            last = node;
            shz_node_addref(last);
        }
        /* insert last at the appropriate place for common ancestor ca */
        {
            shz_node *parent, *before;
            insert_location(p, ca, &parent, &before);
            shz_dom_insert_raw(parent, last, before);
        }
        shz_node_release(last);
        ne = clone_element(p, fe);
        if (ne) {
            while (fb->first_child) shz_dom_insert_raw(ne, fb->first_child, NULL);
            shz_dom_insert_raw(fb, ne, NULL);
            /* formatting list: replace fe by ne at the bookmark */
            i = fmt_index(p, fe);
            if (i != (size_t)-1) {
                shz_vec_remove_at(&p->fmt, i);
                if (i < bookmark) --bookmark;
                shz_node_release(fe);
            }
            if (bookmark > p->fmt.len) bookmark = p->fmt.len;
            shz_vec_insert(&p->fmt, bookmark, ne);
            shz_node_addref(ne);
            /* stack: remove fe, insert ne right after fb */
            remove_from_stack(p, fe);
            fb_idx = shz_vec_index(&p->stack, fb);
            if (fb_idx != (size_t)-1) {
                shz_vec_insert(&p->stack, fb_idx + 1, ne);
                shz_node_addref(ne);
            }
            shz_node_release(ne);
        }
        shz_node_release(ca);
        shz_node_release(fb);
        shz_node_release(fe);
    }
    return 0;
}

/* ---------------------------------------------------------------------------------------------------- modes */

static void reset_insertion_mode(shz_parser *p)
{
    size_t i = p->stack.len;
    while (i--) {
        shz_node *n = p->stack.items[i];
        int last = i == 0;
        if (last && p->fragment && p->context) n = p->context;
        switch (tag_of(n)) {
        case SHZ_TAG_SELECT: {
            size_t j = i;
            if (!last) {
                while (j--) {
                    shz_node *a = p->stack.items[j];
                    if (shz_is_tag(a, SHZ_TAG_TEMPLATE)) break;
                    if (shz_is_tag(a, SHZ_TAG_TABLE)) { p->mode = IM_IN_SELECT_IN_TABLE; return; }
                }
            }
            p->mode = IM_IN_SELECT;
            return;
        }
        case SHZ_TAG_TD: case SHZ_TAG_TH:
            if (!last) { p->mode = IM_IN_CELL; return; }
            break;
        case SHZ_TAG_TR: p->mode = IM_IN_ROW; return;
        case SHZ_TAG_TBODY: case SHZ_TAG_THEAD: case SHZ_TAG_TFOOT: p->mode = IM_IN_TABLE_BODY; return;
        case SHZ_TAG_CAPTION: p->mode = IM_IN_CAPTION; return;
        case SHZ_TAG_COLGROUP: p->mode = IM_IN_COLUMN_GROUP; return;
        case SHZ_TAG_TABLE: p->mode = IM_IN_TABLE; return;
        case SHZ_TAG_TEMPLATE: p->mode = IM_IN_BODY; return;
        case SHZ_TAG_HEAD:
            if (!last) { p->mode = IM_IN_HEAD; return; }
            break;
        case SHZ_TAG_BODY: p->mode = IM_IN_BODY; return;
        case SHZ_TAG_FRAMESET: p->mode = IM_IN_FRAMESET; return;
        case SHZ_TAG_HTML: p->mode = p->head ? IM_AFTER_HEAD : IM_BEFORE_HEAD; return;
        default: break;
        }
        if (last) { p->mode = IM_IN_BODY; return; }
    }
    p->mode = IM_IN_BODY;
}

static void generic_text(shz_parser *p, token *t, int state)
{
    insert_element(p, t);
    p->state = state;
    p->orig_mode = p->mode;
    p->mode = IM_TEXT;
}

static int is_ws(shz_char c)
{
    return c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' ';
}

static size_t leading_ws(const token *t)
{
    size_t i = 0;
    while (i < t->nchars && is_ws(t->chars[i])) ++i;
    return i;
}

static int all_ws(const token *t)
{
    return leading_ws(t) == t->nchars;
}

static void set_doctype_quirks(shz_parser *p, token *t)
{
    static const char *const quirky_prefixes[] = {
        "+//silmaril//dtd html pro v0r11 19970101//", "-//as//dtd html 3.0 aswedit + extensions//",
        "-//advasoft ltd//dtd html 3.0 aswedit + extensions//", "-//ietf//dtd html 2.0 level 1//",
        "-//ietf//dtd html 2.0 level 2//", "-//ietf//dtd html 2.0 strict level 1//",
        "-//ietf//dtd html 2.0 strict level 2//", "-//ietf//dtd html 2.0 strict//", "-//ietf//dtd html 2.0//",
        "-//ietf//dtd html 2.1e//", "-//ietf//dtd html 3.0//", "-//ietf//dtd html 3.2 final//",
        "-//ietf//dtd html 3.2//", "-//ietf//dtd html 3//", "-//ietf//dtd html level 0//",
        "-//ietf//dtd html level 1//", "-//ietf//dtd html level 2//", "-//ietf//dtd html level 3//",
        "-//ietf//dtd html strict level 0//", "-//ietf//dtd html strict level 1//",
        "-//ietf//dtd html strict level 2//", "-//ietf//dtd html strict level 3//", "-//ietf//dtd html strict//",
        "-//ietf//dtd html//", "-//metrius//dtd metrius presentational//",
        "-//microsoft//dtd internet explorer 2.0 html strict//", "-//microsoft//dtd internet explorer 2.0 html//",
        "-//microsoft//dtd internet explorer 2.0 tables//", "-//microsoft//dtd internet explorer 3.0 html strict//",
        "-//microsoft//dtd internet explorer 3.0 html//", "-//microsoft//dtd internet explorer 3.0 tables//",
        "-//netscape comm. corp.//dtd html//", "-//netscape comm. corp.//dtd strict html//",
        "-//o'reilly and associates//dtd html 2.0//", "-//o'reilly and associates//dtd html extended 1.0//",
        "-//o'reilly and associates//dtd html extended relaxed 1.0//",
        "-//sq//dtd html 2.0 hotmetal + extensions//",
        "-//softquad software//dtd hotmetal pro 6.0::19990601::extensions to html 4.0//",
        "-//softquad//dtd hotmetal pro 4.0::19971010::extensions to html 4.0//",
        "-//spyglass//dtd html 2.0 extended//", "-//sun microsystems corp.//dtd hotjava html//",
        "-//sun microsystems corp.//dtd hotjava strict html//", "-//w3c//dtd html 3 1995-03-24//",
        "-//w3c//dtd html 3.2 draft//", "-//w3c//dtd html 3.2 final//", "-//w3c//dtd html 3.2//",
        "-//w3c//dtd html 3.2s draft//", "-//w3c//dtd html 4.0 frameset//", "-//w3c//dtd html 4.0 transitional//",
        "-//w3c//dtd html experimental 19960712//", "-//w3c//dtd html experimental 970421//",
        "-//w3c//dtd w3 html//", "-//w3o//dtd w3 html 3.0//", "-//webtechs//dtd mozilla html 2.0//",
        "-//webtechs//dtd mozilla html//"
    };
    const shz_char *pub = t->public_id.s;
    size_t pn = t->has_public ? t->public_id.len : 0, i;
    int quirks = SHZ_QUIRKS_NONE;
    if (t->force_quirks || !t->has_name || !shz_strneq_ascii(t->name.s, t->name.len, "html")) {
        quirks = SHZ_QUIRKS_FULL;
    } else if (t->has_public && (shz_strnieq_ascii(pub, pn, "-//W3O//DTD W3 HTML Strict 3.0//EN//")
                                 || shz_strnieq_ascii(pub, pn, "-/W3C/DTD HTML 4.0 Transitional/EN")
                                 || shz_strnieq_ascii(pub, pn, "HTML"))) {
        quirks = SHZ_QUIRKS_FULL;
    } else if (t->has_system && shz_strnieq_ascii(t->system_id.s, t->system_id.len,
                                                  "http://www.ibm.com/data/dtd/v11/ibmxhtml1-transitional.dtd")) {
        quirks = SHZ_QUIRKS_FULL;
    } else if (t->has_public) {
        for (i = 0; i < SHZ_ARRAY_SIZE(quirky_prefixes); ++i)
            if (shz_starts_with_ascii_ci(pub, pn, quirky_prefixes[i])) { quirks = SHZ_QUIRKS_FULL; break; }
        if (!quirks && (shz_starts_with_ascii_ci(pub, pn, "-//W3C//DTD HTML 4.01 Frameset//")
                        || shz_starts_with_ascii_ci(pub, pn, "-//W3C//DTD HTML 4.01 Transitional//")))
            quirks = t->has_system ? SHZ_QUIRKS_LIMITED : SHZ_QUIRKS_FULL;
        if (!quirks && (shz_starts_with_ascii_ci(pub, pn, "-//W3C//DTD XHTML 1.0 Frameset//")
                        || shz_starts_with_ascii_ci(pub, pn, "-//W3C//DTD XHTML 1.0 Transitional//")))
            quirks = SHZ_QUIRKS_LIMITED;
    }
    p->doc->doctype_quirks = (uint8_t)quirks;
}

static int quirks(shz_parser *p)
{
    return p->doc->doctype_quirks == SHZ_QUIRKS_FULL;
}

/* script end tag in the text mode */
static void run_script(shz_parser *p, shz_node *script)
{
    shz_doc *doc = p->doc;
    int depth;
    if (p->fragment || !doc->hooks || !doc->hooks->run_script || !shz_in_doc(script)) {
        script->flags |= SHZ_NF_STARTED;
        return;
    }
    if (p->script_nesting >= SHZ_MAX_SCRIPT_NESTING) {
        script->flags |= SHZ_NF_STARTED;
        return;
    }
    script->flags |= SHZ_NF_STARTED;
    depth = p->script_nesting++;
    p->ins_stack[depth] = p->has_ins ? p->ins : (size_t)-1;
    p->has_ins = 1;
    p->ins = p->pos;
    shz_node_addref(script);
    doc->hooks->run_script(doc->hooks_ctx, doc, script, 1);
    shz_node_release(script);
    p->script_nesting = depth;
    if (p->ins_stack[depth] == (size_t)-1) p->has_ins = 0;
    else p->ins = p->ins_stack[depth];
}

/* ---------------------------------------------------------------------------------------------------- in head */

static int in_head(shz_parser *p, token *t)
{
    /* returns 1 when handled, 0 = "anything else" */
    if (t->type == TOK_CHARS) {
        size_t ws = leading_ws(t);
        if (ws) {
            insert_chars(p, t->chars, ws);
            t->chars += ws;
            t->nchars -= ws;
        }
        return t->nchars == 0;
    }
    if (t->type == TOK_COMMENT) { insert_comment(p, t, NULL); return 1; }
    if (t->type == TOK_DOCTYPE) return 1;
    if (t->type == TOK_START) {
        switch (t->tag) {
        case SHZ_TAG_HTML:
            process(p, t, IM_IN_BODY);
            return 1;
        case SHZ_TAG_BASE: case SHZ_TAG_BASEFONT: case SHZ_TAG_BGSOUND: case SHZ_TAG_LINK: case SHZ_TAG_META:
            insert_void(p, t);
            return 1;
        case SHZ_TAG_TITLE:
            generic_text(p, t, TS_RCDATA);
            return 1;
        case SHZ_TAG_NOSCRIPT: case SHZ_TAG_NOFRAMES: case SHZ_TAG_STYLE:
            generic_text(p, t, TS_RAWTEXT);
            return 1;
        case SHZ_TAG_SCRIPT:
            generic_text(p, t, TS_SCRIPT);
            return 1;
        case SHZ_TAG_TEMPLATE:
            insert_element(p, t);
            fmt_push_marker(p);
            p->frameset_ok = 0;
            return 1;
        case SHZ_TAG_HEAD:
            return 1;
        default:
            return 0;
        }
    }
    if (t->type == TOK_END) {
        switch (t->tag) {
        case SHZ_TAG_HEAD:
            pop(p);
            p->mode = IM_AFTER_HEAD;
            return 1;
        case SHZ_TAG_BODY: case SHZ_TAG_HTML: case SHZ_TAG_BR:
            return 0;
        case SHZ_TAG_TEMPLATE: {
            size_t i = p->stack.len;
            int found = 0;
            while (i--) if (shz_is_tag(p->stack.items[i], SHZ_TAG_TEMPLATE)) { found = 1; break; }
            if (found) {
                generate_implied_end_tags(p, 0);
                pop_until_tag(p, SHZ_TAG_TEMPLATE);
                fmt_clear_to_marker(p);
                reset_insertion_mode(p);
            }
            return 1;
        }
        default:
            return 1;           /* ignored */
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------------------------------- in body */

static const int closes_p_tags[] = {
    SHZ_TAG_ADDRESS, SHZ_TAG_ARTICLE, SHZ_TAG_ASIDE, SHZ_TAG_BLOCKQUOTE, SHZ_TAG_CENTER, SHZ_TAG_DETAILS,
    SHZ_TAG_DIALOG, SHZ_TAG_DIR, SHZ_TAG_DIV, SHZ_TAG_DL, SHZ_TAG_FIELDSET, SHZ_TAG_FIGCAPTION, SHZ_TAG_FIGURE,
    SHZ_TAG_FOOTER, SHZ_TAG_HEADER, SHZ_TAG_HGROUP, SHZ_TAG_MAIN, SHZ_TAG_MENU, SHZ_TAG_NAV, SHZ_TAG_OL, SHZ_TAG_P,
    SHZ_TAG_SEARCH, SHZ_TAG_SECTION, SHZ_TAG_SUMMARY, SHZ_TAG_UL, 0
};

static const int block_end_tags[] = {
    SHZ_TAG_ADDRESS, SHZ_TAG_ARTICLE, SHZ_TAG_ASIDE, SHZ_TAG_BLOCKQUOTE, SHZ_TAG_BUTTON, SHZ_TAG_CENTER,
    SHZ_TAG_DETAILS, SHZ_TAG_DIALOG, SHZ_TAG_DIR, SHZ_TAG_DIV, SHZ_TAG_DL, SHZ_TAG_FIELDSET, SHZ_TAG_FIGCAPTION,
    SHZ_TAG_FIGURE, SHZ_TAG_FOOTER, SHZ_TAG_HEADER, SHZ_TAG_HGROUP, SHZ_TAG_LISTING, SHZ_TAG_MAIN, SHZ_TAG_MENU,
    SHZ_TAG_NAV, SHZ_TAG_OL, SHZ_TAG_PRE, SHZ_TAG_SEARCH, SHZ_TAG_SECTION, SHZ_TAG_SUMMARY, SHZ_TAG_UL, 0
};

static const int formatting_tags[] = {
    SHZ_TAG_B, SHZ_TAG_BIG, SHZ_TAG_CODE, SHZ_TAG_EM, SHZ_TAG_FONT, SHZ_TAG_I, SHZ_TAG_S, SHZ_TAG_SMALL,
    SHZ_TAG_STRIKE, SHZ_TAG_STRONG, SHZ_TAG_TT, SHZ_TAG_U, 0
};

static void add_missing_attrs(shz_node *elem, token *t)
{
    size_t i;
    if (!elem) return;
    for (i = 0; i < t->nattrs; ++i) {
        tok_attr *a = &t->attrs[i];
        if (a->dup || !a->name.len || shz_elem_find_attr(elem, a->name.s, a->name.len)) continue;
        shz_elem_set_attr(elem, a->name.s, a->name.len, a->value.s, a->value.len);
    }
}

static void any_other_end_tag(shz_parser *p, token *t)
{
    size_t i = p->stack.len;
    while (i--) {
        shz_node *n = p->stack.items[i];
        shz_element *e = shz_elem(n);
        if (e && e->ns == SHZ_NS_HTML && shz_strneq(e->qname, e->qname_len, t->name.s, t->name.len)) {
            generate_implied_end_tags(p, e->tag ? e->tag : -1);
            pop_until_node(p, n);
            return;
        }
        if (is_html_elem(n) ? (shz_tag_flags(tag_of(n)) & SHZ_TF_SPECIAL) != 0 : 0) return;
    }
}

static const shz_char *attr_value(token *t, const char *name, size_t *len)
{
    static const shz_char empty[1] = {0};
    size_t i;
    for (i = 0; i < t->nattrs; ++i)
        if (!t->attrs[i].dup && shz_strneq_ascii(t->attrs[i].name.s, t->attrs[i].name.len, name)) {
            *len = t->attrs[i].value.len;
            return t->attrs[i].value.s ? t->attrs[i].value.s : empty;
        }
    return NULL;
}

static void insert_foreign(shz_parser *p, token *t, int ns)
{
    reconstruct_formatting(p);
    if (insert_element_ns(p, t, ns) && t->self_closing) pop(p);
}

static void in_body(shz_parser *p, token *t)
{
    size_t i;
    switch (t->type) {
    case TOK_CHARS:
        reconstruct_formatting(p);
        insert_chars(p, t->chars, t->nchars);
        if (!all_ws(t)) p->frameset_ok = 0;
        return;
    case TOK_COMMENT:
        insert_comment(p, t, NULL);
        return;
    case TOK_DOCTYPE:
        return;
    case TOK_EOF:
        p->done = 1;
        return;
    case TOK_START:
        switch (t->tag) {
        case SHZ_TAG_HTML:
            if (p->stack.len) add_missing_attrs(p->stack.items[0], t);
            return;
        case SHZ_TAG_BASE: case SHZ_TAG_BASEFONT: case SHZ_TAG_BGSOUND: case SHZ_TAG_LINK: case SHZ_TAG_META:
        case SHZ_TAG_NOFRAMES: case SHZ_TAG_SCRIPT: case SHZ_TAG_STYLE: case SHZ_TAG_TEMPLATE: case SHZ_TAG_TITLE:
            in_head(p, t);
            return;
        case SHZ_TAG_BODY:
            if (p->stack.len < 2 || !shz_is_tag(p->stack.items[1], SHZ_TAG_BODY)) return;
            p->frameset_ok = 0;
            add_missing_attrs(p->stack.items[1], t);
            return;
        case SHZ_TAG_FRAMESET:
            if (p->stack.len < 2 || !shz_is_tag(p->stack.items[1], SHZ_TAG_BODY) || !p->frameset_ok) return;
            shz_node_remove(p->stack.items[1]);
            while (p->stack.len > 1) pop(p);
            insert_element(p, t);
            p->mode = IM_IN_FRAMESET;
            return;
        case SHZ_TAG_H1: case SHZ_TAG_H2: case SHZ_TAG_H3: case SHZ_TAG_H4: case SHZ_TAG_H5: case SHZ_TAG_H6:
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            if (is_html_elem(cur(p)) && (shz_tag_flags(tag_of(cur(p))) & SHZ_TF_HEADING)) pop(p);
            insert_element(p, t);
            return;
        case SHZ_TAG_PRE: case SHZ_TAG_LISTING:
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            insert_element(p, t);
            p->skip_lf = 1;
            p->frameset_ok = 0;
            return;
        case SHZ_TAG_FORM:
            if (p->form) return;
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            {
                shz_node *f = insert_element(p, t);
                if (f) { shz_node_addref(f); p->form = f; }
            }
            return;
        case SHZ_TAG_LI: case SHZ_TAG_DD: case SHZ_TAG_DT: {
            p->frameset_ok = 0;
            i = p->stack.len;
            while (i--) {
                shz_node *n = p->stack.items[i];
                int tg = tag_of(n);
                if ((t->tag == SHZ_TAG_LI && tg == SHZ_TAG_LI)
                    || (t->tag != SHZ_TAG_LI && (tg == SHZ_TAG_DD || tg == SHZ_TAG_DT))) {
                    generate_implied_end_tags(p, tg);
                    pop_until_tag(p, tg);
                    break;
                }
                if (is_html_elem(n) && (shz_tag_flags(tg) & SHZ_TF_SPECIAL) && tg != SHZ_TAG_ADDRESS
                    && tg != SHZ_TAG_DIV && tg != SHZ_TAG_P)
                    break;
            }
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            insert_element(p, t);
            return;
        }
        case SHZ_TAG_PLAINTEXT:
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            insert_element(p, t);
            p->state = TS_PLAINTEXT;
            return;
        case SHZ_TAG_BUTTON:
            if (in_scope(p, SHZ_TAG_BUTTON, SCOPE_DEFAULT)) {
                generate_implied_end_tags(p, 0);
                pop_until_tag(p, SHZ_TAG_BUTTON);
            }
            reconstruct_formatting(p);
            insert_element(p, t);
            p->frameset_ok = 0;
            return;
        case SHZ_TAG_A: {
            shz_node *a = NULL;
            i = p->fmt.len;
            while (i--) {
                shz_node *e = p->fmt.items[i];
                if (!e) break;
                if (shz_is_tag(e, SHZ_TAG_A)) { a = e; break; }
            }
            if (a) {
                token end;
                memset(&end, 0, sizeof(end));
                end.type = TOK_END;
                end.tag = SHZ_TAG_A;
                end.name = t->name;
                shz_node_addref(a);
                if (adoption_agency(p, &end)) any_other_end_tag(p, &end);
                fmt_remove(p, a);
                remove_from_stack(p, a);
                shz_node_release(a);
            }
            reconstruct_formatting(p);
            {
                shz_node *n = insert_element(p, t);
                if (n) fmt_push(p, n);
            }
            return;
        }
        case SHZ_TAG_NOBR:
            reconstruct_formatting(p);
            if (in_scope(p, SHZ_TAG_NOBR, SCOPE_DEFAULT)) {
                if (adoption_agency(p, t)) any_other_end_tag(p, t);
                reconstruct_formatting(p);
            }
            {
                shz_node *n = insert_element(p, t);
                if (n) fmt_push(p, n);
            }
            return;
        case SHZ_TAG_APPLET: case SHZ_TAG_MARQUEE: case SHZ_TAG_OBJECT:
            reconstruct_formatting(p);
            insert_element(p, t);
            fmt_push_marker(p);
            p->frameset_ok = 0;
            return;
        case SHZ_TAG_TABLE:
            if (!quirks(p) && in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            insert_element(p, t);
            p->frameset_ok = 0;
            p->mode = IM_IN_TABLE;
            return;
        case SHZ_TAG_AREA: case SHZ_TAG_BR: case SHZ_TAG_EMBED: case SHZ_TAG_IMG: case SHZ_TAG_KEYGEN:
        case SHZ_TAG_WBR:
            reconstruct_formatting(p);
            insert_void(p, t);
            p->frameset_ok = 0;
            return;
        case SHZ_TAG_INPUT: {
            size_t len;
            const shz_char *type;
            reconstruct_formatting(p);
            insert_void(p, t);
            type = attr_value(t, "type", &len);
            if (!type || !shz_strnieq_ascii(type, len, "hidden")) p->frameset_ok = 0;
            return;
        }
        case SHZ_TAG_PARAM: case SHZ_TAG_SOURCE: case SHZ_TAG_TRACK:
            insert_void(p, t);
            return;
        case SHZ_TAG_HR:
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            insert_void(p, t);
            p->frameset_ok = 0;
            return;
        case SHZ_TAG_IMAGE: {
            static const shz_char img[] = { 'i', 'm', 'g' };
            shz_buf_clear(&t->name);
            shz_buf_put(&t->name, img, 3);
            t->tag = SHZ_TAG_IMG;
            in_body(p, t);
            return;
        }
        case SHZ_TAG_TEXTAREA:
            insert_element(p, t);
            p->skip_lf = 1;
            p->state = TS_RCDATA;
            p->orig_mode = p->mode;
            p->frameset_ok = 0;
            p->mode = IM_TEXT;
            return;
        case SHZ_TAG_XMP:
            if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
            reconstruct_formatting(p);
            p->frameset_ok = 0;
            generic_text(p, t, TS_RAWTEXT);
            return;
        case SHZ_TAG_IFRAME:
            p->frameset_ok = 0;
            generic_text(p, t, TS_RAWTEXT);
            return;
        case SHZ_TAG_NOEMBED: case SHZ_TAG_NOSCRIPT:
            generic_text(p, t, TS_RAWTEXT);
            return;
        case SHZ_TAG_SELECT:
            reconstruct_formatting(p);
            insert_element(p, t);
            p->frameset_ok = 0;
            if (p->mode == IM_IN_TABLE || p->mode == IM_IN_CAPTION || p->mode == IM_IN_TABLE_BODY
                || p->mode == IM_IN_ROW || p->mode == IM_IN_CELL)
                p->mode = IM_IN_SELECT_IN_TABLE;
            else
                p->mode = IM_IN_SELECT;
            return;
        case SHZ_TAG_OPTGROUP: case SHZ_TAG_OPTION:
            if (cur_is(p, SHZ_TAG_OPTION)) pop(p);
            reconstruct_formatting(p);
            insert_element(p, t);
            return;
        case SHZ_TAG_RB: case SHZ_TAG_RTC:
            if (in_scope(p, SHZ_TAG_RUBY, SCOPE_DEFAULT)) generate_implied_end_tags(p, 0);
            insert_element(p, t);
            return;
        case SHZ_TAG_RP: case SHZ_TAG_RT:
            if (in_scope(p, SHZ_TAG_RUBY, SCOPE_DEFAULT)) generate_implied_end_tags(p, SHZ_TAG_RTC);
            insert_element(p, t);
            return;
        case SHZ_TAG_MATH:
            insert_foreign(p, t, SHZ_NS_MATHML);
            return;
        case SHZ_TAG_SVG:
            insert_foreign(p, t, SHZ_NS_SVG);
            return;
        case SHZ_TAG_CAPTION: case SHZ_TAG_COL: case SHZ_TAG_COLGROUP: case SHZ_TAG_FRAME: case SHZ_TAG_HEAD:
        case SHZ_TAG_TBODY: case SHZ_TAG_TD: case SHZ_TAG_TFOOT: case SHZ_TAG_TH: case SHZ_TAG_THEAD: case SHZ_TAG_TR:
            return;
        default:
            if (tag_in(t->tag, closes_p_tags)) {
                if (in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) close_p(p);
                insert_element(p, t);
                return;
            }
            if (tag_in(t->tag, formatting_tags)) {
                shz_node *n;
                reconstruct_formatting(p);
                n = insert_element(p, t);
                if (n) fmt_push(p, n);
                return;
            }
            reconstruct_formatting(p);
            insert_element(p, t);
            return;
        }
    case TOK_END:
        switch (t->tag) {
        case SHZ_TAG_TEMPLATE:
            in_head(p, t);
            return;
        case SHZ_TAG_BODY:
            if (!in_scope(p, SHZ_TAG_BODY, SCOPE_DEFAULT)) return;
            p->mode = IM_AFTER_BODY;
            return;
        case SHZ_TAG_HTML:
            if (!in_scope(p, SHZ_TAG_BODY, SCOPE_DEFAULT)) return;
            p->mode = IM_AFTER_BODY;
            process(p, t, IM_AFTER_BODY);
            return;
        case SHZ_TAG_FORM: {
            shz_node *f = p->form;
            p->form = NULL;
            if (!f) return;
            if (!node_in_scope(p, f, SCOPE_DEFAULT)) { shz_node_release(f); return; }
            generate_implied_end_tags(p, 0);
            remove_from_stack(p, f);
            shz_node_release(f);
            return;
        }
        case SHZ_TAG_P:
            if (!in_scope(p, SHZ_TAG_P, SCOPE_BUTTON)) insert_tag(p, SHZ_TAG_P);
            close_p(p);
            return;
        case SHZ_TAG_LI:
            if (!in_scope(p, SHZ_TAG_LI, SCOPE_LIST_ITEM)) return;
            generate_implied_end_tags(p, SHZ_TAG_LI);
            pop_until_tag(p, SHZ_TAG_LI);
            return;
        case SHZ_TAG_DD: case SHZ_TAG_DT:
            if (!in_scope(p, t->tag, SCOPE_DEFAULT)) return;
            generate_implied_end_tags(p, t->tag);
            pop_until_tag(p, t->tag);
            return;
        case SHZ_TAG_H1: case SHZ_TAG_H2: case SHZ_TAG_H3: case SHZ_TAG_H4: case SHZ_TAG_H5: case SHZ_TAG_H6:
            if (!heading_in_scope(p)) return;
            generate_implied_end_tags(p, 0);
            while (p->stack.len) {
                int h = is_html_elem(cur(p)) && (shz_tag_flags(tag_of(cur(p))) & SHZ_TF_HEADING);
                pop(p);
                if (h) break;
            }
            return;
        case SHZ_TAG_A: case SHZ_TAG_NOBR:
            if (adoption_agency(p, t)) any_other_end_tag(p, t);
            return;
        case SHZ_TAG_APPLET: case SHZ_TAG_MARQUEE: case SHZ_TAG_OBJECT:
            if (!in_scope(p, t->tag, SCOPE_DEFAULT)) return;
            generate_implied_end_tags(p, 0);
            pop_until_tag(p, t->tag);
            fmt_clear_to_marker(p);
            return;
        case SHZ_TAG_BR: {
            token br;
            memset(&br, 0, sizeof(br));
            br.type = TOK_START;
            br.tag = SHZ_TAG_BR;
            br.name = t->name;
            br.nattrs = 0;
            reconstruct_formatting(p);
            insert_void(p, &br);
            p->frameset_ok = 0;
            return;
        }
        default:
            if (tag_in(t->tag, block_end_tags)) {
                if (!in_scope(p, t->tag, SCOPE_DEFAULT)) return;
                generate_implied_end_tags(p, 0);
                pop_until_tag(p, t->tag);
                return;
            }
            if (tag_in(t->tag, formatting_tags)) {
                if (adoption_agency(p, t)) any_other_end_tag(p, t);
                return;
            }
            any_other_end_tag(p, t);
            return;
        }
    default:
        return;
    }
}

/* ---------------------------------------------------------------------------------------------------- tables */

static void clear_to_table_context(shz_parser *p)
{
    static const int stop[] = { SHZ_TAG_TABLE, SHZ_TAG_TEMPLATE, SHZ_TAG_HTML, 0 };
    while (p->stack.len > 1 && !cur_is_any(p, stop)) pop(p);
}

static void clear_to_tbody_context(shz_parser *p)
{
    static const int stop[] = { SHZ_TAG_TBODY, SHZ_TAG_TFOOT, SHZ_TAG_THEAD, SHZ_TAG_TEMPLATE, SHZ_TAG_HTML, 0 };
    while (p->stack.len > 1 && !cur_is_any(p, stop)) pop(p);
}

static void clear_to_row_context(shz_parser *p)
{
    static const int stop[] = { SHZ_TAG_TR, SHZ_TAG_TEMPLATE, SHZ_TAG_HTML, 0 };
    while (p->stack.len > 1 && !cur_is_any(p, stop)) pop(p);
}

static void in_table(shz_parser *p, token *t)
{
    static const int table_ctx[] = { SHZ_TAG_TABLE, SHZ_TAG_TBODY, SHZ_TAG_TFOOT, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    switch (t->type) {
    case TOK_CHARS:
        if (cur_is_any(p, table_ctx)) {
            shz_buf_clear(&p->table_chars);
            p->table_chars_nonspace = 0;
            p->orig_mode = p->mode;
            p->mode = IM_IN_TABLE_TEXT;
            process(p, t, IM_IN_TABLE_TEXT);
            return;
        }
        break;
    case TOK_COMMENT:
        insert_comment(p, t, NULL);
        return;
    case TOK_DOCTYPE:
        return;
    case TOK_START:
        switch (t->tag) {
        case SHZ_TAG_CAPTION:
            clear_to_table_context(p);
            fmt_push_marker(p);
            insert_element(p, t);
            p->mode = IM_IN_CAPTION;
            return;
        case SHZ_TAG_COLGROUP:
            clear_to_table_context(p);
            insert_element(p, t);
            p->mode = IM_IN_COLUMN_GROUP;
            return;
        case SHZ_TAG_COL:
            clear_to_table_context(p);
            insert_tag(p, SHZ_TAG_COLGROUP);
            p->mode = IM_IN_COLUMN_GROUP;
            process(p, t, IM_IN_COLUMN_GROUP);
            return;
        case SHZ_TAG_TBODY: case SHZ_TAG_TFOOT: case SHZ_TAG_THEAD:
            clear_to_table_context(p);
            insert_element(p, t);
            p->mode = IM_IN_TABLE_BODY;
            return;
        case SHZ_TAG_TD: case SHZ_TAG_TH: case SHZ_TAG_TR:
            clear_to_table_context(p);
            insert_tag(p, SHZ_TAG_TBODY);
            p->mode = IM_IN_TABLE_BODY;
            process(p, t, IM_IN_TABLE_BODY);
            return;
        case SHZ_TAG_TABLE:
            if (!in_scope(p, SHZ_TAG_TABLE, SCOPE_TABLE)) return;
            pop_until_tag(p, SHZ_TAG_TABLE);
            reset_insertion_mode(p);
            process(p, t, p->mode);
            return;
        case SHZ_TAG_STYLE: case SHZ_TAG_SCRIPT: case SHZ_TAG_TEMPLATE:
            in_head(p, t);
            return;
        case SHZ_TAG_INPUT: {
            size_t len;
            const shz_char *type = attr_value(t, "type", &len);
            if (!type || !shz_strnieq_ascii(type, len, "hidden")) break;
            insert_void(p, t);
            return;
        }
        case SHZ_TAG_FORM:
            if (p->form) return;
            {
                shz_node *f = insert_element(p, t);
                if (f) {
                    shz_node_addref(f);
                    p->form = f;
                    pop(p);
                }
            }
            return;
        default:
            break;
        }
        break;
    case TOK_END:
        switch (t->tag) {
        case SHZ_TAG_TABLE:
            if (!in_scope(p, SHZ_TAG_TABLE, SCOPE_TABLE)) return;
            pop_until_tag(p, SHZ_TAG_TABLE);
            reset_insertion_mode(p);
            return;
        case SHZ_TAG_BODY: case SHZ_TAG_CAPTION: case SHZ_TAG_COL: case SHZ_TAG_COLGROUP: case SHZ_TAG_HTML:
        case SHZ_TAG_TBODY: case SHZ_TAG_TD: case SHZ_TAG_TFOOT: case SHZ_TAG_TH: case SHZ_TAG_THEAD: case SHZ_TAG_TR:
            return;
        case SHZ_TAG_TEMPLATE:
            in_head(p, t);
            return;
        default:
            break;
        }
        break;
    case TOK_EOF:
        in_body(p, t);
        return;
    }
    /* anything else: process with in-body rules, foster parenting enabled */
    p->foster = 1;
    in_body(p, t);
    p->foster = 0;
}

static void in_table_text(shz_parser *p, token *t)
{
    if (t->type == TOK_CHARS) {
        size_t i;
        for (i = 0; i < t->nchars; ++i) {
            if (!t->chars[i]) continue;
            if (!is_ws(t->chars[i])) p->table_chars_nonspace = 1;
            shz_buf_putc(&p->table_chars, t->chars[i]);
        }
        return;
    }
    if (p->table_chars.len) {
        if (p->table_chars_nonspace) {
            token ct;
            memset(&ct, 0, sizeof(ct));
            ct.type = TOK_CHARS;
            ct.chars = p->table_chars.s;
            ct.nchars = p->table_chars.len;
            p->foster = 1;
            in_body(p, &ct);
            p->foster = 0;
        } else {
            insert_chars(p, p->table_chars.s, p->table_chars.len);
        }
        shz_buf_clear(&p->table_chars);
    }
    p->mode = p->orig_mode;
    process(p, t, p->mode);
}

static int close_caption(shz_parser *p)
{
    if (!in_scope(p, SHZ_TAG_CAPTION, SCOPE_TABLE)) return 0;
    generate_implied_end_tags(p, 0);
    pop_until_tag(p, SHZ_TAG_CAPTION);
    fmt_clear_to_marker(p);
    p->mode = IM_IN_TABLE;
    return 1;
}

static void in_caption(shz_parser *p, token *t)
{
    static const int reprocess_start[] = { SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_TBODY, SHZ_TAG_TD,
                                           SHZ_TAG_TFOOT, SHZ_TAG_TH, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    static const int ignore_end[] = { SHZ_TAG_BODY, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_HTML, SHZ_TAG_TBODY,
                                      SHZ_TAG_TD, SHZ_TAG_TFOOT, SHZ_TAG_TH, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    if (t->type == TOK_END && t->tag == SHZ_TAG_CAPTION) { close_caption(p); return; }
    if ((t->type == TOK_START && tag_in(t->tag, reprocess_start)) || (t->type == TOK_END && t->tag == SHZ_TAG_TABLE)) {
        if (close_caption(p)) process(p, t, IM_IN_TABLE);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, ignore_end)) return;
    in_body(p, t);
}

static void in_column_group(shz_parser *p, token *t)
{
    if (t->type == TOK_CHARS) {
        size_t ws = leading_ws(t);
        if (ws) {
            insert_chars(p, t->chars, ws);
            t->chars += ws;
            t->nchars -= ws;
        }
        if (!t->nchars) return;
    } else if (t->type == TOK_COMMENT) {
        insert_comment(p, t, NULL);
        return;
    } else if (t->type == TOK_DOCTYPE) {
        return;
    } else if (t->type == TOK_START && t->tag == SHZ_TAG_HTML) {
        in_body(p, t);
        return;
    } else if (t->type == TOK_START && t->tag == SHZ_TAG_COL) {
        insert_void(p, t);
        return;
    } else if (t->type == TOK_END && t->tag == SHZ_TAG_COLGROUP) {
        if (!cur_is(p, SHZ_TAG_COLGROUP)) return;
        pop(p);
        p->mode = IM_IN_TABLE;
        return;
    } else if (t->type == TOK_END && t->tag == SHZ_TAG_COL) {
        return;
    } else if ((t->type == TOK_START || t->type == TOK_END) && t->tag == SHZ_TAG_TEMPLATE) {
        in_head(p, t);
        return;
    } else if (t->type == TOK_EOF) {
        in_body(p, t);
        return;
    }
    if (!cur_is(p, SHZ_TAG_COLGROUP)) return;
    pop(p);
    p->mode = IM_IN_TABLE;
    process(p, t, IM_IN_TABLE);
}

static void in_table_body(shz_parser *p, token *t)
{
    static const int sections[] = { SHZ_TAG_TBODY, SHZ_TAG_THEAD, SHZ_TAG_TFOOT, 0 };
    static const int reprocess_start[] = { SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_TBODY,
                                           SHZ_TAG_TFOOT, SHZ_TAG_THEAD, 0 };
    static const int ignore_end[] = { SHZ_TAG_BODY, SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_HTML,
                                      SHZ_TAG_TD, SHZ_TAG_TH, SHZ_TAG_TR, 0 };
    if (t->type == TOK_START && t->tag == SHZ_TAG_TR) {
        clear_to_tbody_context(p);
        insert_element(p, t);
        p->mode = IM_IN_ROW;
        return;
    }
    if (t->type == TOK_START && (t->tag == SHZ_TAG_TH || t->tag == SHZ_TAG_TD)) {
        clear_to_tbody_context(p);
        insert_tag(p, SHZ_TAG_TR);
        p->mode = IM_IN_ROW;
        process(p, t, IM_IN_ROW);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, sections)) {
        if (!in_scope(p, t->tag, SCOPE_TABLE)) return;
        clear_to_tbody_context(p);
        pop(p);
        p->mode = IM_IN_TABLE;
        return;
    }
    if ((t->type == TOK_START && tag_in(t->tag, reprocess_start)) || (t->type == TOK_END && t->tag == SHZ_TAG_TABLE)) {
        if (!in_scope(p, SHZ_TAG_TBODY, SCOPE_TABLE) && !in_scope(p, SHZ_TAG_THEAD, SCOPE_TABLE)
            && !in_scope(p, SHZ_TAG_TFOOT, SCOPE_TABLE))
            return;
        clear_to_tbody_context(p);
        pop(p);
        p->mode = IM_IN_TABLE;
        process(p, t, IM_IN_TABLE);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, ignore_end)) return;
    in_table(p, t);
}

static int close_row(shz_parser *p)
{
    if (!in_scope(p, SHZ_TAG_TR, SCOPE_TABLE)) return 0;
    clear_to_row_context(p);
    pop(p);
    p->mode = IM_IN_TABLE_BODY;
    return 1;
}

static void in_row(shz_parser *p, token *t)
{
    static const int reprocess_start[] = { SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_TBODY,
                                           SHZ_TAG_TFOOT, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    static const int sections[] = { SHZ_TAG_TBODY, SHZ_TAG_THEAD, SHZ_TAG_TFOOT, 0 };
    static const int ignore_end[] = { SHZ_TAG_BODY, SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_HTML,
                                      SHZ_TAG_TD, SHZ_TAG_TH, 0 };
    if (t->type == TOK_START && (t->tag == SHZ_TAG_TH || t->tag == SHZ_TAG_TD)) {
        clear_to_row_context(p);
        insert_element(p, t);
        p->mode = IM_IN_CELL;
        fmt_push_marker(p);
        return;
    }
    if (t->type == TOK_END && t->tag == SHZ_TAG_TR) { close_row(p); return; }
    if ((t->type == TOK_START && tag_in(t->tag, reprocess_start)) || (t->type == TOK_END && t->tag == SHZ_TAG_TABLE)) {
        if (close_row(p)) process(p, t, IM_IN_TABLE_BODY);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, sections)) {
        if (!in_scope(p, t->tag, SCOPE_TABLE)) return;
        if (close_row(p)) process(p, t, IM_IN_TABLE_BODY);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, ignore_end)) return;
    in_table(p, t);
}

static void close_cell(shz_parser *p)
{
    generate_implied_end_tags(p, 0);
    while (p->stack.len) {
        int done = cur_is(p, SHZ_TAG_TD) || cur_is(p, SHZ_TAG_TH);
        pop(p);
        if (done) break;
    }
    fmt_clear_to_marker(p);
    p->mode = IM_IN_ROW;
}

static void in_cell(shz_parser *p, token *t)
{
    static const int reprocess_start[] = { SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_TBODY, SHZ_TAG_TD,
                                           SHZ_TAG_TFOOT, SHZ_TAG_TH, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    static const int ignore_end[] = { SHZ_TAG_BODY, SHZ_TAG_CAPTION, SHZ_TAG_COL, SHZ_TAG_COLGROUP, SHZ_TAG_HTML, 0 };
    static const int reprocess_end[] = { SHZ_TAG_TABLE, SHZ_TAG_TBODY, SHZ_TAG_TFOOT, SHZ_TAG_THEAD, SHZ_TAG_TR, 0 };
    if (t->type == TOK_END && (t->tag == SHZ_TAG_TD || t->tag == SHZ_TAG_TH)) {
        if (!in_scope(p, t->tag, SCOPE_TABLE)) return;
        generate_implied_end_tags(p, 0);
        pop_until_tag(p, t->tag);
        fmt_clear_to_marker(p);
        p->mode = IM_IN_ROW;
        return;
    }
    if (t->type == TOK_START && tag_in(t->tag, reprocess_start)) {
        if (!in_scope(p, SHZ_TAG_TD, SCOPE_TABLE) && !in_scope(p, SHZ_TAG_TH, SCOPE_TABLE)) return;
        close_cell(p);
        process(p, t, IM_IN_ROW);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, ignore_end)) return;
    if (t->type == TOK_END && tag_in(t->tag, reprocess_end)) {
        if (!in_scope(p, t->tag, SCOPE_TABLE)) return;
        close_cell(p);
        process(p, t, IM_IN_ROW);
        return;
    }
    in_body(p, t);
}

/* ---------------------------------------------------------------------------------------------------- select */

static void in_select(shz_parser *p, token *t)
{
    switch (t->type) {
    case TOK_CHARS:
        insert_chars(p, t->chars, t->nchars);
        return;
    case TOK_COMMENT:
        insert_comment(p, t, NULL);
        return;
    case TOK_DOCTYPE:
        return;
    case TOK_EOF:
        in_body(p, t);
        return;
    case TOK_START:
        switch (t->tag) {
        case SHZ_TAG_HTML:
            in_body(p, t);
            return;
        case SHZ_TAG_OPTION:
            if (cur_is(p, SHZ_TAG_OPTION)) pop(p);
            insert_element(p, t);
            return;
        case SHZ_TAG_OPTGROUP:
            if (cur_is(p, SHZ_TAG_OPTION)) pop(p);
            if (cur_is(p, SHZ_TAG_OPTGROUP)) pop(p);
            insert_element(p, t);
            return;
        case SHZ_TAG_HR:
            if (cur_is(p, SHZ_TAG_OPTION)) pop(p);
            if (cur_is(p, SHZ_TAG_OPTGROUP)) pop(p);
            insert_void(p, t);
            return;
        case SHZ_TAG_SELECT:
            if (!in_scope(p, SHZ_TAG_SELECT, SCOPE_SELECT)) return;
            pop_until_tag(p, SHZ_TAG_SELECT);
            reset_insertion_mode(p);
            return;
        case SHZ_TAG_INPUT: case SHZ_TAG_KEYGEN: case SHZ_TAG_TEXTAREA:
            if (!in_scope(p, SHZ_TAG_SELECT, SCOPE_SELECT)) return;
            pop_until_tag(p, SHZ_TAG_SELECT);
            reset_insertion_mode(p);
            process(p, t, p->mode);
            return;
        case SHZ_TAG_SCRIPT: case SHZ_TAG_TEMPLATE:
            in_head(p, t);
            return;
        default:
            return;
        }
    case TOK_END:
        switch (t->tag) {
        case SHZ_TAG_OPTGROUP:
            if (cur_is(p, SHZ_TAG_OPTION) && p->stack.len >= 2
                && shz_is_tag(p->stack.items[p->stack.len - 2], SHZ_TAG_OPTGROUP))
                pop(p);
            if (cur_is(p, SHZ_TAG_OPTGROUP)) pop(p);
            return;
        case SHZ_TAG_OPTION:
            if (cur_is(p, SHZ_TAG_OPTION)) pop(p);
            return;
        case SHZ_TAG_SELECT:
            if (!in_scope(p, SHZ_TAG_SELECT, SCOPE_SELECT)) return;
            pop_until_tag(p, SHZ_TAG_SELECT);
            reset_insertion_mode(p);
            return;
        case SHZ_TAG_TEMPLATE:
            in_head(p, t);
            return;
        default:
            return;
        }
    }
}

static void in_select_in_table(shz_parser *p, token *t)
{
    static const int tags[] = { SHZ_TAG_CAPTION, SHZ_TAG_TABLE, SHZ_TAG_TBODY, SHZ_TAG_TFOOT, SHZ_TAG_THEAD, SHZ_TAG_TR,
                                SHZ_TAG_TD, SHZ_TAG_TH, 0 };
    if (t->type == TOK_START && tag_in(t->tag, tags)) {
        pop_until_tag(p, SHZ_TAG_SELECT);
        reset_insertion_mode(p);
        process(p, t, p->mode);
        return;
    }
    if (t->type == TOK_END && tag_in(t->tag, tags)) {
        if (!in_scope(p, t->tag, SCOPE_TABLE)) return;
        pop_until_tag(p, SHZ_TAG_SELECT);
        reset_insertion_mode(p);
        process(p, t, p->mode);
        return;
    }
    in_select(p, t);
}

/* ---------------------------------------------------------------------------------------------------- foreign */

static int breaks_out_of_foreign(token *t)
{
    static const int tags[] = {
        SHZ_TAG_B, SHZ_TAG_BIG, SHZ_TAG_BLOCKQUOTE, SHZ_TAG_BODY, SHZ_TAG_BR, SHZ_TAG_CENTER, SHZ_TAG_CODE,
        SHZ_TAG_DD, SHZ_TAG_DIV, SHZ_TAG_DL, SHZ_TAG_DT, SHZ_TAG_EM, SHZ_TAG_EMBED, SHZ_TAG_H1, SHZ_TAG_H2,
        SHZ_TAG_H3, SHZ_TAG_H4, SHZ_TAG_H5, SHZ_TAG_H6, SHZ_TAG_HEAD, SHZ_TAG_HR, SHZ_TAG_I, SHZ_TAG_IMG,
        SHZ_TAG_LI, SHZ_TAG_LISTING, SHZ_TAG_MENU, SHZ_TAG_META, SHZ_TAG_NOBR, SHZ_TAG_OL, SHZ_TAG_P, SHZ_TAG_PRE,
        SHZ_TAG_RUBY, SHZ_TAG_S, SHZ_TAG_SMALL, SHZ_TAG_SPAN, SHZ_TAG_STRONG, SHZ_TAG_STRIKE, SHZ_TAG_SUB,
        SHZ_TAG_SUP, SHZ_TAG_TABLE, SHZ_TAG_TT, SHZ_TAG_U, SHZ_TAG_UL, SHZ_TAG_VAR, 0
    };
    size_t len;
    if (t->type == TOK_END) return t->tag == SHZ_TAG_BR || t->tag == SHZ_TAG_P;
    if (tag_in(t->tag, tags)) return 1;
    return t->tag == SHZ_TAG_FONT && (attr_value(t, "color", &len) || attr_value(t, "face", &len)
                                      || attr_value(t, "size", &len));
}

static int is_html_integration_point(shz_node *n)
{
    shz_element *e = shz_elem(n);
    if (!e) return 0;
    if (e->ns == SHZ_NS_SVG)
        return shz_strieq_ascii(e->local, "foreignobject") || shz_streq_ascii(e->local, "desc")
               || shz_streq_ascii(e->local, "title");
    if (e->ns == SHZ_NS_MATHML && shz_streq_ascii(e->local, "annotation-xml")) {
        uint32_t i;
        for (i = 0; i < e->attr_count; ++i)
            if (shz_strieq_ascii(e->attrs[i].name, "encoding"))
                return shz_strieq_ascii(e->attrs[i].value, "text/html")
                       || shz_strieq_ascii(e->attrs[i].value, "application/xhtml+xml");
    }
    return 0;
}

static int is_mathml_text_integration_point(shz_node *n)
{
    shz_element *e = shz_elem(n);
    return e && e->ns == SHZ_NS_MATHML
           && (shz_streq_ascii(e->local, "mi") || shz_streq_ascii(e->local, "mo") || shz_streq_ascii(e->local, "mn")
               || shz_streq_ascii(e->local, "ms") || shz_streq_ascii(e->local, "mtext"));
}

/* Returns 1 when the token was handled by the "rules for parsing tokens in foreign content". */
static int foreign_content(shz_parser *p, token *t)
{
    shz_node *acn = adjusted_cur(p);
    shz_element *e = shz_elem(acn);
    if (!e || e->ns == SHZ_NS_HTML || t->type == TOK_EOF) return 0;
    if (is_mathml_text_integration_point(acn) && (t->type == TOK_CHARS || (t->type == TOK_START
        && !(t->name.len == 6 && shz_strneq_ascii(t->name.s, 6, "mglyph"))
        && !(t->name.len == 10 && shz_strneq_ascii(t->name.s, 10, "malignmark")))))
        return 0;
    if (e->ns == SHZ_NS_MATHML && shz_streq_ascii(e->local, "annotation-xml") && t->type == TOK_START
        && t->tag == SHZ_TAG_SVG)
        return 0;
    if (is_html_integration_point(acn) && (t->type == TOK_START || t->type == TOK_CHARS)) return 0;

    switch (t->type) {
    case TOK_CHARS: {
        size_t i;
        shz_buf b;
        shz_buf_init(&b);
        for (i = 0; i < t->nchars; ++i) shz_buf_putc(&b, t->chars[i] ? t->chars[i] : 0xFFFD);
        insert_chars(p, b.s, b.len);
        if (!all_ws(t)) p->frameset_ok = 0;
        shz_buf_free(&b);
        return 1;
    }
    case TOK_COMMENT:
        insert_comment(p, t, NULL);
        return 1;
    case TOK_DOCTYPE:
        return 1;
    case TOK_START:
        if (breaks_out_of_foreign(t)) {
            while (p->stack.len > 1) {
                shz_node *n = cur(p);
                if (is_html_elem(n) || is_mathml_text_integration_point(n) || is_html_integration_point(n)) break;
                pop(p);
            }
            process_mode(p, t, p->mode);
            return 1;
        }
        if (insert_element_ns(p, t, e->ns) && t->self_closing) pop(p);
        return 1;
    case TOK_END: {
        size_t i = p->stack.len;
        if (breaks_out_of_foreign(t)) {
            while (p->stack.len > 1) {
                shz_node *n = cur(p);
                if (is_html_elem(n) || is_mathml_text_integration_point(n) || is_html_integration_point(n)) break;
                pop(p);
            }
            process_mode(p, t, p->mode);
            return 1;
        }
        while (i--) {
            shz_node *n = p->stack.items[i];
            shz_element *ne = shz_elem(n);
            if (i == 0) return 1;
            if (ne && ne->ns != SHZ_NS_HTML && shz_strnieq(ne->local, shz_strlen(ne->local), t->name.s, t->name.len)) {
                pop_until_node(p, n);
                return 1;
            }
            if (ne && ne->ns == SHZ_NS_HTML) {
                process_mode(p, t, p->mode);
                return 1;
            }
        }
        return 1;
    }
    default:
        return 0;
    }
}

/* ---------------------------------------------------------------------------------------------------- XML */

/* XML element: the namespace comes from an xmlns attribute or is inherited from the parent element */
static shz_node *xml_create(shz_parser *p, token *t)
{
    size_t len, i;
    const shz_char *v = attr_value(t, "xmlns", &len);
    shz_node *parent = cur(p), *n;
    shz_char *uri = NULL;
    if (v) uri = shz_strndup(v, len);
    else if (parent && parent->type == SHZ_ELEMENT_NODE) uri = shz_elem_namespace(parent);
    n = shz_create_element_ns(p->doc, uri, t->name.s, t->name.len);
    shz_free(uri);
    if (!n) return NULL;
    for (i = 0; i < t->nattrs; ++i) {
        tok_attr *a = &t->attrs[i];
        if (a->dup || !a->name.len) continue;
        shz_elem_add_attr_raw(n, a->name.s, a->name.len, a->value.s ? a->value.s : a->name.s, a->value.len);
    }
    n->flags |= SHZ_NF_CREATED_BY_PARSER;
    return n;
}

static void xml_mode(shz_parser *p, token *t)
{
    switch (t->type) {
    case TOK_CHARS:
        if (!p->stack.len) return;
        insert_chars(p, t->chars, t->nchars);
        return;
    case TOK_COMMENT:
        if (t->data.len && t->data.s[0] == '?') {
            /* processing instruction "<?target data?>" */
            size_t i = 1, ts, te, n = t->data.len;
            shz_node *pi;
            shz_char *target;
            ts = i;
            while (i < n && !is_ws(t->data.s[i]) && t->data.s[i] != '?') ++i;
            te = i;
            while (i < n && is_ws(t->data.s[i])) ++i;
            if (n > i && t->data.s[n - 1] == '?') --n;
            if (te == ts || shz_strnieq_ascii(t->data.s + ts, te - ts, "xml")) return;
            target = shz_strndup(t->data.s + ts, te - ts);
            if (!target) return;
            pi = shz_create_pi(p->doc, target, t->data.s + i, n > i ? n - i : 0);
            shz_free(target);
            if (!pi) return;
            shz_dom_insert_raw(p->stack.len ? cur(p) : p->doc->node, pi, NULL);
            shz_node_release(pi);
            return;
        }
        insert_comment(p, t, p->stack.len ? cur(p) : p->doc->node);
        return;
    case TOK_DOCTYPE: {
        shz_char *name = shz_strndup(t->name.s, t->name.len), *pub = NULL, *sys = NULL;
        shz_node *dt;
        if (t->has_public) pub = shz_strndup(t->public_id.s, t->public_id.len);
        if (t->has_system) sys = shz_strndup(t->system_id.s, t->system_id.len);
        dt = name ? shz_create_doctype(p->doc, name, pub, sys) : NULL;
        if (dt && !p->stack.len && !shz_doc_doctype(p->doc)) shz_dom_insert_raw(p->doc->node, dt, NULL);
        if (dt) shz_node_release(dt);
        shz_free(name);
        shz_free(pub);
        shz_free(sys);
        return;
    }
    case TOK_START: {
        shz_node *n;
        if (!p->stack.len && shz_doc_element(p->doc)) return;       /* one document element */
        n = xml_create(p, t);
        if (!n) return;
        shz_dom_insert_raw(p->stack.len ? cur(p) : (p->fragment ? p->root : p->doc->node), n, NULL);
        if (!t->self_closing) push(p, n);
        shz_node_release(n);
        return;
    }
    case TOK_END: {
        size_t i = p->stack.len;
        while (i--) {
            shz_element *e = shz_elem(p->stack.items[i]);
            if (e && shz_strneq(e->qname, e->qname_len, t->name.s, t->name.len)) {
                pop_until_node(p, &e->node);
                return;
            }
        }
        return;
    }
    case TOK_EOF:
        p->done = 1;
        return;
    }
}

/* ---------------------------------------------------------------------------------------------------- dispatch */

/* the rules of an insertion mode ("in HTML content"), without the foreign-content dispatch */
static void process_mode(shz_parser *p, token *t, int mode)
{
    p->mode = mode;
    if (p->done) return;
    switch (mode) {
    case IM_XML:
        xml_mode(p, t);
        return;
    case IM_INITIAL:
        if (t->type == TOK_CHARS) {
            size_t ws = leading_ws(t);
            t->chars += ws;
            t->nchars -= ws;
            if (!t->nchars) return;
        } else if (t->type == TOK_COMMENT) {
            insert_comment(p, t, p->doc->node);
            return;
        } else if (t->type == TOK_DOCTYPE) {
            shz_char *name = shz_strndup(t->name.s, t->name.len), *pub = NULL, *sys = NULL;
            shz_node *dt;
            if (t->has_public) pub = shz_strndup(t->public_id.s, t->public_id.len);
            if (t->has_system) sys = shz_strndup(t->system_id.s, t->system_id.len);
            set_doctype_quirks(p, t);
            dt = name ? shz_create_doctype(p->doc, name, pub, sys) : NULL;
            shz_free(name);
            shz_free(pub);
            shz_free(sys);
            if (dt) {
                shz_dom_insert_raw(p->doc->node, dt, NULL);
                shz_node_release(dt);
            }
            p->mode = IM_BEFORE_HTML;
            return;
        }
        p->doc->doctype_quirks = SHZ_QUIRKS_FULL;
        process(p, t, IM_BEFORE_HTML);
        return;
    case IM_BEFORE_HTML:
        if (t->type == TOK_DOCTYPE) return;
        if (t->type == TOK_COMMENT) { insert_comment(p, t, p->doc->node); return; }
        if (t->type == TOK_CHARS) {
            size_t ws = leading_ws(t);
            t->chars += ws;
            t->nchars -= ws;
            if (!t->nchars) return;
        } else if (t->type == TOK_START && t->tag == SHZ_TAG_HTML) {
            shz_node *h = create_for_token(p, t, SHZ_NS_HTML);
            if (!h) return;
            shz_dom_insert_raw(p->doc->node, h, NULL);
            push(p, h);
            shz_node_release(h);
            p->mode = IM_BEFORE_HEAD;
            return;
        } else if (t->type == TOK_END && t->tag != SHZ_TAG_HEAD && t->tag != SHZ_TAG_BODY && t->tag != SHZ_TAG_HTML
                   && t->tag != SHZ_TAG_BR) {
            return;
        }
        {
            shz_node *h = shz_create_element_tag(p->doc, SHZ_TAG_HTML);
            if (!h) return;
            h->flags |= SHZ_NF_CREATED_BY_PARSER;
            shz_dom_insert_raw(p->doc->node, h, NULL);
            push(p, h);
            shz_node_release(h);
        }
        process(p, t, IM_BEFORE_HEAD);
        return;
    case IM_BEFORE_HEAD:
        if (t->type == TOK_CHARS) {
            size_t ws = leading_ws(t);
            t->chars += ws;
            t->nchars -= ws;
            if (!t->nchars) return;
        } else if (t->type == TOK_COMMENT) {
            insert_comment(p, t, NULL);
            return;
        } else if (t->type == TOK_DOCTYPE) {
            return;
        } else if (t->type == TOK_START && t->tag == SHZ_TAG_HTML) {
            in_body(p, t);
            return;
        } else if (t->type == TOK_START && t->tag == SHZ_TAG_HEAD) {
            shz_node *h = insert_element(p, t);
            if (h) { shz_node_addref(h); p->head = h; }
            p->mode = IM_IN_HEAD;
            return;
        } else if (t->type == TOK_END && t->tag != SHZ_TAG_HEAD && t->tag != SHZ_TAG_BODY && t->tag != SHZ_TAG_HTML
                   && t->tag != SHZ_TAG_BR) {
            return;
        }
        {
            shz_node *h = insert_tag(p, SHZ_TAG_HEAD);
            if (h) { shz_node_addref(h); p->head = h; }
        }
        process(p, t, IM_IN_HEAD);
        return;
    case IM_IN_HEAD:
    case IM_IN_HEAD_NOSCRIPT:
        if (in_head(p, t)) return;
        pop(p);             /* the head element */
        process(p, t, IM_AFTER_HEAD);
        return;
    case IM_AFTER_HEAD:
        if (t->type == TOK_CHARS) {
            size_t ws = leading_ws(t);
            if (ws) {
                insert_chars(p, t->chars, ws);
                t->chars += ws;
                t->nchars -= ws;
            }
            if (!t->nchars) return;
        } else if (t->type == TOK_COMMENT) {
            insert_comment(p, t, NULL);
            return;
        } else if (t->type == TOK_DOCTYPE) {
            return;
        } else if (t->type == TOK_START) {
            switch (t->tag) {
            case SHZ_TAG_HTML:
                in_body(p, t);
                return;
            case SHZ_TAG_BODY:
                insert_element(p, t);
                p->frameset_ok = 0;
                p->mode = IM_IN_BODY;
                return;
            case SHZ_TAG_FRAMESET:
                insert_element(p, t);
                p->mode = IM_IN_FRAMESET;
                return;
            case SHZ_TAG_BASE: case SHZ_TAG_BASEFONT: case SHZ_TAG_BGSOUND: case SHZ_TAG_LINK: case SHZ_TAG_META:
            case SHZ_TAG_NOFRAMES: case SHZ_TAG_SCRIPT: case SHZ_TAG_STYLE: case SHZ_TAG_TEMPLATE:
            case SHZ_TAG_TITLE:
                if (p->head) {
                    shz_node *h = p->head;
                    push(p, h);
                    in_head(p, t);
                    remove_from_stack(p, h);
                } else {
                    in_head(p, t);
                }
                return;
            case SHZ_TAG_HEAD:
                return;
            default:
                break;
            }
        } else if (t->type == TOK_END) {
            if (t->tag == SHZ_TAG_TEMPLATE) { in_head(p, t); return; }
            if (t->tag != SHZ_TAG_BODY && t->tag != SHZ_TAG_HTML && t->tag != SHZ_TAG_BR) return;
        }
        insert_tag(p, SHZ_TAG_BODY);
        process(p, t, IM_IN_BODY);
        return;
    case IM_IN_BODY:
        in_body(p, t);
        return;
    case IM_TEXT:
        if (t->type == TOK_CHARS) {
            insert_chars(p, t->chars, t->nchars);
            return;
        }
        if (t->type == TOK_EOF) {
            if (cur_is(p, SHZ_TAG_SCRIPT)) cur(p)->flags |= SHZ_NF_STARTED;
            pop(p);
            process(p, t, p->orig_mode);
            return;
        }
        if (t->type == TOK_END && t->tag == SHZ_TAG_SCRIPT && cur_is(p, SHZ_TAG_SCRIPT)) {
            shz_node *script = cur(p);
            shz_node_addref(script);
            pop(p);
            p->mode = p->orig_mode;
            run_script(p, script);
            shz_node_release(script);
            return;
        }
        if (t->type == TOK_END) {
            pop(p);
            p->mode = p->orig_mode;
        }
        return;
    case IM_IN_TABLE:
        in_table(p, t);
        return;
    case IM_IN_TABLE_TEXT:
        in_table_text(p, t);
        return;
    case IM_IN_CAPTION:
        in_caption(p, t);
        return;
    case IM_IN_COLUMN_GROUP:
        in_column_group(p, t);
        return;
    case IM_IN_TABLE_BODY:
        in_table_body(p, t);
        return;
    case IM_IN_ROW:
        in_row(p, t);
        return;
    case IM_IN_CELL:
        in_cell(p, t);
        return;
    case IM_IN_SELECT:
        in_select(p, t);
        return;
    case IM_IN_SELECT_IN_TABLE:
        in_select_in_table(p, t);
        return;
    case IM_AFTER_BODY:
        if (t->type == TOK_CHARS && all_ws(t)) { in_body(p, t); return; }
        if (t->type == TOK_COMMENT) {
            insert_comment(p, t, p->stack.len ? p->stack.items[0] : p->doc->node);
            return;
        }
        if (t->type == TOK_DOCTYPE) return;
        if (t->type == TOK_START && t->tag == SHZ_TAG_HTML) { in_body(p, t); return; }
        if (t->type == TOK_END && t->tag == SHZ_TAG_HTML) {
            if (!p->fragment) p->mode = IM_AFTER_AFTER_BODY;
            return;
        }
        if (t->type == TOK_EOF) { p->done = 1; return; }
        process(p, t, IM_IN_BODY);
        return;
    case IM_IN_FRAMESET:
        if (t->type == TOK_CHARS) {
            size_t i;
            for (i = 0; i < t->nchars; ++i)
                if (is_ws(t->chars[i])) insert_chars(p, t->chars + i, 1);
            return;
        }
        if (t->type == TOK_COMMENT) { insert_comment(p, t, NULL); return; }
        if (t->type == TOK_START) {
            if (t->tag == SHZ_TAG_HTML) { in_body(p, t); return; }
            if (t->tag == SHZ_TAG_FRAMESET) { insert_element(p, t); return; }
            if (t->tag == SHZ_TAG_FRAME) { insert_void(p, t); return; }
            if (t->tag == SHZ_TAG_NOFRAMES) { in_head(p, t); return; }
            return;
        }
        if (t->type == TOK_END && t->tag == SHZ_TAG_FRAMESET) {
            if (cur_is(p, SHZ_TAG_HTML)) return;
            pop(p);
            if (!p->fragment && !cur_is(p, SHZ_TAG_FRAMESET)) p->mode = IM_AFTER_FRAMESET;
            return;
        }
        if (t->type == TOK_EOF) { p->done = 1; return; }
        return;
    case IM_AFTER_FRAMESET:
        if (t->type == TOK_CHARS) {
            size_t i;
            for (i = 0; i < t->nchars; ++i)
                if (is_ws(t->chars[i])) insert_chars(p, t->chars + i, 1);
            return;
        }
        if (t->type == TOK_COMMENT) { insert_comment(p, t, NULL); return; }
        if (t->type == TOK_START && t->tag == SHZ_TAG_HTML) { in_body(p, t); return; }
        if (t->type == TOK_END && t->tag == SHZ_TAG_HTML) { p->mode = IM_AFTER_AFTER_FRAMESET; return; }
        if (t->type == TOK_START && t->tag == SHZ_TAG_NOFRAMES) { in_head(p, t); return; }
        if (t->type == TOK_EOF) { p->done = 1; return; }
        return;
    case IM_AFTER_AFTER_BODY:
        if (t->type == TOK_COMMENT) { insert_comment(p, t, p->doc->node); return; }
        if (t->type == TOK_DOCTYPE || (t->type == TOK_CHARS && all_ws(t))
            || (t->type == TOK_START && t->tag == SHZ_TAG_HTML)) {
            in_body(p, t);
            return;
        }
        if (t->type == TOK_EOF) { p->done = 1; return; }
        process(p, t, IM_IN_BODY);
        return;
    case IM_AFTER_AFTER_FRAMESET:
        if (t->type == TOK_COMMENT) { insert_comment(p, t, p->doc->node); return; }
        if (t->type == TOK_DOCTYPE || (t->type == TOK_CHARS && all_ws(t))
            || (t->type == TOK_START && t->tag == SHZ_TAG_HTML)) {
            in_body(p, t);
            return;
        }
        if (t->type == TOK_EOF) { p->done = 1; return; }
        if (t->type == TOK_START && t->tag == SHZ_TAG_NOFRAMES) { in_head(p, t); return; }
        return;
    default:
        in_body(p, t);
        return;
    }
}

/* tree construction dispatcher (13.2.6): foreign content or the current insertion mode */
static void process(shz_parser *p, token *t, int mode)
{
    p->mode = mode;
    if (p->done) return;
    if (mode != IM_XML && mode != IM_TEXT && foreign_content(p, t)) return;
    process_mode(p, t, mode);
}

/* ---------------------------------------------------------------------------------------------------- entry */

void shz_tree_init(shz_parser *p)
{
    shz_vec_init(&p->stack);
    shz_vec_init(&p->fmt);
    shz_buf_init(&p->table_chars);
    p->mode = p->xml ? IM_XML : IM_INITIAL;
    p->frameset_ok = 1;
}

void shz_tree_free(shz_parser *p)
{
    while (p->stack.len) {
        shz_node *n = p->stack.items[--p->stack.len];
        shz_node_release(n);
    }
    shz_vec_free(&p->stack);
    while (p->fmt.len) {
        shz_node *n = p->fmt.items[--p->fmt.len];
        if (n) shz_node_release(n);
    }
    shz_vec_free(&p->fmt);
    shz_buf_free(&p->table_chars);
    if (p->head) shz_node_release(p->head);
    if (p->form) shz_node_release(p->form);
    p->head = p->form = NULL;
    p->title_open = 0;
}

void shz_tree_setup_fragment(shz_parser *p)
{
    shz_node *f;
    int tag = shz_tag_of(p->context);
    push(p, p->root);
    switch (tag) {
    case SHZ_TAG_TITLE: case SHZ_TAG_TEXTAREA: p->state = TS_RCDATA; break;
    case SHZ_TAG_STYLE: case SHZ_TAG_XMP: case SHZ_TAG_IFRAME: case SHZ_TAG_NOEMBED: case SHZ_TAG_NOFRAMES:
    case SHZ_TAG_NOSCRIPT:
        p->state = TS_RAWTEXT;
        break;
    case SHZ_TAG_SCRIPT: p->state = TS_SCRIPT; break;
    case SHZ_TAG_PLAINTEXT: p->state = TS_PLAINTEXT; break;
    default: p->state = TS_DATA; break;
    }
    p->text_state = p->state;
    reset_insertion_mode(p);
    for (f = p->context; f; f = f->parent) {
        if (shz_is_tag(f, SHZ_TAG_FORM)) {
            shz_node_addref(f);
            p->form = f;
            break;
        }
    }
}

void shz_tree_token(shz_parser *p, token *t)
{
    token copy;
    if (p->done) return;
    if (p->skip_lf) {
        p->skip_lf = 0;
        if (t->type == TOK_CHARS && t->nchars && t->chars[0] == '\n') {
            copy = *t;
            ++copy.chars;
            --copy.nchars;
            if (!copy.nchars) return;
            t = &copy;
        }
    }
    if (t->type == TOK_CHARS) {
        /* the modes consume the characters in place: work on a copy of the descriptor */
        copy = *t;
        t = &copy;
    }
    process(p, t, p->mode);
    if (p->done) {
        /* stop parsing: pop everything */
        while (p->stack.len) pop(p);
    }
}
