/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: scripts and document.write. Expected behaviour: WHATWG HTML "parsing HTML documents" (a parser-inserted
 * script runs when its end tag is parsed, with the parser paused; document.write inserts at the insertion point and
 * is tokenized immediately, nested writes included; after the load, write implies open), "prepare the script"
 * (connected, not already started, run once), and engine.h's host callbacks (node_inserted per node, the host may
 * mutate the tree from it).
 */
#include "host_test.h"

static shz_node *byid(shz_doc *doc, const char *id)
{
    return shz_doc_get_element_by_id(doc, T(id));
}

/* ---- 1. timing: the script runs when </script> is parsed */
static int seen_a, seen_b, script_calls, parser_flag;
static char script_text[64];

static void on_script_timing(t_host *h, shz_doc *doc, shz_node *script, int parser_inserted)
{
    (void)h;
    ++script_calls;
    parser_flag = parser_inserted;
    seen_a = byid(doc, "a") != NULL;
    seen_b = byid(doc, "b") != NULL;
    snprintf(script_text, sizeof(script_text), "%s", U8take(shz_node_text_content(script)));
}

/* ---- 2. document.write */
static void on_script_write(t_host *h, shz_doc *doc, shz_node *script, int parser_inserted)
{
    const char *text = U8take(shz_node_text_content(script));
    (void)h;
    (void)parser_inserted;
    ++script_calls;
    if (!strcmp(text, "w1")) {
        const shz_char *w = T("<p id=w>written</p>");
        shz_doc_write(doc, w, shz_strlen(w), 0);
        T_INTEQ("written element exists right after write()", byid(doc, "w") != NULL, 1);
    } else if (!strcmp(text, "two")) {
        const shz_char *w1 = T("<b id=bb>1"), *w2 = T("2</b>");
        shz_doc_write(doc, w1, shz_strlen(w1), 0);
        shz_doc_write(doc, w2, shz_strlen(w2), 0);
    } else if (!strcmp(text, "outer")) {
        const shz_char *w = T("<script>inner</script><i id=after-inner></i>");
        shz_doc_write(doc, w, shz_strlen(w), 0);
    } else if (!strcmp(text, "inner")) {
        const shz_char *w = T("<i id=deep></i>");
        shz_doc_write(doc, w, shz_strlen(w), 0);
    } else if (!strcmp(text, "open")) {
        const shz_char *w = T("<div id=wd>");
        shz_doc_write(doc, w, shz_strlen(w), 0);
    } else if (!strcmp(text, "ln")) {
        const shz_char *w = T("x");
        shz_doc_write(doc, w, 1, 1);
    }
}

/* ---- 3. the host replaces conditional comments from node_inserted (what mshtml does) */
static void on_inserted_cc(t_host *h, shz_doc *doc, shz_node *node)
{
    shz_chardata *c = shz_cdata(node);
    (void)h;
    (void)doc;
    if (node->type == SHZ_COMMENT_NODE && c->len > 9 && !memcmp(c->data, T("[if IE]>"), 8 * sizeof(shz_char))) {
        /* "[if IE]>" ... "<![endif]" */
        size_t n = c->len - 8 - 9;
        shz_node *frag = NULL, *parent = node->parent;
        if (shz_parse_fragment(parent, c->data + 8, n, &frag) == SHZ_OK) {
            shz_node_replace_child(parent, frag, node);
            shz_node_release(frag);
        }
    }
}

static const char *body_of(shz_doc *doc)
{
    return U8take(shz_serialize(shz_doc_body(doc), 0));
}

int main(void)
{
    t_host h;
    shz_doc *doc;
    shz_node *s, *body;
    const shz_char *w;

    /* 1 */
    memset(&h, 0, sizeof(h));
    doc = t_new_doc(&h);
    h.on_script = on_script_timing;
    w = T("<p id=a>a</p><script>s1</script><p id=b>b</p>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    T_INTEQ("run_script called once", script_calls, 1);
    T_INTEQ("parser_inserted flag", parser_flag, 1);
    T_INTEQ("content before the script is parsed", seen_a, 1);
    T_INTEQ("content after the script is not parsed yet", seen_b, 0);
    T_STREQ("the script's text is complete", script_text, "s1");
    T_INTEQ("parse_done once", h.parse_done, 1);
    T_INTEQ("load_done once", h.load_done, 1);
    T_INTEQ("readyState complete", doc->ready_state, SHZ_READY_COMPLETE);
    shz_doc_release(doc);

    /* incremental: the script end tag arrives in pieces */
    script_calls = 0;
    doc = t_new_doc(&h);
    h.on_script = on_script_timing;
    shz_parser_begin(doc, T("utf-8"));
    shz_parser_feed(doc, (const uint8_t *)"<p id=a></p><script>a", 21);
    T_INTEQ("no run before </script>", script_calls, 0);
    shz_parser_feed(doc, (const uint8_t *)"bc</scr", 7);
    T_INTEQ("still none on a partial end tag", script_calls, 0);
    shz_parser_feed(doc, (const uint8_t *)"ipt><p id=b>", 12);
    T_INTEQ("runs once the end tag is complete", script_calls, 1);
    T_STREQ("text across chunks", script_text, "abc");
    T_INTEQ("parse_done not before parser_end", h.parse_done, 0);
    shz_parser_end(doc);
    T_INTEQ("parse_done after parser_end", h.parse_done, 1);
    shz_doc_release(doc);

    /* 2 */
    script_calls = 0;
    doc = t_new_doc(&h);
    h.on_script = on_script_write;
    w = T("<script>w1</script><p id=b>b</p><script>two</script><script>outer</script><p id=c>c</p>"
          "<script>ln</script>|<script>open</script><p id=d>d</p>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    T_STREQ("document.write results",
            body_of(doc),
            "<p id=\"w\">written</p><p id=\"b\">b</p><script>two</script><b id=\"bb\">12</b>"
            "<script>outer</script><script>inner</script><i id=\"deep\"></i><i id=\"after-inner\"></i>"
            "<p id=\"c\">c</p><script>ln</script>x\n|<script>open</script><div id=\"wd\"><p id=\"d\">d</p></div>");
    T_INTEQ("six scripts ran (w1 two outer inner ln open)", script_calls, 6);
    T_STREQ("the first script is in <head> (before any body content)",
            U8take(shz_serialize(shz_doc_head(doc), 0)), "<script>w1</script>");
    shz_doc_release(doc);

    /* document.write after the load: implies document.open (the document is replaced) */
    doc = t_new_doc(&h);
    w = T("<p>old</p>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    w = T("<p id=n>new</p>");
    T_INTEQ("write after load", shz_doc_write(doc, w, shz_strlen(w), 0), SHZ_OK);
    T_STREQ("old content gone, new content parsed", body_of(doc), "<p id=\"n\">new</p>");
    T_INTEQ("a script-created parser waits for close()", h.parse_done, 1);
    T_INTEQ("readyState loading until close", doc->ready_state, SHZ_READY_LOADING);
    T_INTEQ("close", shz_doc_close(doc), SHZ_OK);
    T_INTEQ("parse_done after close", h.parse_done, 2);
    T_INTEQ("readyState complete after close", doc->ready_state, SHZ_READY_COMPLETE);
    shz_doc_release(doc);

    /* scripts inserted through the DOM run once; fragment scripts never */
    script_calls = 0;
    doc = t_new_doc(&h);
    h.on_script = on_script_timing;
    w = T("<body>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    body = shz_doc_body(doc);
    s = shz_create_element(doc, T("script"), 6);
    shz_node_set_text_content(s, T("dyn"));
    shz_node_append(body, s);
    T_INTEQ("DOM-inserted script runs", script_calls, 1);
    T_INTEQ("not parser-inserted", parser_flag, 0);
    shz_node_append(body, shz_create_text(doc, T("t"), 1));
    shz_node_release(body->last_child);
    shz_node_insert_before(body, s, NULL);
    T_INTEQ("moving it does not run it again", script_calls, 1);
    shz_node_release(s);
    {
        shz_node *frag = NULL;
        w = T("<script>frag</script>");
        shz_parse_fragment(body, w, shz_strlen(w), &frag);
        shz_node_append(body, frag);
        shz_node_release(frag);
        T_INTEQ("innerHTML scripts do not run", script_calls, 1);
    }
    s = shz_create_element(doc, T("script"), 6);
    shz_node_append(body, s);
    T_INTEQ("an empty script without src does not run", script_calls, 1);
    shz_node_release(s);
    shz_doc_release(doc);

    /* 3: the host rewrites conditional comments during parsing */
    memset(&h, 0, sizeof(h));
    doc = t_new_doc(&h);
    h.on_inserted = on_inserted_cc;
    w = T("<p>1</p><!--[if IE]><p id=cc>ie</p><![endif]--><p>2</p>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    T_STREQ("conditional comment replaced by its content, parsing continued", body_of(doc),
            "<p>1</p><p id=\"cc\">ie</p><p>2</p>");
    shz_doc_release(doc);

    /* title changes */
    memset(&h, 0, sizeof(h));
    doc = t_new_doc(&h);
    w = T("<title>a</title><body>");
    shz_doc_load_string(doc, w, shz_strlen(w));
    T_INTEQ("title_changed once for the parsed title", h.title_changed, 1);
    {
        shz_node *title = shz_doc_head(doc)->first_child;
        shz_node_set_text_content(title, T("b"));
        T_INTEQ("title_changed when the title text changes", h.title_changed >= 2, 1);
        T_STREQ("document title", U8take(shz_doc_title(doc)), "b");
    }
    shz_doc_release(doc);
    return t_finish("t_script");
}
