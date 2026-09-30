/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident engine API (version 1)
 *
 * The contract between the Trident compatibility layer (Wine's mshtml, which talks to its layout engine only through
 * the Gecko binding, re-implemented by trident/xul as an adaptor over this API) and a layout/script engine backend:
 *
 *   iexplore.exe / WebBrowser control (ieframe) -> mshtml.dll (IHTMLDocument2, IHTMLElement, document.all, attachEvent,
 *   window.event, currentStyle, document modes, conditional comments, IActiveScript hosting ...)
 *     -> xul.dll (trident/xul: the nsI* interfaces mshtml calls, implemented over this header)
 *       -> engine backend DLL: shzlite.dll (trident/engine, the minimal engine) or the WebKit backend (W3's WebCore)
 *
 * A backend is a DLL exporting
 *     const shzeng_vtbl * WINAPI ShzEngineGetInterface(UINT api_version);
 * which returns NULL when it cannot serve api_version. Selection (trident/xul/select.c): the WebKit backend is used by
 * default when its DLL loads and serves SHZENG_API_VERSION; otherwise shzlite.dll. HKCU\Software\Shizuku\Trident
 * value "Engine" (REG_SZ "webkit" | "lite") or the environment variable SHZ_TRIDENT_ENGINE overrides the choice.
 *
 * Conventions
 * - Every entry returns HRESULT unless stated otherwise. S_OK = done; S_FALSE = "no value" (absent attribute, null
 *   string, no such node): the out parameter is then NULL/0. E_NOTIMPL = the backend does not implement this entry
 *   (the adaptor maps it to NS_ERROR_NOT_IMPLEMENTED and Wine's mshtml reports its usual FIXME/E_FAIL).
 *   A vtbl slot may also be NULL, which means the same as E_NOTIMPL. Slots marked [required] are never NULL.
 * - Strings are UTF-16 (WCHAR). Input strings are NUL-terminated unless a length is given. Output strings are
 *   allocated by the backend and released by the caller with vtbl->str_free(); an absent string is NULL + S_FALSE.
 * - Handles are opaque pointers owned by the backend. Nodes, lists, styles, events and ranges are reference counted:
 *   every handle returned to the caller carries one reference that the caller releases with the matching *_release.
 *   The same DOM node is always returned as the same shzeng_node pointer (identity is comparable with ==).
 * - Threading: one document and everything reachable from it is used from a single thread (the apartment thread that
 *   created it). Backends may assume that; callbacks are delivered on that thread.
 * - Coordinates are CSS pixels relative to the document's initial containing block unless stated otherwise; the
 *   minimal engine uses 1 CSS px = 1 device px (96 DPI).
 */
#ifndef SHIZUKU_TRIDENT_ENGINE_H
#define SHIZUKU_TRIDENT_ENGINE_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHZENG_API_VERSION 1

typedef struct shzeng_doc shzeng_doc;       /* a document (HTML, or XML for DOMParser) */
typedef struct shzeng_node shzeng_node;     /* any DOM node: document, doctype, element, text, comment, fragment, attr */
typedef struct shzeng_list shzeng_list;     /* a node list or collection (live unless stated otherwise) */
typedef struct shzeng_style shzeng_style;   /* a CSS declaration block: inline, computed or a rule's */
typedef struct shzeng_event shzeng_event;   /* a DOM event being dispatched */
typedef struct shzeng_view shzeng_view;     /* a document presented in a window */
typedef struct shzeng_range shzeng_range;   /* a DOM range */
typedef struct shzeng_sheet shzeng_sheet;   /* a style sheet */

/* backend capabilities (shzeng_vtbl.caps) */
#define SHZENG_CAP_LAYOUT      0x0001   /* lays out and paints documents */
#define SHZENG_CAP_SCRIPT      0x0002   /* script_eval works (the backend owns a JavaScript engine) */
#define SHZENG_CAP_CSSOM       0x0004   /* style sheets and computed style */
#define SHZENG_CAP_RANGES      0x0008   /* range_* and selection */
#define SHZENG_CAP_EDITING     0x0010   /* designMode / execCommand */
#define SHZENG_CAP_IMAGES      0x0020   /* decodes and paints <img> */
#define SHZENG_CAP_FORMS       0x0040   /* renders and edits form controls */
#define SHZENG_CAP_PRINT       0x0080   /* paginate / print_page */

/* node types: DOM Level 1 values */
#define SHZENG_ELEMENT_NODE                 1
#define SHZENG_ATTRIBUTE_NODE               2
#define SHZENG_TEXT_NODE                    3
#define SHZENG_CDATA_SECTION_NODE           4
#define SHZENG_PROCESSING_INSTRUCTION_NODE  7
#define SHZENG_COMMENT_NODE                 8
#define SHZENG_DOCUMENT_NODE                9
#define SHZENG_DOCUMENT_TYPE_NODE          10
#define SHZENG_DOCUMENT_FRAGMENT_NODE      11

/* document (compat) modes, set by the Trident layer (Wine's compat_mode_t order). The backend lays out QUIRKS and IE5
 * in quirks mode, IE7 in "almost standards" (limited quirks), IE8 and later in standards mode. */
typedef enum {
    SHZENG_MODE_QUIRKS = 0, SHZENG_MODE_IE5, SHZENG_MODE_IE7, SHZENG_MODE_IE8, SHZENG_MODE_IE9, SHZENG_MODE_IE10,
    SHZENG_MODE_IE11
} shzeng_mode;

/* collections a document keeps (doc_collection) */
typedef enum {
    SHZENG_COLL_ALL = 0, SHZENG_COLL_FORMS, SHZENG_COLL_IMAGES, SHZENG_COLL_LINKS, SHZENG_COLL_ANCHORS,
    SHZENG_COLL_SCRIPTS, SHZENG_COLL_APPLETS, SHZENG_COLL_EMBEDS
} shzeng_collection;

/* get_elements_by */
typedef enum { SHZENG_BY_TAG = 0, SHZENG_BY_CLASS, SHZENG_BY_NAME, SHZENG_BY_TAG_NS } shzeng_by;

/* element boxes (elem_box) */
typedef enum {
    SHZENG_BOX_OFFSET = 0,   /* offsetLeft/Top/Width/Height, relative to elem_offset_parent's padding edge */
    SHZENG_BOX_CLIENT,       /* clientLeft/Top/Width/Height (padding box without scroll bars; left/top = border widths) */
    SHZENG_BOX_SCROLL,       /* scrollLeft/Top/Width/Height */
    SHZENG_BOX_BORDER        /* border box relative to the viewport (getBoundingClientRect) */
} shzeng_box;

/* event classes (event_kind), matching Wine's EVENT_TYPE_* order as far as it goes */
typedef enum {
    SHZENG_EVENT_GENERIC = 0, SHZENG_EVENT_UI, SHZENG_EVENT_KEYBOARD, SHZENG_EVENT_MOUSE, SHZENG_EVENT_FOCUS,
    SHZENG_EVENT_PROGRESS, SHZENG_EVENT_CUSTOM, SHZENG_EVENT_MESSAGE
} shzeng_event_kind;

typedef struct shzeng_mouse {
    LONG client_x, client_y, screen_x, screen_y, page_x, page_y, offset_x, offset_y;
    USHORT button;            /* DOM button: 0 left, 1 middle, 2 right */
    USHORT buttons;           /* DOM buttons bit mask */
    BOOL ctrl, shift, alt, meta;
    shzeng_node *related;     /* relatedTarget (a new reference, may be NULL) */
    LONG detail;              /* click count */
} shzeng_mouse;

typedef struct shzeng_key {
    UINT key_code;            /* legacy keyCode (virtual-key code) */
    UINT char_code;           /* legacy charCode for keypress */
    WCHAR key[32];            /* KeyboardEvent.key */
    UINT location;
    BOOL repeat, ctrl, shift, alt, meta;
} shzeng_key;

/* Receives the bytes of a fetched resource (host_callbacks.fetch). The backend implements it; the host calls it. */
typedef struct shzeng_sink shzeng_sink;
typedef struct shzeng_sink_vtbl {
    void (*start)(shzeng_sink *sink, const WCHAR *final_url, const WCHAR *mime, const WCHAR *charset);
    void (*data)(shzeng_sink *sink, const void *bytes, SIZE_T len);
    void (*done)(shzeng_sink *sink, HRESULT status);      /* always called exactly once, also after a failure */
} shzeng_sink_vtbl;
struct shzeng_sink { const shzeng_sink_vtbl *vtbl; };

/* resource kinds for host_callbacks.fetch */
typedef enum { SHZENG_FETCH_STYLESHEET = 0, SHZENG_FETCH_IMAGE, SHZENG_FETCH_SCRIPT, SHZENG_FETCH_FRAME, SHZENG_FETCH_OTHER } shzeng_fetch_kind;

/* Callbacks from the backend to the Trident layer. Every member may be NULL. ctx is the pointer given to doc_create.
 * They replace Gecko's nsIDocumentObserver (node_inserted, parse_done), nsIContentUtils script runners (run_script),
 * nsIDOMEventListener (event), the network channel (fetch), nsIWebBrowserChrome (status_text, title_changed) and the
 * context-menu/tooltip listeners. */
typedef struct shzeng_host {
    /* A node became part of the document (parser insertion or DOM mutation). Called once per node, in tree order,
     * after it was attached; Wine's mshtml uses it for <meta http-equiv>, conditional comments, <script>, <iframe>,
     * <object>, on* attributes. The host may mutate the tree from inside this callback (e.g. replace a comment). */
    void (*node_inserted)(void *ctx, shzeng_doc *doc, shzeng_node *node);
    void (*node_removed)(void *ctx, shzeng_doc *doc, shzeng_node *node);
    /* Parsing finished (all bytes fed and parser_end called, blocking scripts run): DOMContentLoaded time. */
    void (*parse_done)(void *ctx, shzeng_doc *doc);
    /* A <script> element is ready to run (inline: when its end tag is parsed; external: the host fetches it itself).
     * parser_inserted: TRUE when the parser inserted it; the parser is paused until the callback returns. */
    void (*run_script)(void *ctx, shzeng_doc *doc, shzeng_node *script, BOOL parser_inserted);
    /* An event reached a listener registered with add_listener. Return S_FALSE to request preventDefault. */
    HRESULT (*event)(void *ctx, shzeng_node *current_target, shzeng_event *event, void *listener_cookie);
    /* The backend needs a sub-resource (style sheet, image, frame document). The host loads it asynchronously and
     * reports to sink; returning a failure means the resource is unavailable (sink is not called then). */
    HRESULT (*fetch)(void *ctx, shzeng_doc *doc, const WCHAR *url, shzeng_fetch_kind kind, shzeng_sink *sink);
    /* The load of the document and every blocking sub-resource finished: the "load" event is about to be dispatched
     * to the window (the host also gets it through event() when it listens for "load"). */
    void (*load_done)(void *ctx, shzeng_doc *doc);
    void (*title_changed)(void *ctx, shzeng_doc *doc);
    void (*status_text)(void *ctx, const WCHAR *text);            /* hover over a link, NULL to clear */
    /* A link or form was activated by the user: the host navigates (BeforeNavigate2, ...). target may be NULL. */
    HRESULT (*navigate)(void *ctx, shzeng_doc *doc, const WCHAR *url, const WCHAR *target, const void *post,
                        SIZE_T post_len, const WCHAR *headers);
    void (*context_menu)(void *ctx, shzeng_doc *doc, LONG screen_x, LONG screen_y, shzeng_node *node);
    void (*invalidate)(void *ctx, shzeng_doc *doc, const RECT *rect);   /* windowless views only (view_paint users) */
} shzeng_host;

typedef struct shzeng_vtbl {
    UINT api_version;                      /* SHZENG_API_VERSION */
    UINT caps;                             /* SHZENG_CAP_* */
    const WCHAR *name;                     /* e.g. L"ShizukuTrident Lite 1.0", L"WebKit 620.1" */
    const WCHAR *ua_token;                 /* engine token for navigator.userAgent, e.g. L"AppleWebKit/620.1" [required] */

    /* ---------------------------------------------------------------- memory */
    void    (*str_free)(WCHAR *str);                                                     /* [required] */

    /* ---------------------------------------------------------------- documents and loading */
    /* url: the document URL (base for relative references); mime: L"text/html" (default when NULL) or an XML type. */
    HRESULT (*doc_create)(const shzeng_host *host, void *ctx, const WCHAR *url, const WCHAR *mime,
                          shzeng_doc **doc);                                              /* [required] */
    void    (*doc_release)(shzeng_doc *doc);                                             /* [required] */
    HRESULT (*doc_set_url)(shzeng_doc *doc, const WCHAR *url);                           /* after redirects */
    /* Incremental parsing (network loads): charset from the channel or NULL (sniff: BOM, <meta charset>, UTF-8). */
    HRESULT (*parser_begin)(shzeng_doc *doc, const WCHAR *charset);                      /* [required] */
    HRESULT (*parser_feed)(shzeng_doc *doc, const void *bytes, SIZE_T len);              /* [required] */
    HRESULT (*parser_end)(shzeng_doc *doc);                                              /* [required] */
    /* Replace the whole document with already decoded markup (about:blank, IPersistStreamInit on a string). */
    HRESULT (*load_string)(shzeng_doc *doc, const WCHAR *html, SIZE_T len);              /* [required] */
    /* document.open/write/close: write inserts at the parser's insertion point (inside a running parser-inserted
     * script) or after document.open. */
    HRESULT (*doc_open)(shzeng_doc *doc);
    HRESULT (*doc_write)(shzeng_doc *doc, const WCHAR *text, BOOL newline);
    HRESULT (*doc_close)(shzeng_doc *doc);
    HRESULT (*doc_set_mode)(shzeng_doc *doc, shzeng_mode mode);                          /* [required] */
    HRESULT (*doc_get_ready_state)(shzeng_doc *doc, WCHAR **state);                     /* loading|interactive|complete */
    /* Parse a standalone document (DOMParser, createHTMLDocument). */
    HRESULT (*parse_document)(const WCHAR *src, const WCHAR *mime, shzeng_doc **doc);

    /* ---------------------------------------------------------------- tree */
    HRESULT (*doc_node)(shzeng_doc *doc, shzeng_node **node);          /* the Document node          [required] */
    HRESULT (*doc_element)(shzeng_doc *doc, shzeng_node **node);       /* documentElement            [required] */
    HRESULT (*doc_body)(shzeng_doc *doc, shzeng_node **node);          /* body or frameset           [required] */
    HRESULT (*doc_head)(shzeng_doc *doc, shzeng_node **node);
    HRESULT (*doc_doctype)(shzeng_doc *doc, shzeng_node **node, WCHAR **name, WCHAR **public_id, WCHAR **system_id);
    HRESULT (*node_doc)(shzeng_node *node, shzeng_doc **doc);          /* owner document, no reference [required] */
    void    (*node_addref)(shzeng_node *node);                                            /* [required] */
    void    (*node_release)(shzeng_node *node);                                           /* [required] */
    int     (*node_type)(shzeng_node *node);                                              /* [required] */
    HRESULT (*node_name)(shzeng_node *node, WCHAR **name);         /* nodeName: upper-case tag name for HTML */
    HRESULT (*node_value)(shzeng_node *node, WCHAR **value);       /* text/comment data, attribute value */
    HRESULT (*node_set_value)(shzeng_node *node, const WCHAR *value);
    HRESULT (*node_parent)(shzeng_node *node, shzeng_node **out);                         /* [required] */
    HRESULT (*node_first_child)(shzeng_node *node, shzeng_node **out);                    /* [required] */
    HRESULT (*node_last_child)(shzeng_node *node, shzeng_node **out);
    HRESULT (*node_next_sibling)(shzeng_node *node, shzeng_node **out);                   /* [required] */
    HRESULT (*node_prev_sibling)(shzeng_node *node, shzeng_node **out);
    HRESULT (*node_child_nodes)(shzeng_node *node, shzeng_list **list);                   /* live NodeList */
    HRESULT (*node_insert_before)(shzeng_node *parent, shzeng_node *child, shzeng_node *ref);  /* ref NULL = append */
    HRESULT (*node_remove_child)(shzeng_node *parent, shzeng_node *child);
    HRESULT (*node_replace_child)(shzeng_node *parent, shzeng_node *child, shzeng_node *old);
    HRESULT (*node_clone)(shzeng_node *node, BOOL deep, shzeng_node **out);
    BOOL    (*node_contains)(shzeng_node *node, shzeng_node *other);
    UINT    (*node_compare_position)(shzeng_node *node, shzeng_node *other);   /* DOM compareDocumentPosition bits */
    /* textContent (and innerText when inner_text is TRUE: rendered text, block boundaries as line breaks) */
    HRESULT (*node_text)(shzeng_node *node, BOOL inner_text, WCHAR **text);
    HRESULT (*node_set_text)(shzeng_node *node, const WCHAR *text);
    /* One host pointer per node (Wine's Get/SetMshtmlNode): the Trident wrapper of this node. Not reference counted. */
    void    (*node_set_host_data)(shzeng_node *node, void *data);                          /* [required] */
    void   *(*node_get_host_data)(shzeng_node *node);                                      /* [required] */

    HRESULT (*create_element)(shzeng_doc *doc, const WCHAR *ns, const WCHAR *tag, shzeng_node **out);  /* [required] */
    HRESULT (*create_text)(shzeng_doc *doc, const WCHAR *data, shzeng_node **out);                    /* [required] */
    HRESULT (*create_comment)(shzeng_doc *doc, const WCHAR *data, shzeng_node **out);
    HRESULT (*create_fragment)(shzeng_doc *doc, shzeng_node **out);
    /* Parse markup in the context of an element (innerHTML, insertAdjacentHTML, Range.createContextualFragment,
     * conditional comments): returns a DocumentFragment. */
    HRESULT (*parse_fragment)(shzeng_node *context, const WCHAR *html, shzeng_node **fragment);      /* [required] */
    /* Serialize: outer = the node itself (outerHTML), otherwise its children (innerHTML). */
    HRESULT (*serialize)(shzeng_node *node, BOOL outer, WCHAR **html);                               /* [required] */
    HRESULT (*text_split)(shzeng_node *text, UINT offset, shzeng_node **tail);

    /* ---------------------------------------------------------------- elements and attributes */
    HRESULT (*elem_tag)(shzeng_node *elem, WCHAR **local_name);     /* lower-case local name for HTML  [required] */
    HRESULT (*elem_namespace)(shzeng_node *elem, WCHAR **ns);
    HRESULT (*elem_get_attr)(shzeng_node *elem, const WCHAR *name, WCHAR **value);  /* S_FALSE: absent [required] */
    HRESULT (*elem_set_attr)(shzeng_node *elem, const WCHAR *name, const WCHAR *value);              /* [required] */
    HRESULT (*elem_remove_attr)(shzeng_node *elem, const WCHAR *name);                                /* [required] */
    UINT    (*elem_attr_count)(shzeng_node *elem);
    HRESULT (*elem_attr_at)(shzeng_node *elem, UINT index, WCHAR **name, WCHAR **value);
    HRESULT (*elem_attr_node)(shzeng_node *elem, const WCHAR *name, shzeng_node **attr);   /* Attr node or S_FALSE */
    HRESULT (*doc_get_element_by_id)(shzeng_doc *doc, const WCHAR *id, shzeng_node **out);            /* [required] */
    HRESULT (*get_elements_by)(shzeng_node *root, shzeng_by by, const WCHAR *ns, const WCHAR *value, shzeng_list **out);
    HRESULT (*doc_collection)(shzeng_doc *doc, shzeng_collection which, shzeng_list **out);
    HRESULT (*query_selector)(shzeng_node *root, const WCHAR *selector, BOOL all, shzeng_node **one, shzeng_list **list);
    HRESULT (*matches)(shzeng_node *elem, const WCHAR *selector, BOOL *result);
    UINT    (*list_length)(shzeng_list *list);
    HRESULT (*list_item)(shzeng_list *list, UINT index, shzeng_node **out);
    HRESULT (*list_named_item)(shzeng_list *list, const WCHAR *name, shzeng_node **out);
    void    (*list_release)(shzeng_list *list);

    /* form controls (value/checked/selectedIndex are state, not attributes) */
    HRESULT (*ctl_get_value)(shzeng_node *ctl, WCHAR **value);
    HRESULT (*ctl_set_value)(shzeng_node *ctl, const WCHAR *value);
    HRESULT (*ctl_get_checked)(shzeng_node *ctl, BOOL *checked);
    HRESULT (*ctl_set_checked)(shzeng_node *ctl, BOOL checked);
    HRESULT (*select_get_index)(shzeng_node *select, LONG *index);
    HRESULT (*select_set_index)(shzeng_node *select, LONG index);
    /* The submission a form would make (GetFormData): action URL resolved, body encoded per enctype. */
    HRESULT (*form_submission)(shzeng_node *form, shzeng_node *submitter, WCHAR **action, WCHAR **method,
                               WCHAR **content_type, BYTE **body, SIZE_T *body_len);
    HRESULT (*form_reset)(shzeng_node *form);
    void    (*bytes_free)(BYTE *bytes);
    /* images */
    HRESULT (*img_state)(shzeng_node *img, BOOL *complete, LONG *natural_width, LONG *natural_height);
    /* frames: the document inside an <iframe>/<frame>, S_FALSE when not loaded */
    HRESULT (*frame_doc)(shzeng_node *frame, shzeng_doc **doc);

    /* ---------------------------------------------------------------- style and geometry */
    HRESULT (*style_inline)(shzeng_node *elem, shzeng_style **style);
    HRESULT (*style_computed)(shzeng_node *elem, const WCHAR *pseudo, shzeng_style **style);  /* read-only */
    HRESULT (*style_get)(shzeng_style *style, const WCHAR *property, WCHAR **value);  /* CSS property name, "" if unset */
    HRESULT (*style_get_priority)(shzeng_style *style, const WCHAR *property, WCHAR **priority);
    HRESULT (*style_set)(shzeng_style *style, const WCHAR *property, const WCHAR *value, const WCHAR *priority);
    HRESULT (*style_remove)(shzeng_style *style, const WCHAR *property);
    HRESULT (*style_css_text)(shzeng_style *style, WCHAR **text);
    HRESULT (*style_set_css_text)(shzeng_style *style, const WCHAR *text);
    UINT    (*style_length)(shzeng_style *style);
    HRESULT (*style_item)(shzeng_style *style, UINT index, WCHAR **property);
    void    (*style_release)(shzeng_style *style);
    UINT    (*doc_sheet_count)(shzeng_doc *doc);
    HRESULT (*doc_sheet_at)(shzeng_doc *doc, UINT index, shzeng_sheet **sheet);
    UINT    (*sheet_rule_count)(shzeng_sheet *sheet);
    HRESULT (*sheet_rule_text)(shzeng_sheet *sheet, UINT index, WCHAR **text);
    HRESULT (*sheet_rule_style)(shzeng_sheet *sheet, UINT index, WCHAR **selector, shzeng_style **style);
    HRESULT (*sheet_insert_rule)(shzeng_sheet *sheet, const WCHAR *rule, UINT index);
    HRESULT (*sheet_delete_rule)(shzeng_sheet *sheet, UINT index);
    HRESULT (*sheet_href)(shzeng_sheet *sheet, WCHAR **href);
    void    (*sheet_release)(shzeng_sheet *sheet);
    HRESULT (*media_matches)(shzeng_doc *doc, const WCHAR *query, BOOL *result);
    /* Layout is brought up to date on demand by every geometry query. */
    HRESULT (*elem_box)(shzeng_node *elem, shzeng_box which, RECT *box);  /* left/top/right/bottom, CSS px */
    HRESULT (*elem_offset_parent)(shzeng_node *elem, shzeng_node **parent);
    UINT    (*elem_client_rects)(shzeng_node *elem, RECT *rects, UINT max);
    HRESULT (*elem_set_scroll)(shzeng_node *elem, LONG x, LONG y);
    HRESULT (*elem_scroll_into_view)(shzeng_node *elem, BOOL align_top);
    HRESULT (*hit_test)(shzeng_doc *doc, LONG x, LONG y, shzeng_node **node);   /* elementFromPoint, viewport coords */

    /* ---------------------------------------------------------------- events */
    /* target NULL = the document's window. The cookie is handed back in host->event. Listening for a type makes the
     * backend deliver trusted events of that type (input, load, readystate ...) to host->event. */
    HRESULT (*add_listener)(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL capture, void *cookie);
    HRESULT (*remove_listener)(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL capture, void *cookie);
    /* Dispatch a synthetic event through the DOM (capture/target/bubble). *default_prevented receives the outcome. */
    HRESULT (*dispatch_event)(shzeng_doc *doc, shzeng_node *target, const WCHAR *type, BOOL bubbles,
                              BOOL cancelable, BOOL *default_prevented);
    HRESULT (*event_type)(shzeng_event *event, WCHAR **type);                                        /* [required] */
    shzeng_event_kind (*event_kind)(shzeng_event *event);                                            /* [required] */
    HRESULT (*event_target)(shzeng_event *event, shzeng_node **target);      /* S_FALSE + NULL: the window */
    HRESULT (*event_flags)(shzeng_event *event, BOOL *bubbles, BOOL *cancelable, BOOL *trusted, UINT *phase,
                           ULONGLONG *time_stamp);
    HRESULT (*event_mouse)(shzeng_event *event, shzeng_mouse *mouse);        /* E_INVALIDARG when not a mouse event */
    HRESULT (*event_key)(shzeng_event *event, shzeng_key *key);
    HRESULT (*event_progress)(shzeng_event *event, ULONGLONG *loaded, ULONGLONG *total, BOOL *computable);
    HRESULT (*event_prevent_default)(shzeng_event *event);
    HRESULT (*event_stop)(shzeng_event *event, BOOL immediate);
    BOOL    (*event_default_prevented)(shzeng_event *event);
    void    (*event_addref)(shzeng_event *event);
    void    (*event_release)(shzeng_event *event);
    HRESULT (*elem_click)(shzeng_node *elem);     /* element.click(): synthetic click + activation behaviour */
    HRESULT (*elem_focus)(shzeng_node *elem);
    HRESULT (*elem_blur)(shzeng_node *elem);
    HRESULT (*doc_active_element)(shzeng_doc *doc, shzeng_node **elem);

    /* ---------------------------------------------------------------- script */
    /* Evaluate script in the document's global (only backends with SHZENG_CAP_SCRIPT; the minimal engine returns
     * E_NOTIMPL and the Trident layer runs scripts with an IActiveScript engine, Wine's jscript). lang: L"javascript".
     * result may be NULL; otherwise it receives the completion value (VT_EMPTY for undefined). */
    HRESULT (*script_eval)(shzeng_doc *doc, const WCHAR *lang, const WCHAR *code, const WCHAR *source_url,
                           UINT line, VARIANT *result);

    /* ---------------------------------------------------------------- views */
    /* Present the document in a new child window of parent covering rect (client coordinates of parent). The view
     * window paints, scrolls and turns input into DOM events itself. */
    HRESULT (*view_create)(shzeng_doc *doc, HWND parent, const RECT *rect, shzeng_view **view);      /* [required] */
    void    (*view_destroy)(shzeng_view *view);                                                       /* [required] */
    HWND    (*view_hwnd)(shzeng_view *view);                                                          /* [required] */
    HRESULT (*view_set_rect)(shzeng_view *view, const RECT *rect);                                    /* [required] */
    HRESULT (*view_show)(shzeng_view *view, BOOL show);
    HRESULT (*view_set_parent)(shzeng_view *view, HWND parent);
    HRESULT (*view_focus)(shzeng_view *view);
    HRESULT (*view_scroll)(shzeng_view *view, LONG x, LONG y, BOOL relative);
    HRESULT (*view_scroll_pos)(shzeng_view *view, LONG *x, LONG *y);
    HRESULT (*view_set_zoom)(shzeng_view *view, float zoom);
    /* Paint the document (viewport at scroll position x, y) into a caller-provided DC (IViewObject::Draw). */
    HRESULT (*view_paint)(shzeng_doc *doc, HDC dc, const RECT *dest, LONG scroll_x, LONG scroll_y);
    /* Snapshot: lay out at the given width and render into a new top-down 32-bpp DIB section (0x00RRGGBB);
     * height 0 = the document's full height. The caller deletes the bitmap. */
    HRESULT (*snapshot)(shzeng_doc *doc, LONG width, LONG height, HBITMAP *bitmap);                  /* [required] */
    /* Document size after layout (scrollWidth/Height of the viewport). */
    HRESULT (*doc_content_size)(shzeng_doc *doc, LONG *width, LONG *height);

    /* ---------------------------------------------------------------- ranges and selection (SHZENG_CAP_RANGES) */
    HRESULT (*range_create)(shzeng_doc *doc, shzeng_range **range);
    HRESULT (*range_set)(shzeng_range *range, BOOL end, shzeng_node *node, LONG offset);
    HRESULT (*range_get)(shzeng_range *range, BOOL end, shzeng_node **node, LONG *offset);
    HRESULT (*range_text)(shzeng_range *range, WCHAR **text);
    void    (*range_release)(shzeng_range *range);
    HRESULT (*sel_get)(shzeng_doc *doc, shzeng_range **range);        /* first selection range, S_FALSE if none */
    HRESULT (*sel_set)(shzeng_doc *doc, shzeng_range *range);         /* NULL clears */

    /* ---------------------------------------------------------------- editing (SHZENG_CAP_EDITING) */
    HRESULT (*doc_set_design_mode)(shzeng_doc *doc, BOOL on);
    HRESULT (*exec_command)(shzeng_doc *doc, const WCHAR *command, const WCHAR *value, BOOL *done);

    /* ---------------------------------------------------------------- printing (SHZENG_CAP_PRINT) */
    HRESULT (*paginate)(shzeng_doc *doc, LONG page_width, LONG page_height, UINT *pages);
    HRESULT (*print_page)(shzeng_doc *doc, UINT page, HDC dc, const RECT *dest);
} shzeng_vtbl;

typedef const shzeng_vtbl * (WINAPI *shzeng_get_interface_fn)(UINT api_version);
#define SHZENG_ENTRY_NAME "ShzEngineGetInterface"

/* Backend DLL names known to the selector (trident/xul/select.c) */
#define SHZENG_WEBKIT_DLL L"shzwebkit.dll"
#define SHZENG_LITE_DLL   L"shzlite.dll"

#ifdef __cplusplus
}
#endif

#endif /* SHIZUKU_TRIDENT_ENGINE_H */
