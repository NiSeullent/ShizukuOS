/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - known HTML element and attribute names.
 *
 * Elements in the HTML namespace carry the SHZ_TAG_* id of their local name (SHZ_TAG_UNKNOWN for other names), so the
 * parser, style and layout code compare integers. Elements in other namespaces have SHZ_TAG_UNKNOWN, except the roots
 * <svg> (SHZ_NS_SVG) and <math> (SHZ_NS_MATHML) which keep SHZ_TAG_SVG / SHZ_TAG_MATH: test the namespace as well
 * when that matters. Attributes with a known name carry a SHZ_ATTR_* id (0 otherwise).
 *
 * The lists are sorted by name (binary search); tests/t_names.c checks the order.
 */
#ifndef SHZ_NAMES_H
#define SHZ_NAMES_H

#include "base.h"

/* per-tag flags (meaningful for HTML-namespace elements only) */
#define SHZ_TF_VOID        0x0001   /* void element: no end tag, never has children when parsed, serialized without one */
#define SHZ_TF_SPECIAL     0x0002   /* HTML parser "special" category */
#define SHZ_TF_FORMATTING  0x0004   /* HTML parser formatting element (active formatting list) */
#define SHZ_TF_RAWTEXT     0x0008   /* text children are serialized without escaping (style, script, xmp, ...) */
#define SHZ_TF_BLOCK       0x0010   /* the UA style sheet makes it a block-level box (block, list-item, table parts) */
#define SHZ_TF_HEADING     0x0020   /* h1..h6 */
#define SHZ_TF_FORM_ASSOC  0x0040   /* form-associated element with a form owner (button, fieldset, input, ...) */
#define SHZ_TF_HIDDEN      0x0080   /* display: none in the UA style sheet (head, script, style, title, meta, ...) */

/* X(ENUM, "name", flags) */
#define SHZ_TAG_LIST(X) \
    X(A, "a", SHZ_TF_FORMATTING) \
    X(ABBR, "abbr", 0) \
    X(ACRONYM, "acronym", 0) \
    X(ADDRESS, "address", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(APPLET, "applet", SHZ_TF_SPECIAL) \
    X(AREA, "area", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(ARTICLE, "article", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(ASIDE, "aside", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(AUDIO, "audio", 0) \
    X(B, "b", SHZ_TF_FORMATTING) \
    X(BASE, "base", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(BASEFONT, "basefont", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(BDI, "bdi", 0) \
    X(BDO, "bdo", 0) \
    X(BGSOUND, "bgsound", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(BIG, "big", SHZ_TF_FORMATTING) \
    X(BLINK, "blink", 0) \
    X(BLOCKQUOTE, "blockquote", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(BODY, "body", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(BR, "br", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(BUTTON, "button", SHZ_TF_SPECIAL|SHZ_TF_FORM_ASSOC) \
    X(CANVAS, "canvas", 0) \
    X(CAPTION, "caption", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(CENTER, "center", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(CITE, "cite", 0) \
    X(CODE, "code", SHZ_TF_FORMATTING) \
    X(COL, "col", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(COLGROUP, "colgroup", SHZ_TF_SPECIAL) \
    X(DATA, "data", 0) \
    X(DATALIST, "datalist", SHZ_TF_HIDDEN) \
    X(DD, "dd", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(DEL, "del", 0) \
    X(DETAILS, "details", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(DFN, "dfn", 0) \
    X(DIALOG, "dialog", SHZ_TF_BLOCK) \
    X(DIR, "dir", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(DIV, "div", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(DL, "dl", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(DT, "dt", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(EM, "em", SHZ_TF_FORMATTING) \
    X(EMBED, "embed", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(FIELDSET, "fieldset", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_FORM_ASSOC) \
    X(FIGCAPTION, "figcaption", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(FIGURE, "figure", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(FONT, "font", SHZ_TF_FORMATTING) \
    X(FOOTER, "footer", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(FORM, "form", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(FRAME, "frame", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(FRAMESET, "frameset", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(H1, "h1", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(H2, "h2", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(H3, "h3", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(H4, "h4", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(H5, "h5", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(H6, "h6", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_HEADING) \
    X(HEAD, "head", SHZ_TF_SPECIAL|SHZ_TF_HIDDEN) \
    X(HEADER, "header", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(HGROUP, "hgroup", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(HR, "hr", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_BLOCK) \
    X(HTML, "html", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(I, "i", SHZ_TF_FORMATTING) \
    X(IFRAME, "iframe", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT) \
    X(IMAGE, "image", 0) \
    X(IMG, "img", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(INPUT, "input", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_FORM_ASSOC) \
    X(INS, "ins", 0) \
    X(ISINDEX, "isindex", SHZ_TF_SPECIAL) \
    X(KBD, "kbd", 0) \
    X(KEYGEN, "keygen", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_FORM_ASSOC) \
    X(LABEL, "label", SHZ_TF_FORM_ASSOC) \
    X(LEGEND, "legend", SHZ_TF_BLOCK) \
    X(LI, "li", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(LINK, "link", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(LISTING, "listing", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(MAIN, "main", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(MAP, "map", 0) \
    X(MARK, "mark", 0) \
    X(MARQUEE, "marquee", SHZ_TF_SPECIAL) \
    X(MATH, "math", 0) \
    X(MENU, "menu", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(MENUITEM, "menuitem", 0) \
    X(META, "meta", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(METER, "meter", 0) \
    X(NAV, "nav", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(NOBR, "nobr", SHZ_TF_FORMATTING) \
    X(NOEMBED, "noembed", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT|SHZ_TF_HIDDEN) \
    X(NOFRAMES, "noframes", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT|SHZ_TF_HIDDEN) \
    X(NOSCRIPT, "noscript", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT|SHZ_TF_HIDDEN) \
    X(OBJECT, "object", SHZ_TF_SPECIAL|SHZ_TF_FORM_ASSOC) \
    X(OL, "ol", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(OPTGROUP, "optgroup", SHZ_TF_BLOCK) \
    X(OPTION, "option", SHZ_TF_BLOCK) \
    X(OUTPUT, "output", SHZ_TF_FORM_ASSOC) \
    X(P, "p", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(PARAM, "param", SHZ_TF_SPECIAL|SHZ_TF_VOID|SHZ_TF_HIDDEN) \
    X(PICTURE, "picture", 0) \
    X(PLAINTEXT, "plaintext", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_RAWTEXT) \
    X(PRE, "pre", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(PROGRESS, "progress", 0) \
    X(Q, "q", 0) \
    X(RB, "rb", 0) \
    X(RP, "rp", 0) \
    X(RT, "rt", 0) \
    X(RTC, "rtc", 0) \
    X(RUBY, "ruby", 0) \
    X(S, "s", SHZ_TF_FORMATTING) \
    X(SAMP, "samp", 0) \
    X(SCRIPT, "script", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT|SHZ_TF_HIDDEN) \
    X(SEARCH, "search", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(SECTION, "section", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(SELECT, "select", SHZ_TF_SPECIAL|SHZ_TF_FORM_ASSOC) \
    X(SLOT, "slot", 0) \
    X(SMALL, "small", SHZ_TF_FORMATTING) \
    X(SOURCE, "source", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(SPAN, "span", 0) \
    X(STRIKE, "strike", SHZ_TF_FORMATTING) \
    X(STRONG, "strong", SHZ_TF_FORMATTING) \
    X(STYLE, "style", SHZ_TF_SPECIAL|SHZ_TF_RAWTEXT|SHZ_TF_HIDDEN) \
    X(SUB, "sub", 0) \
    X(SUMMARY, "summary", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(SUP, "sup", 0) \
    X(SVG, "svg", 0) \
    X(TABLE, "table", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TBODY, "tbody", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TD, "td", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TEMPLATE, "template", SHZ_TF_SPECIAL|SHZ_TF_HIDDEN) \
    X(TEXTAREA, "textarea", SHZ_TF_SPECIAL|SHZ_TF_FORM_ASSOC) \
    X(TFOOT, "tfoot", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TH, "th", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(THEAD, "thead", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TIME, "time", 0) \
    X(TITLE, "title", SHZ_TF_SPECIAL|SHZ_TF_HIDDEN) \
    X(TR, "tr", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(TRACK, "track", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(TT, "tt", SHZ_TF_FORMATTING) \
    X(U, "u", SHZ_TF_FORMATTING) \
    X(UL, "ul", SHZ_TF_SPECIAL|SHZ_TF_BLOCK) \
    X(VAR, "var", 0) \
    X(VIDEO, "video", 0) \
    X(WBR, "wbr", SHZ_TF_SPECIAL|SHZ_TF_VOID) \
    X(XMP, "xmp", SHZ_TF_SPECIAL|SHZ_TF_BLOCK|SHZ_TF_RAWTEXT)

enum shz_tag_id {
    SHZ_TAG_UNKNOWN = 0,
#define SHZ_X_(e, s, f) SHZ_TAG_##e,
    SHZ_TAG_LIST(SHZ_X_)
#undef SHZ_X_
    SHZ_TAG__COUNT
};

/* X(ENUM, "name") */
#define SHZ_ATTR_LIST(X) \
    X(ACCEPT, "accept") \
    X(ACCEPT_CHARSET, "accept-charset") \
    X(ACCESSKEY, "accesskey") \
    X(ACTION, "action") \
    X(ALIGN, "align") \
    X(ALINK, "alink") \
    X(ALT, "alt") \
    X(ARCHIVE, "archive") \
    X(AUTOCOMPLETE, "autocomplete") \
    X(AUTOFOCUS, "autofocus") \
    X(AXIS, "axis") \
    X(BACKGROUND, "background") \
    X(BGCOLOR, "bgcolor") \
    X(BORDER, "border") \
    X(CELLPADDING, "cellpadding") \
    X(CELLSPACING, "cellspacing") \
    X(CHAR, "char") \
    X(CHAROFF, "charoff") \
    X(CHARSET, "charset") \
    X(CHECKED, "checked") \
    X(CITE, "cite") \
    X(CLASS, "class") \
    X(CLASSID, "classid") \
    X(CLEAR, "clear") \
    X(CODE, "code") \
    X(CODEBASE, "codebase") \
    X(COLOR, "color") \
    X(COLS, "cols") \
    X(COLSPAN, "colspan") \
    X(COMPACT, "compact") \
    X(CONTENT, "content") \
    X(CONTENTEDITABLE, "contenteditable") \
    X(COORDS, "coords") \
    X(DATA, "data") \
    X(DATETIME, "datetime") \
    X(DECLARE, "declare") \
    X(DEFER, "defer") \
    X(DIR, "dir") \
    X(DISABLED, "disabled") \
    X(ENCTYPE, "enctype") \
    X(FACE, "face") \
    X(FOR, "for") \
    X(FORM, "form") \
    X(FRAME, "frame") \
    X(FRAMEBORDER, "frameborder") \
    X(HEADERS, "headers") \
    X(HEIGHT, "height") \
    X(HIDDEN, "hidden") \
    X(HREF, "href") \
    X(HREFLANG, "hreflang") \
    X(HSPACE, "hspace") \
    X(HTTP_EQUIV, "http-equiv") \
    X(ID, "id") \
    X(ISMAP, "ismap") \
    X(LABEL, "label") \
    X(LANG, "lang") \
    X(LANGUAGE, "language") \
    X(LINK, "link") \
    X(LONGDESC, "longdesc") \
    X(MARGINHEIGHT, "marginheight") \
    X(MARGINWIDTH, "marginwidth") \
    X(MAX, "max") \
    X(MAXLENGTH, "maxlength") \
    X(MEDIA, "media") \
    X(METHOD, "method") \
    X(MIN, "min") \
    X(MULTIPLE, "multiple") \
    X(NAME, "name") \
    X(NOHREF, "nohref") \
    X(NORESIZE, "noresize") \
    X(NOSHADE, "noshade") \
    X(NOWRAP, "nowrap") \
    X(PLACEHOLDER, "placeholder") \
    X(PROFILE, "profile") \
    X(READONLY, "readonly") \
    X(REL, "rel") \
    X(REV, "rev") \
    X(ROWS, "rows") \
    X(ROWSPAN, "rowspan") \
    X(RULES, "rules") \
    X(SCHEME, "scheme") \
    X(SCOPE, "scope") \
    X(SCROLLING, "scrolling") \
    X(SELECTED, "selected") \
    X(SHAPE, "shape") \
    X(SIZE, "size") \
    X(SPAN, "span") \
    X(SRC, "src") \
    X(STANDBY, "standby") \
    X(START, "start") \
    X(STEP, "step") \
    X(STYLE, "style") \
    X(SUMMARY, "summary") \
    X(TABINDEX, "tabindex") \
    X(TARGET, "target") \
    X(TEXT, "text") \
    X(TITLE, "title") \
    X(TYPE, "type") \
    X(USEMAP, "usemap") \
    X(VALIGN, "valign") \
    X(VALUE, "value") \
    X(VALUETYPE, "valuetype") \
    X(VERSION, "version") \
    X(VLINK, "vlink") \
    X(VSPACE, "vspace") \
    X(WIDTH, "width") \
    X(WRAP, "wrap")

enum shz_attr_id {
    SHZ_ATTR_UNKNOWN = 0,
#define SHZ_X_(e, s) SHZ_ATTR_##e,
    SHZ_ATTR_LIST(SHZ_X_)
#undef SHZ_X_
    SHZ_ATTR__COUNT
};

/* Lookups take the exact (already lower-cased) name; the _ci variants fold ASCII case. 0 = unknown. */
int         shz_tag_lookup(const shz_char *name, size_t n);
int         shz_tag_lookup_ci(const shz_char *name, size_t n);
const char *shz_tag_name(int tag);                 /* lower-case name, "" for SHZ_TAG_UNKNOWN */
unsigned    shz_tag_flags(int tag);                /* SHZ_TF_* */
int         shz_attr_lookup(const shz_char *name, size_t n);
int         shz_attr_lookup_ci(const shz_char *name, size_t n);
const char *shz_attr_name(int attr);               /* lower-case name, "" for SHZ_ATTR_UNKNOWN */

/* self-check of the tables (host tests): returns 1 when both lists are strictly sorted */
int         shz_names_sorted(void);

#endif /* SHZ_NAMES_H */
