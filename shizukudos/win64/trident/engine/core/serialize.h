/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - markup serialization (core): the HTML fragment serialization algorithm (WHATWG HTML
 * 13.3 "Serializing HTML fragments") for HTML documents, and a plain XML serialization for XML documents.
 *
 * HTML: element names are the qualified names (lower-case for HTML elements), attribute values are double-quoted with
 * & NBSP " < > escaped (the 2025 specification change also escapes < and > in attributes), text is escaped
 * (& NBSP < >) except inside style, script, xmp, iframe, noembed, noframes,
 * plaintext and noscript, void elements have no end tag, comments are <!--data-->, doctypes <!DOCTYPE name>,
 * processing instructions <?target data>. The removed "extra newline after <pre>/<textarea>/<listing>" rule is not
 * applied (current specification).
 */
#ifndef SHZ_SERIALIZE_H
#define SHZ_SERIALIZE_H

#include "dom.h"

/* outer: the node itself (outerHTML), else its children (innerHTML). Allocated; NULL on OOM. */
shz_char *shz_serialize(shz_node *node, int outer);

#endif /* SHZ_SERIALIZE_H */
