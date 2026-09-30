/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - document lifecycle glue: readyState, DOMContentLoaded, load, and repaint requests.
 * Owner: L2 (loader.c). Declared by core; called by the parser (core), fetch.c (core) and layout (L1).
 *
 * Sequence for a load (HTML "the end", simplified):
 *   shz_load_parser_started   readyState = "loading" (readystatechange)
 *   ... parsing, run_script callbacks, sub-resource fetches ...
 *   shz_load_parser_finished  readyState = "interactive" (readystatechange), hooks->parse_done, DOMContentLoaded;
 *                             then, when doc->fetch_pending == 0 (now or later in shz_load_check_complete):
 *                             readyState = "complete" (readystatechange), hooks->load_done, window "load".
 */
#ifndef SHZ_LOADER_H
#define SHZ_LOADER_H

#include "dom.h"

void      shz_load_parser_started(shz_doc *doc);
void      shz_load_parser_finished(shz_doc *doc);
void      shz_load_check_complete(shz_doc *doc);      /* doc->fetch_pending dropped to 0 */
/* Something visible changed (L1 after relayout / restyle, L2 after caret or focus changes): repaint the views
 * showing doc (InvalidateRect) or tell a windowless host (hooks->invalidate). rect: document space, NULL = all. */
void      shz_doc_invalidate(shz_doc *doc, const shz_irect *rect);

#endif /* SHZ_LOADER_H */
