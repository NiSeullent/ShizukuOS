/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - form controls: state (value, checkedness, selectedness, dirty flags, caret/selection),
 * editing, form submission and reset. Owner: L2 (forms*.c). Declared by core.
 *
 * State lives in shz_element.ctl (struct shz_ctl, private to L2), created lazily; the default value / checkedness /
 * selectedness come from the attributes (value, checked, selected) until the control is dirty, as HTML specifies.
 */
#ifndef SHZ_FORMS_H
#define SHZ_FORMS_H

#include "dom.h"

/* control kinds (rendering and behaviour) */
enum {
    SHZ_CTL_NONE = 0, SHZ_CTL_TEXT, SHZ_CTL_PASSWORD, SHZ_CTL_CHECKBOX, SHZ_CTL_RADIO, SHZ_CTL_BUTTON,
    SHZ_CTL_SUBMIT, SHZ_CTL_RESET, SHZ_CTL_IMAGE, SHZ_CTL_FILE, SHZ_CTL_HIDDEN, SHZ_CTL_SELECT, SHZ_CTL_LISTBOX,
    SHZ_CTL_TEXTAREA
};

/* ---- engine.h entries */
shz_res   shz_forms_get_value(shz_node *ctl, shz_char **value);         /* input/textarea/select/option/button */
shz_res   shz_forms_set_value(shz_node *ctl, const shz_char *value);
shz_res   shz_forms_get_checked(shz_node *ctl, int *checked);
shz_res   shz_forms_set_checked(shz_node *ctl, int checked);             /* radio: unchecks the group */
shz_res   shz_forms_select_get_index(shz_node *select, long *index);    /* -1 = none */
shz_res   shz_forms_select_set_index(shz_node *select, long index);

typedef struct shz_form_submission {
    shz_char *action;                   /* resolved; for GET the query is already appended ("action?a=1&b=2") */
    shz_char *method;                   /* "GET" or "POST" */
    shz_char *content_type;             /* POST: "application/x-www-form-urlencoded" or
                                           "multipart/form-data; boundary=..."; NULL for GET */
    uint8_t *body;                      /* POST body (shz_alloc), NULL for GET */
    size_t body_len;
} shz_form_submission;
/* The submission form would make with submitter (may be NULL). Fields are shz_alloc'ed; the glue hands them to the
 * engine.h caller (str_free / bytes_free). */
shz_res   shz_forms_submission(shz_node *form, shz_node *submitter, shz_form_submission *out);
shz_res   shz_forms_reset(shz_node *form);

/* ---- for selectors and rendering */
int       shz_forms_is_checked(shz_node *elem);   /* :checked: checkbox/radio checkedness, option selectedness */
int       shz_forms_ctl_kind(shz_node *elem);     /* SHZ_CTL_* (SHZ_CTL_NONE for non-controls) */

typedef struct shz_ctl_render {
    int kind;                           /* SHZ_CTL_* */
    shz_char *text;                     /* what the control shows (value, masked value, label, selected option); owned */
    int checked, disabled, focused, pressed;
    uint32_t caret;                     /* caret offset into text when focused */
    uint32_t sel_start, sel_end;
    int size, rows, cols;               /* size= / rows= / cols= attributes (defaults applied: 20, 2, 20) */
} shz_ctl_render;
shz_res   shz_forms_render_info(shz_node *ctl, shz_ctl_render *out);
void      shz_forms_render_info_free(shz_ctl_render *info);

/* ---- editing (the view, L2) */
/* Insert text at the caret of a focused text control / delete (backwards < 0, forwards > 0); fires "input". */
shz_res   shz_forms_edit_insert(shz_node *ctl, const shz_char *text, size_t n);
shz_res   shz_forms_edit_delete(shz_node *ctl, int direction);
shz_res   shz_forms_set_caret(shz_node *ctl, uint32_t offset);

#endif /* SHZ_FORMS_H */
