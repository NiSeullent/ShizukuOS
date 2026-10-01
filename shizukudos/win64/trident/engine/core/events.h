/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - DOM events: listener registration, event objects, dispatch (capture / target / bubble),
 * trusted events, activation behaviour, focus. Owner: L2 (events*.c). Declared by core.
 *
 * Listeners (engine.h add_listener) live in node->listeners (struct shz_listener, private to L2) and, for the window
 * (target NULL), in doc->events. A listener is (type, capture, cookie); the event reaches the host through
 * hooks->event(ctx, current_target, event, cookie), which returns SHZ_FALSE to request preventDefault.
 * Dispatch path: target and its ancestors up to the Document node, then the window (current_target NULL).
 *
 * Default actions (L2): click on <a href> -> hooks->navigate (unless prevented), status_text on link hover, submit /
 * reset buttons -> form submission / reset, checkbox / radio toggling, focus changes on mousedown, typing into text
 * controls (input events), Enter in a text input -> implicit submission.
 */
#ifndef SHZ_EVENTS_H
#define SHZ_EVENTS_H

#include "dom.h"

/* engine.h shzeng_event_kind values */
enum { SHZ_EVENT_GENERIC = 0, SHZ_EVENT_UI, SHZ_EVENT_KEYBOARD, SHZ_EVENT_MOUSE, SHZ_EVENT_FOCUS, SHZ_EVENT_PROGRESS,
       SHZ_EVENT_CUSTOM, SHZ_EVENT_MESSAGE };
/* eventPhase */
enum { SHZ_PHASE_NONE = 0, SHZ_PHASE_CAPTURING = 1, SHZ_PHASE_AT_TARGET = 2, SHZ_PHASE_BUBBLING = 3 };

typedef struct shz_mouse_data {
    int32_t client_x, client_y, screen_x, screen_y, page_x, page_y, offset_x, offset_y;
    uint16_t button;                    /* 0 left, 1 middle, 2 right */
    uint16_t buttons;
    uint8_t ctrl, shift, alt, meta;
    shz_node *related;                  /* relatedTarget (reference held by the event) */
    int32_t detail;                     /* click count */
    int32_t wheel_delta;                /* mousewheel: WHEEL_DELTA units */
} shz_mouse_data;

typedef struct shz_key_data {
    uint32_t key_code;                  /* virtual-key code */
    uint32_t char_code;                 /* keypress character */
    shz_char key[32];                   /* KeyboardEvent.key */
    uint32_t location;
    uint8_t repeat, ctrl, shift, alt, meta;
} shz_key_data;

struct shzeng_event {
    uint32_t refs;
    shz_char *type;                     /* "click", ... */
    int kind;                           /* SHZ_EVENT_* */
    shz_doc *doc;                       /* kept alive by the target reference or by doc->node (see events.c) */
    shz_node *target;                   /* reference held; NULL = the window */
    shz_node *current;                  /* current target during dispatch (no reference); NULL = window */
    uint8_t bubbles, cancelable, trusted, phase;
    uint8_t stop, stop_immediate, default_prevented, dispatching;
    uint64_t time_stamp;                /* ms (shz_platform_time_ms) */
    shz_mouse_data mouse;               /* SHZ_EVENT_MOUSE */
    shz_key_data key;                   /* SHZ_EVENT_KEYBOARD */
    uint64_t loaded, total;             /* SHZ_EVENT_PROGRESS */
    uint8_t computable;
};

/* ---- engine.h entries */
shz_res   shz_events_add_listener(shz_doc *doc, shz_node *target, const shz_char *type, int capture, void *cookie);
shz_res   shz_events_remove_listener(shz_doc *doc, shz_node *target, const shz_char *type, int capture, void *cookie);
/* Synthetic (untrusted) Event dispatch; *prevented receives defaultPrevented. */
shz_res   shz_events_dispatch_synthetic(shz_doc *doc, shz_node *target, const shz_char *type, int bubbles,
                                        int cancelable, int *prevented);
void      shz_event_addref(shz_event *ev);
void      shz_event_release(shz_event *ev);
shz_res   shz_events_click(shz_node *elem);                    /* element.click(): synthetic click + activation */
shz_res   shz_events_focus(shz_node *elem);
shz_res   shz_events_blur(shz_node *elem);
shz_res   shz_events_active_element(shz_doc *doc, shz_node **out);    /* no reference; body when nothing focused */

/* ---- for the other modules */
/* New event (refs = 1): type is ASCII, target may be NULL (window). */
shz_event *shz_event_new(shz_doc *doc, const char *type, int kind, shz_node *target, int bubbles, int cancelable,
                         int trusted);
/* Dispatch ev (capture/target/bubble, then default actions for trusted events); *prevented optional. */
shz_res   shz_events_dispatch(shz_event *ev, int *prevented);
/* Fire a trusted simple event ("load", "error", "scroll", "readystatechange", "DOMContentLoaded", ...). */
void      shz_events_fire(shz_doc *doc, shz_node *target, const char *type, int bubbles, int cancelable);
/* Does anything listen for type on the window or any node of doc? (skip building events nobody wants) */
int       shz_events_has_listener(shz_doc *doc, const char *type);

/* observe.h: void shz_interact_dom_changed(const shz_chg_info *info); implemented by L2 in events.c; it fans out to
 * forms, images and the loader and keeps doc->focus / hover / active valid. */

#endif /* SHZ_EVENTS_H */
