/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - images: decoders (PNG via src/vendor/lodepng, GIF first frame, BMP; JPEG and others report
 * SHZ_E_NOT_SUPPORTED) and the state of <img> / <input type=image> elements (fetch through fetch.h, load / error
 * events, natural size). Owner: L2 (image*.c). Declared by core.
 */
#ifndef SHZ_IMAGE_H
#define SHZ_IMAGE_H

#include "dom.h"

/* A decoded bitmap: top-down rows of width 32-bit pixels 0xAARRGGBB with PREMULTIPLIED alpha (what GdiAlphaBlend
 * wants; opaque images have A = 0xFF and the plain color). Reference counted; immutable once decoded. */
typedef struct shz_image {
    uint32_t refs;
    int32_t width, height;
    uint32_t *pixels;
    int has_alpha;                      /* some pixel has A != 0xFF */
} shz_image;

shz_res   shz_image_decode(const uint8_t *data, size_t len, shz_image **out);   /* sniffs the format */
void      shz_image_addref(shz_image *img);
void      shz_image_release(shz_image *img);

/* engine.h img_state: complete = no request pending (loaded, broken, or no src); natural size 0 when not decoded */
shz_res   shz_image_state(shz_node *elem, int *complete, int32_t *natural_width, int32_t *natural_height);
/* The decoded image of an element (no reference; valid until the element's src changes), or NULL. */
shz_image *shz_image_of(shz_node *elem);

#endif /* SHZ_IMAGE_H */
