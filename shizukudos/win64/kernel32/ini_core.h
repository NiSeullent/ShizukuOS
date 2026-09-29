/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku INI core: the GetPrivateProfileString rules over the text of an initialization file (UTF-16). Pure functions, no
 * Windows types, so tests/host/ini_host_test.c runs the same code natively.
 *
 *   [section]            names and keys compare case-insensitively (ASCII); surrounding blanks are ignored; when a section
 *                        name repeats, only its first section is used
 *   key = value          the value loses leading/trailing blanks and one pair of matching surrounding quotes (' or ")
 *   ; comment            ignored, as are blank lines and lines outside any section
 *
 * ini_get_string(text, section, key, default, out, size) returns what GetPrivateProfileStringW returns:
 *   section == NULL: every section name, each NUL-terminated, the list ends with an extra NUL;
 *   key == NULL: every key name of the section, same format;
 *   otherwise the value, or `def` (NULL: "") without its trailing blanks when the key or section is missing.
 * A value that does not fit is truncated and size - 1 is returned; a list that does not fit ends with two NULs after its
 * truncated last name and size - 2 is returned. *found is set to 1 when the section (and key) exist.
 */
#ifndef SHZ_INI_CORE_H
#define SHZ_INI_CORE_H
#include <stdint.h>

typedef uint16_t ini_w;

unsigned ini_get_string(const ini_w *text, unsigned n, const ini_w *section, const ini_w *key, const ini_w *def, ini_w *out,
                        unsigned size, int *found);
#endif
