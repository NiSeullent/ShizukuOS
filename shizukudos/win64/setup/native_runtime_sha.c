/* SPDX-License-Identifier: GPL-2.0-only
 * The reviewed accounts SHA-256 core is now compiled exactly once inside
 * native_install.c (with the SZOU leaf modules), so every existing link set that
 * names both TUs keeps a single definition. This TU stays for build receipts. */
typedef int shz_native_runtime_sha_in_native_install;
