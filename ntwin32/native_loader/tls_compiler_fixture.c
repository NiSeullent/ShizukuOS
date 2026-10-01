/* SPDX-License-Identifier: GPL-2.0-only
 * Compile with Clang's native Microsoft x86 ABI, never GNU emulated TLS.
 */
__declspec(thread) unsigned ntw_tls_compiler_word=0x1234abcd;
unsigned ntw_tls_compiler_read(void){return ntw_tls_compiler_word;}
void ntw_tls_compiler_write(unsigned value){ntw_tls_compiler_word=value;}
