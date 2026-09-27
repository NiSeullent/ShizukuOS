/* SPDX-License-Identifier: GPL-2.0-only
 * The four independent components must coexist in one adapter. */
#include "../../ntwrapper/include/ntwrapper.h"
#include "../../ntwin32/sync.h"
#include "../../ntwin32/resolve.h"
#include "../../ntwin32/initonce.h"
#include "../../ntwin32/unicode/utf.h"
#include "../../ntwddm/include/ntwddm.h"
#include "../../drivers/pcie/include/ntw_pcie.h"
int ntw_headers_coexist(void) { return NTW_OK + NTWG_OK + NTW_PCI_OK; }
