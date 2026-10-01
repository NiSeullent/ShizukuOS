/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libxml2 (libxml2.dll): parse a namespaced document with an entity, XPath, serialize, and reject a
 * malformed document with a line number. */
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include "deptest.h"

static int errors, last_line;
static void on_error(void *ctx, const xmlError *e) { (void)ctx; ++errors; last_line = e->line; }

int main(void)
{
    static const char doc_text[] =
        "<?xml version=\"1.0\"?>\n<!DOCTYPE r [<!ENTITY who \"Shizuku\">]>\n"
        "<r xmlns:s=\"urn:shz\"><s:item n=\"1\">a &amp; &who;</s:item><s:item n=\"2\">b</s:item><other/></r>";
    xmlInitParser();
    xmlDocPtr doc = xmlReadMemory(doc_text, (int)strlen(doc_text), "t.xml", NULL, XML_PARSE_NOENT);
    CHECK(doc != NULL);
    xmlXPathContextPtr xp = xmlXPathNewContext(doc);
    xmlXPathRegisterNs(xp, BAD_CAST "s", BAD_CAST "urn:shz");
    xmlXPathObjectPtr r = xmlXPathEvalExpression(BAD_CAST "//s:item[@n='1']", xp);
    CHECK(r && r->nodesetval && r->nodesetval->nodeNr == 1);
    xmlChar *text = r && r->nodesetval->nodeNr ? xmlNodeGetContent(r->nodesetval->nodeTab[0]) : NULL;
    CHECK(text && !strcmp((const char *)text, "a & Shizuku"));
    xmlFree(text);
    xmlXPathFreeObject(r);
    r = xmlXPathEvalExpression(BAD_CAST "count(//s:item) + sum(//s:item/@n)", xp);
    CHECK(r && r->type == XPATH_NUMBER && r->floatval == 5.0);
    xmlXPathFreeObject(r);
    xmlXPathFreeContext(xp);
    xmlChar *out = NULL;
    int len = 0;
    xmlDocDumpMemory(doc, &out, &len);
    CHECK(out && strstr((const char *)out, "<other/>") != NULL);
    xmlFree(out);
    xmlFreeDoc(doc);
    xmlSetStructuredErrorFunc(NULL, on_error);
    doc = xmlReadMemory("<a>\n<b>\n</a>", 12, "bad.xml", NULL, 0);
    printf("malformed: doc=%p errors=%d line=%d, libxml2 %s\n", (void *)doc, errors, last_line, xmlParserVersion);
    CHECK(doc == NULL && errors > 0 && last_line == 3);
    xmlCleanupParser();
    return DONE("t_dep_libxml2");
}
