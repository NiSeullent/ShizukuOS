/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of libxslt (libxslt.dll over libxml2.dll): a stylesheet with a template, xsl:sort (numeric) and a
 * parameter; the serialized result is compared byte for byte. */
#include <string.h>
#include <libxml/parser.h>
#include <libxslt/transform.h>
#include <libxslt/xsltInternals.h>
#include <libxslt/xsltutils.h>
#include "deptest.h"

int main(void)
{
    static const char xml[] = "<list><i v=\"3\">c</i><i v=\"10\">j</i><i v=\"1\">a</i></list>";
    static const char xsl[] =
        "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\">"
        "<xsl:output method=\"text\"/><xsl:param name=\"sep\" select=\"'-'\"/>"
        "<xsl:template match=\"/list\"><xsl:for-each select=\"i\"><xsl:sort select=\"@v\" data-type=\"number\"/>"
        "<xsl:value-of select=\".\"/><xsl:if test=\"position()!=last()\"><xsl:value-of select=\"$sep\"/></xsl:if>"
        "</xsl:for-each></xsl:template></xsl:stylesheet>";
    xmlDocPtr sd = xmlReadMemory(xsl, (int)strlen(xsl), "t.xsl", NULL, 0);
    xsltStylesheetPtr ss = sd ? xsltParseStylesheetDoc(sd) : NULL;
    CHECK(ss != NULL);
    xmlDocPtr d = xmlReadMemory(xml, (int)strlen(xml), "t.xml", NULL, 0);
    const char *params[] = {"sep", "'+'", NULL};
    xmlDocPtr res = (ss && d) ? xsltApplyStylesheet(ss, d, params) : NULL;
    CHECK(res != NULL);
    xmlChar *out = NULL;
    int len = 0;
    if (res) xsltSaveResultToString(&out, &len, res, ss);
    printf("result \"%.*s\" (libxslt %s)\n", len, out ? (const char *)out : "", xsltEngineVersion);
    CHECK(out && len == 5 && !memcmp(out, "a+c+j", 5));
    xmlFree(out);
    xmlFreeDoc(res);
    xmlFreeDoc(d);
    xsltFreeStylesheet(ss);
    xsltCleanupGlobals();
    xmlCleanupParser();
    return DONE("t_dep_libxslt");
}
