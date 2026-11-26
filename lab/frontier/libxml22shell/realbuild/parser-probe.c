/*
 * Parser-side bound check for CVE-2026-86138 (W237).
 * Feeds element names just above XML_MAX_NAME_LENGTH (50000) and, with
 * XML_PARSE_HUGE, above XML_MAX_TEXT_LENGTH (10000000). Neither can reach
 * the ~2^32-byte length needed to wrap xmlDictAddQString's 32-bit sum.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libxml/parser.h>

static void test(size_t n, int huge) {
    size_t cap = n + 64;
    char *buf = malloc(cap);
    const xmlError *err;
    xmlDoc *doc;
    if (buf == NULL) return;
    memcpy(buf, "<a", 2);
    memset(buf + 2, 'a', n);
    memcpy(buf + 2 + n, ">x</a>", 6);
    doc = xmlReadMemory(buf, (int)(n + 8), "probe.xml", NULL,
                        huge ? XML_PARSE_HUGE : 0);
    err = xmlGetLastError();
    printf("PARSER_PROBE NAME_LEN=%zu HUGE=%d DOC=%s ERRCODE=%d MSG=%s\n",
           n, huge, doc == NULL ? "NULL" : "parsed",
           err == NULL ? 0 : err->code,
           (err == NULL || err->message == NULL) ? "(none)" : err->message);
    if (doc != NULL) xmlFreeDoc(doc);
    free(buf);
}

int main(void) {
    xmlInitParser();
    test(50001, 0);
    test(10000001, 1);
    xmlCleanupParser();
    return 0;
}
