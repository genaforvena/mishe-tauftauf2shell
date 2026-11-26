/* Verbatim-consuming harness for inih CVE-2025-71450 (GHSA-gh7m-xpp3-w3vq).
 * Compiled against the pinned r62 (vulnerable) and r63 (fixed) ini.c sources.
 * No synthetic reimplementation of the parser: ini_parse_file() is the
 * shipped library entry point. Input is a local file only. */
#include <stdio.h>
#include "ini.h"

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    (void)user;
    (void)section;
    (void)name;
    (void)value;
    return 1;
}

int main(int argc, char** argv)
{
    FILE* f;
    int rc;
    if (argc != 2) {
        fprintf(stderr, "usage: %s FILE.ini\n", argv[0]);
        return 2;
    }
    f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 3;
    }
    rc = ini_parse_file(f, handler, NULL);
    fclose(f);
    printf("rc=%d\n", rc);
    return 0;
}
