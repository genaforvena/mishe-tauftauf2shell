/* Frontier harness for CVE-2026-40489: calls the pinned editorconfig-core-c
 * ec_glob() and the real editorconfig_parse() caller. No network I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <editorconfig/editorconfig.h>
#include <editorconfig/editorconfig_handle.h>
#include "ec_glob.h"

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s direct <pattern-length> [byte] | file <path>\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "direct")) {
        size_t n = strtoul(argv[2], NULL, 10);
        unsigned char byte = (argc > 3) ? (unsigned char)argv[3][0] : 'A';
        char *pattern = (char *)malloc(n + 1);
        int rc;
        if (!pattern) return 3;
        memset(pattern, byte, n);
        pattern[n] = '\0';
        rc = ec_glob(pattern, "x");
        printf("DIRECT n=%zu byte=%02x rc=%d\n", n, byte, rc);
        free(pattern);
        return 0;
    }
    if (!strcmp(argv[1], "file")) {
        editorconfig_handle h = editorconfig_handle_init();
        int rc;
        if (!h) return 3;
        rc = editorconfig_parse(argv[2], h);
        printf("FILE rc=%d errfile=%s\n", rc,
               editorconfig_handle_get_err_file(h) ? editorconfig_handle_get_err_file(h) : "(none)");
        editorconfig_handle_destroy(h);
        return 0;
    }
    return 2;
}
