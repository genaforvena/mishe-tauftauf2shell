/* Frontier harness for CVE-2026-122056 / GHSA-5h6x-q65w-wxvf.
 * Calls the verbatim upstream ds_sds_mangle_filepath() from pins/sds.c.{vuln,fixed}.
 * Vectors are XCCDF check-content-ref href values from the upstream advisory. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char* ds_sds_mangle_filepath(const char* filepath);

int main(int argc, char** argv)
{
    const char* vector = (argc > 1) ? argv[1] : "slashes";
    const char* input;
    if (strcmp(vector, "slashes") == 0)
        input = "////";                 /* advisory href=//// */
    else if (strcmp(vector, "empty") == 0)
        input = "";                     /* advisory href=file:// after 7-byte strip */
    else if (strcmp(vector, "safe") == 0)
        input = "a/b@c";                /* output 7 bytes + NUL fits 2*4 allocation */
    else
        return 2;

    char* out = ds_sds_mangle_filepath(input);
    printf("vector=%s in=[%s] out=[%s] outlen=%zu\n",
           vector, input, out ? out : "(null)", out ? strlen(out) : 0);
    free(out);
    return 0;
}
