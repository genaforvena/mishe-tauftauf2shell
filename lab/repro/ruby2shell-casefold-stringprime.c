/* Analysis-only probe for the case-fold one-byte-exact OOB read.
 *
 * Make `count` NON-EMBEDDED Ruby Strings (rb_str_buf_new), fill each with
 * `byte`, and hand them back to Ruby. Ruby drops the Array and runs GC, so
 * their malloc buffers enter glibc before Regexp compilation. Unlike a bare
 * malloc()/free() prime this exercises a real Ruby object's buffer; unlike a
 * Ruby literal ("f"*24 is embedded under VWA) it actually reaches malloc.
 *
 * No wire path, no app, no marker.
 */
#include "ruby.h"
#include <string.h>

static VALUE
stringprime_make(VALUE self, VALUE byte_value, VALUE len_value, VALUE count_value)
{
    unsigned int byte = NUM2UINT(byte_value);
    long len = NUM2LONG(len_value);
    long count = NUM2LONG(count_value);
    VALUE ary = rb_ary_new_capa(count);
    long i;

    if (len <= 0 || count <= 0 || count > 4096) rb_raise(rb_eArgError, "bad len/count");
    for (i = 0; i < count; i++) {
        VALUE s = rb_str_buf_new(len);
        rb_str_modify(s);
        memset(RSTRING_PTR(s), (int)byte, (size_t)len);
        rb_str_set_len(s, len);
        rb_ary_push(ary, s);
    }
    return ary;
}

void
Init_ruby2shell_casefold_stringprime(void)
{
    VALUE mod = rb_define_module("Ruby2ShellCasefoldStringprime");
    rb_define_singleton_method(mod, "make", stringprime_make, 3);
}
