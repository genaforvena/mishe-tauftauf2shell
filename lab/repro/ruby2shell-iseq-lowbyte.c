/* Analysis-only probe for Ruby2Shell's one-byte iseq_encoded[0] effect.
 * Applies exactly 0x53 (upcase) or 0x73 (fold) to the low byte of a threaded
 * instruction handler. Not a delivery harness and not part of an app path.
 */
#include "ruby.h"
#include "vm_core.h"
#include "iseq.h"

extern const rb_iseq_t *rb_iseqw_to_iseq(VALUE iseqw);

static VALUE
iseq_info(VALUE self, VALUE iseqw)
{
    const rb_iseq_t *iseq = rb_iseqw_to_iseq(iseqw);
    const VALUE *code = ISEQ_BODY(iseq)->iseq_encoded;
    return rb_ary_new3(6,
        SIZET2NUM((size_t)code), UINT2NUM(ISEQ_BODY(iseq)->iseq_size),
        SIZET2NUM(code[0]), SIZET2NUM(code[1]), SIZET2NUM(code[2]),
        SIZET2NUM(code[3]));
}

static VALUE
value_identity(VALUE self, VALUE value)
{
    return SIZET2NUM((size_t)value);
}

static VALUE
iseq_patch_index(VALUE self, VALUE iseqw, VALUE index_value, VALUE byte_value,
                 VALUE offset_value, VALUE table_value)
{
    const rb_iseq_t *iseq = rb_iseqw_to_iseq(iseqw);
    VALUE *code = ISEQ_BODY(iseq)->iseq_encoded;
    unsigned int index = NUM2UINT(index_value);
    unsigned int byte = NUM2UINT(byte_value);
    VALUE load_base = code[0] - (VALUE)NUM2SIZET(offset_value);
    const VALUE *table = (const VALUE *)(load_base + (VALUE)NUM2SIZET(table_value));
    if (index >= 220) rb_raise(rb_eArgError, "instruction index out of range");
    if (byte != 0x53 && byte != 0x73) rb_raise(rb_eArgError, "not a Ruby2Shell byte");
    code[0] = (table[index] & ~(VALUE)0xff) | (VALUE)byte;
    return iseq_info(self, iseqw);
}

static VALUE
iseq_disclosure(VALUE self, VALUE iseqw, VALUE offset_value, VALUE table_value,
                VALUE byte_value, VALUE putself_value, VALUE putnil_value,
                VALUE leave_value)
{
    const rb_iseq_t *iseq = rb_iseqw_to_iseq(iseqw);
    VALUE *code = ISEQ_BODY(iseq)->iseq_encoded;
    VALUE load_base = code[0] - (VALUE)NUM2SIZET(offset_value);
    const VALUE *table = (const VALUE *)(load_base + (VALUE)NUM2SIZET(table_value));
    unsigned int byte = NUM2UINT(byte_value);
    unsigned int putself = NUM2UINT(putself_value);
    unsigned int putnil = NUM2UINT(putnil_value);
    unsigned int leave = NUM2UINT(leave_value);
    if (byte != 0x53 && byte != 0x73) rb_raise(rb_eArgError, "not a Ruby2Shell byte");
    if (putself >= 220 || putnil >= 220 || leave >= 220)
        rb_raise(rb_eArgError, "instruction index out of range");
    code[0] = (table[putself] & ~(VALUE)0xff) | (VALUE)byte;
    code[1] = table[putnil];
    code[2] = table[leave];
    ISEQ_BODY(iseq)->iseq_size = 3;
    return iseq_info(self, iseqw);
}

void
Init_ruby2shell_iseq_lowbyte(void)
{
    VALUE mod = rb_define_module("Ruby2ShellIseqLowbyte");
    rb_define_singleton_method(mod, "info", iseq_info, 1);
    rb_define_singleton_method(mod, "identity", value_identity, 1);
    rb_define_singleton_method(mod, "patch_index", iseq_patch_index, 5);
    rb_define_singleton_method(mod, "disclosure", iseq_disclosure, 7);
}
