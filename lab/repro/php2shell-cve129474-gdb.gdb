# gdb batch script: instrument-observe the stale-argument read in
# CVE-2026-129474 / GHSA-8mjj-2r7p-4hg2 on the affected 8.5.12 CLI.
#
# Run against the vulnerable build with the vendor case from the committed
# harness (no network, local process only):
#
#   gdb -q -batch -x lab/repro/php2shell-cve129474-gdb.gdb --args \
#     lab/build/php-8.5.12-asan/sapi/cli/php \
#     -n -d fatal_error_backtraces=1 -d zend.exception_ignore_args=0 \
#     -d memory_limit=4M \
#     lab/build/evidence/w29-cve129474/ghsa-8mjj-2r7p-4hg2.php
#
# It breaks at Zend/zend_builtin_functions.c:1822, the buggy
#   p = ZEND_CALL_VAR_NUM(call, last_var + T);
# which the 8.5.13 fix skips for ZEND_ACC_CALL_VIA_TRAMPOLINE frames (1<<18).
# The first stop must show the magic-trampoline frame (trampoline_bit=1) with
# the correct leading slots 1,2 at p; the second stop (the loop head at :1825,
# i==0) shows the slots actually consumed after the reset: 3,4,STRING,UNDEF,
# UNDEF at p+2 zvals. Those are the five wrong zvals printed in the fatal
# backtrace. This is a debugger observation of the wrong frame slots, not an
# ASan report: the soft OOM needs ZendMM, which hides the read from ASan.
set pagination off
set confirm off
set auto-load safe-path /
set environment ASAN_OPTIONS detect_leaks=0

break zend_builtin_functions.c:1822 if num_args == 5
commands
  silent
  printf "=== PRE-RESET (line 1822) ===\n"
  printf "call=%p func_type=%d fn_flags=0x%x trampoline_bit=%d num_args=%u first_extra_arg=%u last_var=%u T=%u\n", call, call->func->type, call->func->common.fn_flags, (call->func->common.fn_flags & 0x40000) != 0, num_args, first_extra_arg, call->func->op_array.last_var, call->func->op_array.T
  printf "p=%p\n", p
  printf "  p[0]: type=%d lval=%ld\n", p[0].u1.v.type, p[0].value.lval
  printf "  p[1]: type=%d lval=%ld\n", p[1].u1.v.type, p[1].value.lval
  continue
end

break zend_builtin_functions.c:1825 if num_args == 5 && i == 0
commands
  silent
  printf "=== POST-RESET (line 1825, slots consumed) ===\n"
  printf "i=%u num_args=%u p=%p\n", i, num_args, p
  printf "  p[0]: type=%d lval=%ld\n", p[0].u1.v.type, p[0].value.lval
  printf "  p[1]: type=%d lval=%ld\n", p[1].u1.v.type, p[1].value.lval
  printf "  p[2]: type=%d str=%p\n", p[2].u1.v.type, p[2].value.str
  printf "  p[3]: type=%d lval=%ld\n", p[3].u1.v.type, p[3].value.lval
  printf "  p[4]: type=%d lval=%ld\n", p[4].u1.v.type, p[4].value.lval
  continue
end

run
quit
