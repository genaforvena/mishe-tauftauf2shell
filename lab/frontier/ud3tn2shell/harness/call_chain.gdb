set pagination off
set confirm off
set breakpoint pending on

break components/bundle6/reports.c:440 if parser->current_index == 1
commands
  silent
  printf "STORE p=%p record=%p rem=%d\n", parser->record_bundle_source_str, parser->record, parser->bytes_remaining
  x/8bx parser->record_bundle_source_str
  continue
end

break components/ud3tn/report_manager.c:127 if record != 0
commands
  silent
  printf "FREE_REC record=%p status=%p scheme=%d\n", record, record->status_report, record->bundle_source_eid.scheme
  continue
end

break components/ud3tn/agent_manager.c:560
commands
  silent
  python import os, gdb; open(os.environ["UD3TN_AGENT_FILE"], "a").write("%#x %#x %#x\n" % (int(gdb.parse_and_eval("ag_ptr")), int(gdb.parse_and_eval("*(unsigned long long*)((char*)ag_ptr-8)")), int(gdb.parse_and_eval("*(unsigned long long*)((char*)ag_ptr+16)"))))
  continue
end
break __GI___libc_free if $rdi == 0x7ffff0001040
commands
  silent
  printf "LIBC_FREE mem=%p hdr=%p\n", $rdi, *(void **)($rdi-8)
  continue
end
break components/ud3tn/agent_manager.c:414
commands
  silent
  printf "CALL_SITE ag=%p trx=%p param=%p\n", ag_ptr, ag_ptr->trx_callback, ag_ptr->param
  continue
end

break system
commands
  silent
  printf "SYSTEM_HIT rdi=%p\n", $rdi
  x/s $rdi
  continue
end

run
printf "CHAIN_STOP (no system call)\n"
