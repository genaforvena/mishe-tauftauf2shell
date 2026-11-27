set pagination off
set confirm off
set breakpoint pending on

break components/bundle6/reports.c:440 if parser->current_index == 1
commands
  silent
  printf "STORE_BEGIN p=%p record=%p rem=%d\n", parser->record_bundle_source_str, parser->record, parser->bytes_remaining
  if parser->bytes_remaining < 100
    x/40bx parser->record_bundle_source_str
  end
  continue
end

break components/ud3tn/report_manager.c:127
commands
  silent
  if record != 0
    printf "FREE_REC record=%p status=%p bpdu=%p scheme=%d dtn=%p\n", record, record->status_report, record->bpdu, record->bundle_source_eid.scheme, record->bundle_source_eid.dtn_eid
    x/2gx record-16
  end
  continue
end

break __GI___libc_free
commands
  silent
  if $rdi != 0
    printf "LIBC_FREE mem=%p\n", $rdi
    x/2gx $rdi-16
  end
  continue
end

run
printf "CHAIN_STOP\n"
bt 8
