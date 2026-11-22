set pagination off
set confirm off
set breakpoint pending on
break components/bundle6/reports.c:440
commands
  silent
  set $hits = $hits + 1
  if $hits == 20
    printf "READBACK hits=%d index=%d remaining=%d ptr=%p\n", $hits, parser->current_index, parser->bytes_remaining, parser->record_bundle_source_str
    x/32bx parser->record_bundle_source_str
    printf "READBACK_DONE\n"
    kill
    quit
  end
  continue
end
set $hits = 0
run
