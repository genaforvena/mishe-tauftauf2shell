set pagination off
set confirm off
set breakpoint pending on

# Stop on the first byte stored into the tcache-poisoned follow-up allocation.
break components/bundle6/reports.c:440 if parser->current_index == 1 && parser->bytes_remaining == 38
commands
  silent
  printf "PROBE_HIT p=%p record=%p rem=%d\n", parser->record_bundle_source_str, parser->record, parser->bytes_remaining
  dump binary memory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/ud3tn2shell/arena-probe/mainheap.bin 0x5555555b8000 0x5555555bc000
  bt 8
  info threads
  info proc mappings
  dump binary memory /home/mesh-home/mishe-tauftauf2shell/lab/frontier/ud3tn2shell/arena-probe/heap.bin 0x7ffff0000000 0x7ffff0020000
  printf "PROBE_DUMPED\n"
  quit
end

run
