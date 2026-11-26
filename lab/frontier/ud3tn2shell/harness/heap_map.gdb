set pagination off
set confirm off
set breakpoint pending on
break components/bundle6/reports.c:440 if parser->bytes_remaining > 100
commands
  silent
  set $hits = $hits + 1
  if $hits == $MAP_HITS
    set $p = parser->record_bundle_source_str
    printf "HEAPMAP hits=%d index=%d remaining=%d p=%p record=%p\n", $hits, parser->current_index, parser->bytes_remaining, $p, parser->record
    printf "HEAPMAP chunk header at p-16\n"
    x/2gx $p-16
    printf "HEAPMAP raw bytes p-32..p+1024\n"
    x/1056bx $p-32
    printf "HEAPMAP words p-32..p+1024\n"
    x/132gx $p-32
    printf "HEAPMAP administrative record struct\n"
    x/24gx parser->record
    printf "HEAPMAP_DONE\n"
    kill
    quit
  end
  continue
end
set $hits = 0
run
