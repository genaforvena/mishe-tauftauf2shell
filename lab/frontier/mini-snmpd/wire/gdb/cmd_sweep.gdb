# Count decode_oid reads at or past the logical 2048-byte packet, then dump
# the decoder state at whichever return path decode_oid takes.
set pagination off
set confirm off
set print pretty off
set $oob = 0

break protocol.c:239 if *pos >= size
commands
  silent
  set $oob = $oob + 1
  continue
end
break protocol.c:233
break protocol.c:243
break protocol.c:255
break protocol.c:195
commands 2 3 4 5
  silent
  printf "RESULT oob=%ld pos=%lu len=%lu subids=%lu subid5=%u subid6=%u\n", $oob, *pos, len, value->subid_list_length, value->subid_list[5], value->subid_list[6]
  quit
end
run
