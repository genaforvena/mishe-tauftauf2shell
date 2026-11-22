set pagination off
set confirm off
set print pretty off
break xs_insert_m
commands
  silent
  if offset >= 24
    printf "INSERT offset=%d usable=%d byte=0x%02x size=%d\n", offset, malloc_usable_size(data), *(unsigned char *)mem, size
  end
  continue
end
run ARG_PAYLOAD
quit
