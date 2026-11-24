set pagination off
set confirm off
break fvimportbdf.c:1751 if glyph < 0
run -script import-filechoice.ff
set $encsp=(char*)encs
watch tcache->entries[5]
continue
printf "STOP1 entries5=%p\n", tcache->entries[5]
bt 2
continue
printf "STOP2 entries5=%p\n", tcache->entries[5]
bt 5
continue
printf "STOP3 entries5=%p\n", tcache->entries[5]
bt 2
continue
printf "STOP4 entries5=%p\n", tcache->entries[5]
bt 5
continue
printf "STOP5 entries5=%p\n", tcache->entries[5]
bt 5
continue
printf "STOP6 entries5=%p\n", tcache->entries[5]
bt 5
continue
quit
