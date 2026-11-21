set pagination off
set confirm off
break consumer-service.c:106
run
set $objp = p
set $objusable = usable
printf "BREAK line106: p=%p usable=%zu sizeofPayload=%zu\n", $objp, $objusable, sizeof(Payload)
watch -l *(unsigned char*)($objp+9)
continue
printf "WATCH HIT at obj+9: new=%02x (first byte past arr[5])\n", *(unsigned char*)($objp+9)
bt 6
printf "glibc chunk size field at obj-8 = %#lx (0x21 = 32-byte chunk, PREV_INUSE)\n", *(unsigned long*)($objp-8)
printf "NEXT CHUNK size field at obj+24 = %#lx BEFORE decode returns\n", *(unsigned long*)($objp+24)
echo DUMP 48 bytes from obj-16 at first store:
x/48bx $objp-16
disable 2
break consumer-service.c:115
continue
echo POST-DECODE 48 bytes from obj-16:
x/48bx $objp-16
printf "post: obj+9=%02x obj+10=%02x obj+11=%02x next_chunk_size=%#lx\n", *(unsigned char*)($objp+9), *(unsigned char*)($objp+10), *(unsigned char*)($objp+11), *(unsigned long*)($objp+24)
quit
