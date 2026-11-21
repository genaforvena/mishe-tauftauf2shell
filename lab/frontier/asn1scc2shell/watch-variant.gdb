set pagination off
set confirm off
break variant-service.c:106
run
set $objp = p
printf "BREAK: p=%p sizeof=%zu usable=%zu\n", $objp, sizeof(Payload), malloc_usable_size($objp)
printf "PRE next-chunk size field at obj+24 = %#lx (live heap metadata)\n", *(unsigned long*)($objp+24)
watch -l *(unsigned char*)($objp+24)
continue
printf "WATCH HIT obj+24: new=%02x (first chosen byte in next chunk's size field)\n", *(unsigned char*)($objp+24)
bt 5
disable 2
break variant-service.c:115
continue
echo POST-DECODE 56 bytes from obj-16 (chunk header, object, next chunk header):
x/56bx $objp-16
printf "POST next-chunk size field at obj+24 = %#lx (PRE was above)\n", *(unsigned long*)($objp+24)
printf "chosen at obj+24..31 = %02x %02x %02x %02x %02x %02x %02x %02x\n", *(unsigned char*)($objp+24), *(unsigned char*)($objp+25), *(unsigned char*)($objp+26), *(unsigned char*)($objp+27), *(unsigned char*)($objp+28), *(unsigned char*)($objp+29), *(unsigned char*)($objp+30), *(unsigned char*)($objp+31)
quit
