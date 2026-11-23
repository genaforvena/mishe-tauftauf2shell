# Inspect groomed A/B chunk state at the abort.
set pagination off
set confirm off
set print pretty off
break calloc if $rsi == 32783
run /tmp/libheif-one-row.heif /tmp/groom-out/g.heif
finish
continue
finish
printf "PLANE2=%p A=%p B=%p\n", $rax, g_A, g_B
continue
printf "--- A chunk header (A-16) ---\n"
x/4gx g_A-16
printf "--- B chunk header (B-16) ---\n"
x/4gx g_B-16
printf "B fn=%p tag0=0x%02x tag8=0x%02x\n", g_B->fn, g_B->tag[0], g_B->tag[8]
bt 3
quit
