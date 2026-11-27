set pagination off
set confirm off
break sftpserver.c:1853
run 4096 41
printf "CHOSEN_41 "
printf "%02x%02x%02x%02x%02x%02x%02x%02x", z_long_name[350], z_long_name[351], z_long_name[352], z_long_name[353], z_long_name[354], z_long_name[355], z_long_name[356], z_long_name[357]
printf "%02x%02x%02x%02x%02x%02x%02x%02x\n", z_long_name[358], z_long_name[359], z_long_name[360], z_long_name[361], z_long_name[362], z_long_name[363], z_long_name[364], z_long_name[365]
run 4096 42
printf "CHOSEN_42 "
printf "%02x%02x%02x%02x%02x%02x%02x%02x", z_long_name[350], z_long_name[351], z_long_name[352], z_long_name[353], z_long_name[354], z_long_name[355], z_long_name[356], z_long_name[357]
printf "%02x%02x%02x%02x%02x%02x%02x%02x\n", z_long_name[358], z_long_name[359], z_long_name[360], z_long_name[361], z_long_name[362], z_long_name[363], z_long_name[364], z_long_name[365]
quit
