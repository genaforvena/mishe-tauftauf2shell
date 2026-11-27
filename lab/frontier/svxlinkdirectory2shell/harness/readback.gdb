set pagination off
set confirm off
break EchoLinkStationData.cpp:219
run 120
printf "CHOSEN_READBACK "
printf "%02x%02x%02x%02x%02x%02x%02x%02x", str[45], str[46], str[47], str[48], str[49], str[50], str[51], str[52]
printf "%02x%02x%02x%02x%02x%02x%02x%02x\n", str[53], str[54], str[55], str[56], str[57], str[58], str[59], str[60]
quit
