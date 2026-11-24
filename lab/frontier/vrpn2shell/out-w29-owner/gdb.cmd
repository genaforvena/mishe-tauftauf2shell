set pagination off
set confirm off
set max-value-size 100000
break vrpn_Connection.C:405
commands
silent
printf "AT405 base=%p slot=%p value=%p useEntry=%d\n", &d_entry[0], &d_entry[-2], d_entry[-2].name, useEntry
bt 5
up 2
printf "UP2 fn=%s\n", __func__
p endpoint
p/x (unsigned long)endpoint + 65840
p/x (unsigned long)&((vrpn_Endpoint_IP*)endpoint)->d_tcpInbuf
p/x (unsigned long)((vrpn_Endpoint_IP*)endpoint)->d_tcpInbuf
p/x (unsigned long)&((vrpn_Endpoint_IP*)endpoint)->d_tcpAlignedInbuf[0]
quit
end
run -f lab/frontier/vrpn2shell/vrpn.cfg 15367
