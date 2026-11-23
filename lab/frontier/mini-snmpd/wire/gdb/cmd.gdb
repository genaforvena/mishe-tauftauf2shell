# gdb batch commands: instrumented read of the vulnerable daemon at the
# 20-subid cap branch in decode_oid(). Plant-started loopback process, no
# source edits, no external address. Transcript captured by run_gdb.sh.
set pagination off
set confirm off
set print pretty off
set breakpoint pending on

# Trace every decode_oid byte read whose offset is at or past the logical
# packet (client->size is 2048 for the crafted datagram).
break protocol.c:239 if *pos >= size
commands
  silent
  printf "OOB_READ pos=%lu byte=%02x addr=%p packet=%p packet_end=%p delta=%ld\n", *pos, packet[*pos], &packet[*pos], packet, packet + size, (long)(&packet[*pos] - (packet + size))
  continue
end

# Stop only when the 20-subid cap actually fires (matches the log message
# "overflow for OID byte"), then dump the decoder and global-struct state.
break protocol.c:230 if value->subid_list_length >= 20
run
printf "=== CAP_BRANCH_REACHED ===\n"
print size
print *pos
print len
print value->subid_list_length
print/x value->subid_list@20
print/x packet
print/x packet + size
print packet == g_udp_client.packet
print g_udp_client.size
print g_udp_client.outgoing
print/x &g_udp_client
print/x &g_udp_client.packet[0]
print/x &g_udp_client.packet[2048]
print/x &g_udp_client.size
print/x &g_udp_client.outgoing
printf "bytes at logical packet end (g_udp_client.size, little endian):\n"
x/16bx g_udp_client.packet + 2048
printf "last in-bounds bytes (offset 2032..2047):\n"
x/16bx g_udp_client.packet + 2032
printf "bytes at offset 2064 onward:\n"
x/16bx g_udp_client.packet + 2064
printf "=== END_CAP_DUMP ===\n"
quit
