#!/bin/bash
# Build host ASan/plain arms from the pinned SendReceiveDeviceGroupMessage bodies.
# The function body is extracted verbatim between its definition and the next
# top-level function; for the fixed arm only, the upstream one-token typo
# "snprintf-p" is repaired to "snprintf_P" so the file compiles (see PROVENANCE).
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=src
OUT=harness/gen
mkdir -p "$OUT"

extract() {
  local in="$1" out="$2"
  awk '
    /^void SendReceiveDeviceGroupMessage\(/ {on=1}
    /^bool _SendDeviceGroupMessage\(/ {on=0}
    on {print}
  ' "$in" > "$out"
}

extract "$SRC/support_device_groups.vuln.ino" "$OUT/fn.vuln.cpp"
extract "$SRC/support_device_groups.fixed.ino" "$OUT/fn.fixed.raw.cpp"
sed 's/snprintf-p(/snprintf_P(/' "$OUT/fn.fixed.raw.cpp" > "$OUT/fn.fixed.cpp"
if grep -q 'snprintf-p' "$OUT/fn.fixed.cpp"; then echo "typo repair failed" >&2; exit 1; fi
printf 'typo_repair_count=%s\n' "$(grep -c 'snprintf_P(log_ptr, log_remaining, PSTR("%u,%u' "$OUT/fn.fixed.cpp")" > "$OUT/typo-repair.txt"

for arm in vuln fixed; do
  { echo '#include "shim.h"'; cat "$OUT/fn.$arm.cpp"; echo '#include "main.cpp"'; } > "$OUT/main.$arm.cpp"
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address -I harness \
      "$OUT/main.$arm.cpp" -o "$OUT/dgr.$arm.asan"
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer -I harness \
      "$OUT/main.$arm.cpp" -o "$OUT/dgr.$arm.plain"
  awk '
    /^void ProcessDeviceGroupMessage\(/ {on=1}
    /^void DeviceGroupStatus\(/ {on=0}
    on {print}
  ' "$SRC/support_device_groups.$arm.ino" > "$OUT/process.$arm.cpp"
  { echo '#include "shim.h"'; cat "$OUT/fn.$arm.cpp"; cat "$OUT/process.$arm.cpp";
    echo '#include "main_wire.cpp"'; } > "$OUT/main_wire.$arm.cpp"
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
      -DUSE_SHIM_LOOPBACK_UDP -I harness "$OUT/main_wire.$arm.cpp" \
      -o "$OUT/dgr.$arm.wire.asan"
  g++ -std=gnu++17 -O0 -g -fno-omit-frame-pointer -DUSE_SHIM_LOOPBACK_UDP \
      -I harness "$OUT/main_wire.$arm.cpp" -o "$OUT/dgr.$arm.wire.plain"
done
echo BUILD_OK
sha256sum "$SRC/support_device_groups.vuln.ino" "$SRC/support_device_groups.fixed.ino" \
          "$OUT/fn.vuln.cpp" "$OUT/fn.fixed.cpp" | tee "$OUT/build.sha256"
