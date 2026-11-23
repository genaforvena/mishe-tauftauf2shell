#!/bin/bash
# CVE-2026-125396 / "Upload2Shell" — Ghostscript Type 1 font-loader
# .putgstringcopy operand-type confusion, recovered .forceput, save/restore UAF.
# PostScript-level rung 1/2 differential on real, shipped gs 10.07.0 builds:
#   vulnerable 10.07.0  + type-confused font -> benign systemdict write succeeds
#   fixed 1484854e      + same font           -> operand guard blocks the write
#   vulnerable 10.07.0  + unmodified font     -> no write (safe input control)
# No network, no service, no off-loopback probe. All execution is local files.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" bin
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
    if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
    if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

# --- pinned bytes -----------------------------------------------------------
[ "$(srcsha ../src/gs_fonts.ps.ghostpdl-10.07.0)" = \
  844ca0cb12eccd32876d938eef42288cd17e9ab79b91f7dec6bb7ded1a9c3233 ] \
  && ok "pin-vuln-gs-fonts-10.07.0" || no "pin-vuln-gs-fonts-10.07.0"
[ "$(srcsha ../src/gs_fonts.ps.ghostpdl-10.07.1)" = \
  844ca0cb12eccd32876d938eef42288cd17e9ab79b91f7dec6bb7ded1a9c3233 ] \
  && ok "pin-10.07.1-byte-identical" || no "pin-10.07.1-byte-identical"
[ "$(srcsha ../src/gs_fonts.ps.1484854e)" = \
  1ad111af10bcce10f1c2fe0162c934121d4cfb7265dc44aa8df6a07815f02d34 ] \
  && ok "pin-fixed-gs-fonts-1484854e" || no "pin-fixed-gs-fonts-1484854e"
[ "$(srcsha ../src/fix-1484854e.patch)" = \
  8a279018297ebd71cea1e008f9de0ff411a70b718c5657de29eae1cdc6637073 ] \
  && ok "pin-fix-patch" || no "pin-fix-patch"
[ "$(srcsha font-injected.pfa)" = \
  ef164da0c9db3fa84ea2f5494dfc856c22fd65752336a48dbf24224ec386b1fa ] \
  && ok "pin-injected-font" || no "pin-injected-font"
[ "$(srcsha font-safe.pfa)" = \
  85649a2b1b2f86df9addfe0ccc27ae48ec2ea6ee1815e180a33d73d062b2a4c6 ] \
  && ok "pin-safe-font" || no "pin-safe-font"
[ "$(srcsha rung1.ps)" = \
  8d83df9aad539d30a6942f4d618bef0411c17759b0d0fa05d396d7b952dbd062  ] \
  && ok "pin-runner" || no "pin-runner"
if (cd ../src && sha256sum -c --status SHA256SUMS); then \
  ok "all-src-pinned-blobs-match"; else no "all-src-pinned-blobs-match"; fi
[ "$(grep -cF 'Resource/Init/gs_fonts.ps' ../src/fix-1484854e.patch)" -ge 2 ] \
  && ok "fix-scope-is-gs-fonts-only" || no "fix-scope-is-gs-fonts-only"
[ "$(grep -cF 'Check operand types' ../src/gs_fonts.ps.1484854e)" -eq 1 ] \
  && ok "fixed-blob-has-type-guard" || no "fixed-blob-has-type-guard"
[ "$(grep -cF 'Check operand types' ../src/gs_fonts.ps.ghostpdl-10.07.0)" -eq 0 ] \
  && ok "vuln-blob-lacks-type-guard" || no "vuln-blob-lacks-type-guard"
[ "$(grep -cF '/.putgstringcopy' ../src/gs_fonts.ps.ghostpdl-10.07.0)" -ge 2 ] \
  && ok "vuln-blob-defines-helper" || no "vuln-blob-defines-helper"

# --- binaries (built from swapped pinned resources; see build-bins.sh) -------
[ -x bin/gs-vuln ] && ok "gs-vuln-present" || no "gs-vuln-present"
[ -x bin/gs-fixed ] && ok "gs-fixed-present" || no "gs-fixed-present"
[ "$(bin/gs-vuln --version 2>/dev/null)" = "10.07.0" ] \
  && ok "gs-vuln-version" || no "gs-vuln-version"
[ "$(bin/gs-fixed --version 2>/dev/null)" = "10.07.0" ] \
  && ok "gs-fixed-version" || no "gs-fixed-version"

FONT=font-injected.pfa
SAFE=font-safe.pfa
run_case() {
    GS_FONT_PATH="$1" "$2" -q -dNODISPLAY -dNOSAFER rung1.ps > "$3" 2>&1
}
ABSINJ="$(pwd)/$FONT"
ABSSAFE="$(pwd)/$SAFE"

# --- rung 1/2: type-confused font reaches .putgstringcopy -------------------
run_case "$ABSINJ" bin/gs-vuln "$E/vuln-injected.out"
has "$E/vuln-injected.out" 'TRAP_FIRED=true' 'r1-vuln-typecheck-trapped'
has "$E/vuln-injected.out" 'GS_FORCEPUT_RESULT=true' 'r2-vuln-privileged-write-succeeded'

# --- fixed control: operand-type guard blocks the recovered store -----------
run_case "$ABSINJ" bin/gs-fixed "$E/fixed-injected.out"
has "$E/fixed-injected.out" 'TRAP_FIRED=true' 'r1-fixed-typecheck-trapped'
has "$E/fixed-injected.out" 'GS_FORCEPUT_RESULT=false' 'r2-fixed-privileged-write-blocked'

# --- safe input control: unmodified font, no type confusion -----------------
run_case "$ABSSAFE" bin/gs-vuln "$E/vuln-safe.out"
has "$E/vuln-safe.out" 'TRAP_FIRED=false' 'r1-safe-no-typecheck'
has "$E/vuln-safe.out" 'GS_FORCEPUT_RESULT=false' 'r2-safe-no-privileged-write'

# --- deterministic normalized trace (no path, PID, address or object id) ----
{
  cat "$E/vuln-injected.out" "$E/fixed-injected.out" "$E/vuln-safe.out"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/==[0-9]+==/==PID==/g; s/^[0-9]{6,}[[:space:]]/OBJID /g' \
  > "$E/normalized.txt"
TRACE=$(srcsha "$E/normalized.txt")
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
