#!/bin/sh
# Run every binary against every PoC; one transcript per case plus a summary.
set -u
cd "$(dirname "$0")/.."
mkdir -p harness/evidence
summary=harness/evidence/matrix.tsv
: > "$summary"
for jpg in poc/*.jpg; do
    [ -e "$jpg" ] || continue
    for bin in harness/bin/g-vuln-asan harness/bin/g-fixed-asan \
               harness/bin/clang-vuln-asan harness/bin/clang-fixed-asan \
               harness/bin/g-vuln-plain harness/bin/g-fixed-plain \
               harness/bin/clang-vuln-plain harness/bin/clang-fixed-plain \
               harness/bin/g-vuln-allocinstr-asan harness/bin/g-vuln-allocinstr-plain \
               harness/bin/clang-vuln-allocinstr-asan; do
        [ -x "$bin" ] || continue
        j=$(basename "$jpg"); b=$(basename "$bin")
        out=harness/evidence/${b}__${j}.out
        ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$bin" "$jpg" > "$out" 2>&1
        rc=$?
        printf '%s\t%s\t%s\n' "$b" "$j" "$rc" >> "$summary"
    done
done
cat "$summary"
