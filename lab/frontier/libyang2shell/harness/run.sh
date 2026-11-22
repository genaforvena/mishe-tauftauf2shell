#!/usr/bin/env bash
# libyang2shell direct-call harness: two deterministic rounds, 40 assertions total.
# No sockets, no libyang build, no external system contacted at run time.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence
PASS=0; FAIL=0

ok() { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
has() { grep -qF -- "$2" "$1"; }

build() {
    local pin="$1" mode="$2" cc="$3" out="$4" san=""
    [ "$mode" = asan ] && san="-fsanitize=address"
    "$cc" -std=c11 -O0 -g $san -D"ALLOC_MODE_$(printf '%s' "$mode" | tr a-z A-Z)" \
        -DPIN_FILE="\"fns-$pin.inc\"" harness.c -o "$out" 2>/dev/null
}

# Normalized evidence: deterministic observation lines only, no PID/address/path.
normalize() {
    grep -E '^(INPUT_LEN|SINK_REQ|MALLOC_REQ|LOGERR|RC=|PTR_NULL|PTR_OFFSET|BUF16|TERM_OFFSET|VERBATIM_OK|ERROR: AddressSanitizer|WRITE of size|[0-9]+ bytes after|    #[0-9]+ .*(instrumented_memcpy|ly_in_read|lyb_read|lyb_read_string|main))' "$1" \
      | sed -E 's/0x[0-9a-f]+/0xADDR/g; s#/[^ ]+\.(c|inc|cpp):[0-9]+#PATH:LINE#g; s/ +/ /g'
}

round() {
    local r="$1" cc loghash="" bin
    python3 gen_fn.py >/dev/null
    python3 verify_verbatim.py > "evidence/r${r}-verbatim.log" 2>&1 \
        && has "evidence/r${r}-verbatim.log" "VERBATIM_OK" && ok "r$r verbatim pinned slices" \
        || no "r$r verbatim pinned slices"
    sha256sum ../src/parser_lyb-*.c ../src/in.c.pin > "evidence/r${r}-pin-hashes.txt"
    [ "$(wc -l < "evidence/r${r}-pin-hashes.txt")" -eq 4 ] \
        && ok "r$r four pinned source hashes recorded" || no "r$r pinned source hashes"

    for cc in gcc clang; do
        for pin in vuln partial hardened; do
            for mode in asan plain; do
                bin="r${r}-${cc}-${pin}-${mode}"
                build "$pin" "$mode" "$cc" "$bin" || no "r$r build $cc $pin $mode"
            done
        done
        ok "r$r builds $cc (3 pins x 2 modes)"

        # 1. Vulnerable pin, ASan: real heap overflow from the pinned write path.
        bin="r${r}-${cc}-vuln-asan"; log="evidence/r${r}-${cc}-vuln-asan.log"
        ./$bin ffffffff 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -ne 0 ] && has "$log" 'ERROR: AddressSanitizer: heap-buffer-overflow' \
          && has "$log" 'WRITE of size 1' && has "$log" '0 bytes after 1-byte region' \
          && has "$log" 'ly_in_read' && has "$log" 'lyb_read_string' \
          && has "$log" 'INPUT_LEN=ffffffff' && has "$log" 'MALLOC_REQ=0'; then
            ok "r$r $cc vuln ASan heap WRITE past malloc(0)"
        else
            no "r$r $cc vuln ASan"
        fi
        normalize "$log" >> "$loghash.tmp"

        # 2. Vulnerable pin, plain: chosen 0x41 at offset 0, terminator at 4 GiB-1.
        bin="r${r}-${cc}-vuln-plain"; log="evidence/r${r}-${cc}-vuln-plain.log"
        ./$bin ffffffff 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'SINK_REQ=536870911 SINK_COPY=16' \
          && has "$log" 'BUF16=4142434445464748494a4b4c4d4e4f50' \
          && has "$log" 'TERM_OFFSET=4294967295 TERM_BYTE=00'; then
            ok "r$r $cc vuln chosen 0x41 + terminator at UINT32_MAX"
        else
            no "r$r $cc vuln chosen 0x41"
        fi
        normalize "$log" >> "$loghash.tmp"

        # 3. Different chosen bytes, same offset.
        bin="r${r}-${cc}-vuln-plain"; log="evidence/r${r}-${cc}-vuln-plain-5a.log"
        ./$bin ffffffff 5a > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'BUF16=5a5b5c5d5e5f60616263646566676869'; then
            ok "r$r $cc vuln chosen 0x5a bytes"
        else
            no "r$r $cc vuln chosen 0x5a"
        fi
        normalize "$log" >> "$loghash.tmp"

        # 4. Advisory-era partial fix: 64-bit casts remove the 32-bit wrap but
        # still request a 4 GiB allocation and a 4 GiB read.
        bin="r${r}-${cc}-partial-plain"; log="evidence/r${r}-${cc}-partial-plain.log"
        ./$bin ffffffff 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'MALLOC_REQ=4294967296' \
          && has "$log" 'SINK_REQ=4294967295' \
          && has "$log" 'TERM_OFFSET=4294967295 TERM_BYTE=00'; then
            ok "r$r $cc partial fix: no wrap, 4 GiB allocation remains"
        else
            no "r$r $cc partial pin"
        fi
        normalize "$log" >> "$loghash.tmp"

        # 5/6. Hardened pin rejects before allocation or write.
        bin="r${r}-${cc}-hardened-asan"; log="evidence/r${r}-${cc}-hardened-asan.log"
        ./$bin ffffffff 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'LOGERR LYB string length overflow.' \
          && has "$log" 'RC=-2' && ! has "$log" 'MALLOC_REQ'; then
            ok "r$r $cc hardened pin rejects before alloc/write (ASan)"
        else
            no "r$r $cc hardened ASan"
        fi
        normalize "$log" >> "$loghash.tmp"

        bin="r${r}-${cc}-hardened-plain"; log="evidence/r${r}-${cc}-hardened-plain.log"
        ./$bin ffffffff 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'RC=-2' && has "$log" 'PTR_NULL=1' \
          && ! has "$log" 'SINK_REQ=536870911'; then
            ok "r$r $cc hardened pin plain: no allocation, no write"
        else
            no "r$r $cc hardened plain"
        fi
        normalize "$log" >> "$loghash.tmp"

        # 7/8. Safe controls on the vulnerable pin, both modes.
        bin="r${r}-${cc}-vuln-asan"; log="evidence/r${r}-${cc}-vuln-safe-asan.log"
        ./$bin 8 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && ! has "$log" 'ERROR: AddressSanitizer' \
          && has "$log" 'MALLOC_REQ=9' && has "$log" 'SINK_REQ=8 SINK_COPY=8'; then
            ok "r$r $cc safe 8-byte string clean under ASan"
        else
            no "r$r $cc safe ASan"
        fi
        normalize "$log" >> "$loghash.tmp"

        bin="r${r}-${cc}-vuln-plain"; log="evidence/r${r}-${cc}-vuln-safe-plain.log"
        ./$bin 8 41 > "$log" 2>&1; rc=$?
        if [ "$rc" -eq 0 ] && has "$log" 'BUF16=41424344454647480000000000000000' \
          && has "$log" 'TERM_OFFSET=8 TERM_BYTE=00'; then
            ok "r$r $cc safe 8-byte string clean in plain"
        else
            no "r$r $cc safe plain"
        fi
        normalize "$log" >> "$loghash.tmp"
    done

    mv "$loghash.tmp" "evidence/r${r}-normalized.txt"
    sha256sum "evidence/r${r}-normalized.txt" | cut -d' ' -f1 > "evidence/r${r}-hash.txt"
    printf 'round %s hash %s\n' "$r" "$(cat "evidence/r${r}-hash.txt")"
}

rm -f evidence/r*-normalized.txt evidence/r*-hash.txt
round 1
round 2
if cmp -s evidence/r1-normalized.txt evidence/r2-normalized.txt; then
    ok "two rounds byte-identical normalized evidence"
else
    no "two rounds byte-identical normalized evidence"
fi
if cmp -s evidence/r1-pin-hashes.txt evidence/r2-pin-hashes.txt; then
    ok "pinned source hashes stable"
else
    no "pinned source hashes stable"
fi
printf 'TOTAL PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
