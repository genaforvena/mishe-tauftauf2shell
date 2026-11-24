#!/usr/bin/env bash
# W185: real Lottie-load -> embedded-JPEG-asset -> jpgd reachability matrix.
# Run from lab/frontier/thorvg2shell after building /tmp/w185-lottie-{vuln,fixed}.
set -u
cd "$(dirname "$0")/.." || exit 2
mkdir -p harness/evidence

python3 harness/make_lottie_poc.py poc/control_large.jpg poc/lottie_control.json || exit 2
python3 harness/make_lottie_poc.py poc/dup4_large.jpg poc/lottie_dup4_large.json || exit 2
python3 harness/make_lottie_poc.py poc/dup4.jpg poc/lottie_dup4_small.json || exit 2

INC=src/vuln/inc
for t in vuln:/tmp/w185-lottie-vuln fixed:/tmp/w185-lottie-fixed; do
    tag=${t%%:*}; b=${t#*:}
    g++ -std=c++17 -g -O0 -I"$INC" harness/lottie_api.cpp \
        -L"$b/src" -lthorvg-1 -Wl,-rpath,"$b/src" -o "harness/bin/lottie-api-$tag" || exit 2
done

: > harness/evidence/lottie.tsv
printf 'build\tjson\tjpegsize\trc\tstdout\n' >> harness/evidence/lottie.tsv
for tag in vuln fixed; do
    for spec in lottie_control:control_large.jpg lottie_dup4_small:dup4.jpg lottie_dup4_large:dup4_large.jpg; do
        name=${spec%%:*}; jpg=${spec#*:}
        out=$(harness/bin/lottie-api-$tag "poc/$name.json" lottie+json 2>&1)
        rc=$?
        printf '%s\t%s\t%s\t%d\t%s\n' "$tag" "$name" \
            "$(stat -c%s "poc/$jpg")" \
            "$rc" "$(printf '%s' "$out" | tr '\n' ' ')" >> harness/evidence/lottie.tsv
    done
done
cat harness/evidence/lottie.tsv
