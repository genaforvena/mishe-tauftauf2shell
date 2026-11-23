#!/bin/sh
# Public-API consumer matrix: real tvg::Picture::load(data,size,"jpg") on the
# pinned ThorVG shared libraries. Run from lab/frontier/thorvg2shell.
set -u
out=harness/evidence/public-api.tsv
: > "$out"
{
  printf '# built %s\n' "$(date -u +%FT%TZ)"
  printf '# vuln_lib %s\n' "$(sha256sum /tmp/thorvg-public-build/src/libthorvg-1.so.1.1.1 | cut -d" " -f1)"
  printf '# fixed_lib %s\n' "$(sha256sum /tmp/thorvg-public-fixed/src/libthorvg-1.so.1.1.2 | cut -d" " -f1)"
  printf 'build\tjpeg\trc\tstdout\n'
} >> "$out"
for b in vuln fixed; do
  for f in poc/control.jpg poc/dup2.jpg poc/dup3.jpg poc/dup4.jpg \
           poc/control_large.jpg poc/dup4_large.jpg \
           poc/marker_control.jpg poc/marker_dup4.jpg; do
    msg=$(timeout 60 ./harness/bin/public-api-"$b" "$f" 2>&1)
    rc=$?
    printf '%s\t%s\t%s\t%s\n' "$b" "$(basename "$f")" "$rc" \
      "$(printf '%s' "$msg" | tr '\n' ' ')" >> "$out"
  done
done
cat "$out"
printf 'matrix_sha256 %s\n' "$(sha256sum "$out" | cut -d' ' -f1)"
