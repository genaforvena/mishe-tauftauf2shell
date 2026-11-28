#!/bin/bash
# W370: static scan of the pinned gem trees used by the stock lab apps for
# (a) request strings that get re-tagged with a wire-nominated encoding, and
# (b) direct case-fold call sites that could consume such strings.
# Read-only; evidence goes to gitignored lab/build/evidence.
set -u
cd "$(dirname "$0")/../.." || exit 1
GEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0/gems"
OUT="${1:-lab/build/evidence/casemap-chain/w370/static-tagging.txt}"
mkdir -p "$(dirname "$OUT")"
{
  echo "== multipart part name/body encoding tags (Rack 3.2.9) =="
  grep -n -E 'def tag_multipart_encoding|name\.force_encoding|body\.force_encoding|if k == "charset"|def find_encoding' \
    "$GEMS/rack-3.2.9/lib/rack/multipart/parser.rb"
  echo "== parse_boundary token scanner (Rack 3.2.9) =="
  grep -n -E 'StringScanner\.new\(content_type\.b\)|token = |scanner\.scan\(token\)|name\.casecmp\?' \
    "$GEMS/rack-3.2.9/lib/rack/multipart/parser.rb" | head -12
  echo "== Rails request param encoding templates (ActionPack 8.1.4.1) =="
  grep -rn -E 'force_encoding\(designated_encoding\)|force_encoding\(encoding_template' \
    "$GEMS/actionpack-8.1.4.1/lib/action_dispatch/http" "$GEMS/actionpack-8.1.4.1/lib/action_dispatch/request" || true
  echo "== direct case-fold callers in the pinned request-path gems =="
  grep -rn -E '\.(casecmp\?|upcase|downcase|capitalize|swapcase)(\(|\b)' \
    "$GEMS/rack-3.2.9/lib/rack" \
    "$GEMS/actionpack-8.1.4.1/lib/action_dispatch" \
    "$GEMS/puma-8.1.2/lib/puma" 2>/dev/null | grep -v -E '_test|/test/' | head -80
} > "$OUT"
echo "wrote $OUT ($(wc -l < "$OUT") lines)"
