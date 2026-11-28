#!/bin/bash
# W369 static caller enumeration. Deterministic grep over the pinned lab gem
# trees actually used by the stock Sinatra and `rails new` apps. Read-only.
set -u
cd "$(dirname "$0")/../.." || exit 1
BASE="lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0/gems"
for gem in rack-3.2.8 rack-3.2.9 sinatra-4.2.2 rack-protection-4.2.2 \
           actionpack-8.1.4.1 puma-8.1.2 webrick-1.9.2; do
  dir="$BASE/$gem/lib"
  [ -d "$dir" ] || continue
  echo "== $gem =="
  grep -RInE 'casecmp\?|\.casecmp\(' "$dir" --include='*.rb' || true
done
echo "== stock apps =="
grep -RInE 'casecmp\?|\.casecmp\(' lab/build/rails-stock-app/app \
  lab/build/rails-stock-app/config lab/repro/ruby2shell-stock-baseline.ru \
  --include='*.rb' --include='*.ru' 2>/dev/null || true
