#!/usr/bin/env bash
# Canonical driver for the read-only stock-coercion survey. Records the full
# source-collector output in a gitignored evidence directory; no lab process
# is launched by this survey.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/stock-coercion-survey
mkdir -p "$EVID"
RUBY=lab/build/plain/ruby-3.4.12-plain/bin/ruby
ROOTS=(
  lab/build/plain/ruby-3.4.12-plain/lib/ruby/3.4.0
  lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0/gems
  lab/build/rails-stock-app
  lab/build/rails-stock-full-app
  lab/build/rails-params-wrapper-app
  lab/build/rails-stageb-app
)
"$RUBY" lab/repro/ruby2shell-stock-coercion-survey.rb "${ROOTS[@]}" \
  >"$EVID/out.txt" 2>"$EVID/err.txt"
rc=$?
echo "survey rc=$rc"
sed -n '1,3p' "$EVID/out.txt"
echo '--- regexp-looking index assignments ---'
grep -n 'rhs=' "$EVID/out.txt" || true
echo '--- dynamic sends of []= (expected none) ---'
grep -rEn 'send\(:\[\]=|__send__\(:\[\]=' --include='*.rb' "${ROOTS[@]}" \
  >"$EVID/dynamic-sends.txt" 2>/dev/null || true
wc -l <"$EVID/dynamic-sends.txt"
exit "$rc"
