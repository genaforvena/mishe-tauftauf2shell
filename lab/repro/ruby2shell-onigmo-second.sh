#!/bin/sh
# Repeat-ID corruption across two requests on one keep-alive Puma worker.
# Labeled conditions: stock Rails /rails/info/notes, 3.4.11 plain, threads=2,
# shallow layout, ASLR off. No instrumentation in the request path.
# Evidence is gitignored under lab/build/evidence/w300-*.
set -eu
cd "$(dirname "$0")/../.."
export RUBY2SHELL_ONIGMO_GEM_PATH=lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0
export RUBY2SHELL_ONIGMO_LAYOUT=shallow
export RUBY2SHELL_ONIGMO_ASLR_OFF=1
export RAILS_MAX_THREADS=2
EV=lab/build/evidence
mkdir -p "$EV"

summary() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(sys.argv[1], "status", d.get("http_status"), "bytes", d.get("response_bytes"), "sha", str(d.get("response_sha256"))[:12], "second", d.get("second_http_status"), d.get("second_response_bytes"), str(d.get("second_response_sha256"))[:12], "health", d.get("health"), "exit", d.get("exit_after_request"), "error", d.get("request_error"))' "$EV/$1.json"
}

run() {
  tag=$1 mode=$2 port=$3
  shift 3
  env RUBY2SHELL_ONIGMO_PORT="$port" "$@" \
    python3 lab/repro/ruby2shell-onigmo-repeat-wire.py "$mode" "$tag" || true
  summary "$tag"
}

ATTACK2='RUBY2SHELL_ONIGMO_SECOND=1'
REPEAT2="$ATTACK2 RUBY2SHELL_ONIGMO_SECOND_REFLECT=1 RUBY2SHELL_ONIGMO_SECOND_UNITS=32767"

run w300-ctrl control 4801
run w300-atk1 attack 4802 "$ATTACK2"
# shellcheck disable=SC2086
run w300-atk2 attack 4803 $REPEAT2
# shellcheck disable=SC2086
run w300-atk3 attack 4804 $REPEAT2
# shellcheck disable=SC2086
run w300-safe safe 4805 $REPEAT2
# shellcheck disable=SC2086
run w300-fixed fixed 4806 $REPEAT2

for tag in w300-atk1 w300-atk2 w300-atk3 w300-safe w300-fixed; do
  for page in html second.html; do
    if [ "$tag" = w300-safe ] && [ "$page" = html ]; then continue; fi
    if [ "$tag" = w300-fixed ] && [ "$page" = html ]; then continue; fi
    out="$EV/$tag.${page%.html}.diff.json"
    python3 lab/repro/ruby2shell-onigmo-response.py \
      "$EV/w300-ctrl.html" "$EV/$tag.$page" --json "$out" || true
  done
done
