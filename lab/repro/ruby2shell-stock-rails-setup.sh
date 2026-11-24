#!/bin/bash
# Provision an unmodified `rails new --minimal` application, or a full
# `rails new` application with RUBY2SHELL_STOCK_RAILS_FULL=1. The driver binds
# loopback; no application file is edited after generation.
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RBUILD="$ROOT/lab/build/plain/ruby-3.4.12-plain"
if [ "${RUBY2SHELL_STOCK_RAILS_FULL:-0}" = 1 ]; then
  APP="${RUBY2SHELL_STOCK_APP_PATH:-$ROOT/lab/build/rails-stock-full-app}"
else
  APP="${RUBY2SHELL_STOCK_APP_PATH:-$ROOT/lab/build/rails-stock-app}"
fi
export PATH="$RBUILD/bin:$PATH"
export GEM_PATH="$RBUILD/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"

if [ -e "$APP" ]; then
  echo "refusing to overwrite existing $APP" >&2
  exit 1
fi

RAILS_OPTIONS=(--skip-bundle --skip-git)
if [ "${RUBY2SHELL_STOCK_RAILS_FULL:-0}" != 1 ]; then
  RAILS_OPTIONS+=(--minimal --skip-test --skip-system-test)
fi
rails new "$APP" "${RAILS_OPTIONS[@]}"
(
  cd "$APP"
  bundle install --local
  bin/rails db:prepare
)

# No controller, route, middleware, ObjectSpace, maps read, tracer, or marker
# hook is added. The generated development 404 page reflects request params.
grep -n 'Rack::MethodOverride' <(cd "$APP" && bin/rails middleware)
