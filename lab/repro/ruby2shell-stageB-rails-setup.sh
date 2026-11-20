#!/bin/bash
# Stage B over HTTP — Rails app provisioning + configuration. Loopback only.
#
# Provisions (lab provisioning standing approval #5, versions recorded on
# the wall): `bin/gem install rails --no-document` into the plain 3.4.12
# build's GEM_HOME, plus `bundle install` of the generated Gemfile
# (incl. webrick as the server handler — same handler as the verified
# Sinatra repro; puma stays in the Gemfile untouched).
#
# Generates lab/build/rails-stageb-app from scratch on every run (the
# app tree is fully derived from this script; it is gitignored):
#   `rails new --minimal --skip-bundle --skip-git`
#   lib/stageb/stageb_middleware.rb <- copy of
#       lab/repro/ruby2shell-stageB-rails-middleware.rb
#   config/application.rb  <- full file below: GroomMiddleware inserted
#       BEFORE the default Rack::MethodOverride, MarkerMiddleware AFTER
#   config/routes.rb, app/controllers/trigger_controller.rb
#   Gemfile += webrick; `bin/rails db:prepare` (empty sqlite db so the
#   dev-mode CheckPending middleware passes)
#
# Ruby: lab/build/plain/ruby-3.4.12-plain (stock build, no sanitizers).
set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RBUILD="$ROOT/lab/build/plain/ruby-3.4.12-plain"
GEM="$RBUILD/bin/gem"
APP="$ROOT/lab/build/rails-stageb-app"
MW="$ROOT/lab/repro/ruby2shell-stageB-rails-middleware.rb"
export PATH="$RBUILD/bin:$PATH"

"$GEM" install rails --no-document >/dev/null   # idempotent (already provisioned)
"$GEM" list --local | grep -E '^(rails|actionpack|railties|webrick) '

mkdir -p "$ROOT/lab/build"
rm -rf "$APP"
( cd "$ROOT/lab/build" && rails new rails-stageb-app \
    --minimal --skip-bundle --skip-git --skip-test --skip-system-test \
    >/dev/null )

mkdir -p "$APP/lib/stageb"
cp "$MW" "$APP/lib/stageb/stageb_middleware.rb"

cat >> "$APP/Gemfile" <<'EOF'

# Stage B repro server handler (same WEBrick as the Sinatra repro).
gem "webrick"
EOF

cat > "$APP/config/application.rb" <<'RB'
require_relative "boot"

require "rails"
# Pick the frameworks you want:
require "active_model/railtie"
# require "active_job/railtie"
require "active_record/railtie"
# require "active_storage/engine"
require "action_controller/railtie"
# require "action_mailer/railtie"
# require "action_mailbox/engine"
# require "action_text/engine"
require "action_view/railtie"
# require "action_cable/engine"
# require "rails/test_unit/railtie"

# Require the gems listed in Gemfile, including any gems
# you've limited to :test, :development, or :production.
Bundler.require(*Rails.groups)

# Stage B groom/marker pair (NOT autoloaded — held by the middleware
# stack, which resolves the constants once at boot).
require_relative "../lib/stageb/stageb_middleware"

module RailsStagebApp
  class Application < Rails::Application
    # Initialize configuration defaults for originally generated Rails version.
    config.load_defaults 8.1

    # lib/stageb is required explicitly above, keep it out of Zeitwerk.
    config.autoload_lib(ignore: %w[assets tasks stageb])

    # Don't generate system test files.
    config.generators.system_tests = nil

    # Stage B: groom runs BEFORE the default Rack::MethodOverride (which
    # performs the vulnerable upcase); the marker alloc runs immediately
    # AFTER it — first 0x450-class malloc after the upcase bins
    # inflated V. Both are lab scaffolding around the DEFAULT stack;
    # the trigger needs no app code.
    config.middleware.insert_before Rack::MethodOverride, GroomMiddleware
    config.middleware.insert_after Rack::MethodOverride, MarkerMiddleware
  end
end
RB

cat > "$APP/config/routes.rb" <<'RB'
Rails.application.routes.draw do
  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  get "up" => "rails/health#show", as: :rails_health_check

  root "trigger#mark"
  post "/trigger", to: "trigger#trigger"
  get "/mark", to: "trigger#mark"
end
RB

mkdir -p "$APP/app/controllers"
cat > "$APP/app/controllers/trigger_controller.rb" <<'RB'
class TriggerController < ApplicationController
  # Route bodies are no-ops on the attack path: the overflow happens in
  # Rack::MethodOverride, the marker take in MarkerMiddleware — both
  # before this controller is reached. The readback in $stageb was
  # captured over the LIVE W object.
  def trigger
    render plain: "triggered control=#{$stageb[:control]} W-readback-hex=#{$stageb[:readback]}\n"
  end

  def mark
    render plain: "W-readback-hex=#{$stageb[:readback]}\n"
  end
end
RB

( cd "$APP" && bundle install --quiet && bin/rails db:prepare )

echo "OK: $APP configured (groom before, marker after Rack::MethodOverride)"
( cd "$APP" && bin/rails middleware | grep -n -B1 -A1 GroomMiddleware )
