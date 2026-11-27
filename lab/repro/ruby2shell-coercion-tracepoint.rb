# W323: dynamic test of the W322 static coercion-closure result.
#
# Observes every Ruby-visible String#[]= call in a live stock Sinatra/Rack or
# `rails new` process, including metaprogramming and C rb_funcall callers that
# Ripper source grep cannot see. TracePoint(:c_call) alone cannot expose C-frame
# arguments (tp.binding is nil on this build), so a prepended module captures
# the argument vector and super reaches the stock C implementation. A
# TracePoint cross-check counts C-method entries after super.
#
# LIMITATION: direct C calls to rb_str_aset/rb_str_subpat_set that bypass the
# Ruby method table are invisible here; W322 enumerated those statically
# (string.c:5874/5936 and date_parse.c:333).
#
# Loopback only. No vulnerability trigger, no harness markers, no debugger.
# Can be run as the Sinatra test app, or preloaded into a stock Rails app with
# RUBYOPT=-r<this file>.
LOG = ENV.fetch('RUBY2SHELL_TP_LOG')
EVIDENCE_ROOT = File.expand_path('../build/evidence', __dir__) + '/'
raise 'log must be under lab/build/evidence' unless LOG.start_with?(EVIDENCE_ROOT)

$tp_aset_calls = 0
$aset_calls = 0
$regexp_keys = 0
$nonstring_rhs = 0
$hits = 0
$log_io = File.open(LOG, 'a')
$log_io.sync = true

module CoercionObserver
  def []=(*args)
    key = args[0]
    rhs = args[-1]
    $aset_calls += 1
    regexp_key = key.is_a?(Regexp)
    $regexp_keys += 1 if regexp_key
    nonstring_rhs = !rhs.is_a?(String)
    $nonstring_rhs += 1 if nonstring_rhs
    if regexp_key && nonstring_rhs
      $hits += 1
      here = caller_locations(2, 1).first
      $log_io.puts("HIT regexp-key non-string-rhs key=#{key.inspect[0, 200]} " \
                   "rhsclass=#{rhs.class} recclass=#{self.class} " \
                   "where=#{here}:#{here.lineno}")
    end
    super
  end
end

String.prepend(CoercionObserver)

$aset_tp = TracePoint.new(:c_call) do |tp|
  $tp_aset_calls += 1 if tp.method_id == :[]= && tp.defined_class == String
end
$aset_tp.enable

at_exit do
  $aset_tp.disable
  $log_io.puts("SUMMARY aset=#{$aset_calls} c_entries=#{$tp_aset_calls} " \
               "regexp_keys=#{$regexp_keys} nonstring_rhs=#{$nonstring_rhs} " \
               "hits=#{$hits}")
  $log_io.flush
  $log_io.close
end

if $PROGRAM_NAME == __FILE__
  require 'sinatra/base'

  class ObserverApp < Sinatra::Base
    set :show_exceptions, false

    get('/health') { "ok\n" }
    # Positive control: proves the observer sees Ruby-visible String#[]= calls,
    # Regexp keys, non-String replacements and C-method entries after super.
    # Never requested by the default stock-traffic driver mode.
    get('/observer-selfcheck') do
      s = 'abc'
      s[1, 1] = 'Z'
      s[/Z/] = 'Q'
      begin
        s[/c/] = 123
        "selfcheck ok\n"
      rescue TypeError => e
        "selfcheck typeerror=#{e.class}\n"
      end
    end
    get('/') { "index params=#{params.inspect}\n" }
    post('/echo') { "echo params=#{params.inspect}\n" }
    post('/trigger') do
      "trigger method=#{request.request_method} params=#{params.inspect}\n"
    end
  end

  require 'rackup/handler/webrick'
  Rackup::Handler::WEBrick.run(
    ObserverApp.new,
    Host: '127.0.0.1',
    Port: ENV.fetch('RUBY2SHELL_TP_PORT', '4551').to_i
  )
end
