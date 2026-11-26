# frozen_string_literal: true
# Loaded with RUBYOPT=-r... into a stock Sinatra/Rails lab server.
# Observability only: logs every Regexp.new/compile whose pattern string has a
# wide encoding, plus a live-hook counter so a zero-hit result is meaningful.
# No request-path middleware, no memory writes, no instrumentation of the
# application's logic. Never contacts anything but the loopback server.

module WpqwReachTrace
  WIDE = %w[UTF-16LE UTF-16BE UTF-32LE UTF-32BE UTF-16 UTF-32].freeze
  LOG = ENV.fetch("WPQW_REACH_LOG", "/tmp/wpqw-reach.log")
  MUTEX = Mutex.new
  CALLS = Counter = Class.new do
    attr_reader :value
    def initialize = @value = 0
    def inc = MUTEX.synchronize { @value += 1 }
  end.new

  def self.record(kind, pattern, options, stack)
    enc = pattern.is_a?(String) ? pattern.encoding.name : pattern.class.name
    if ENV["WPQW_REACH_LOG_ALL"] && pattern.is_a?(String)
      bytes = pattern.bytes.first(128).map { |b| "%02x" % b }.join
      MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "all #{kind} enc=#{enc} opts=#{options.inspect} bytes=#{bytes}" } }
    end
    return unless WIDE.include?(enc)

    bytes = pattern.is_a?(String) ? pattern.bytes.first(96).map { |b| "%02x" % b }.join : ""
    where = stack.first(2).map { |s| s.to_s.sub(%r{\A.*?/gems/}, "gems/") }.join(" | ")
    line = "pid=#{Process.pid} #{kind} enc=#{enc} len=#{pattern.bytesize} " \
           "opts=#{options.inspect} bytes=#{bytes} where=#{where}"
    MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts line } }
  rescue Exception => e # observability must not alter the request path
    MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "trace-error=#{e.class}: #{e.message}" } }
  end

  def self.boot = MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "boot pid=#{Process.pid} hook=installed" } }
end

module WpqwReachTrace::Hook
  def new(pattern, *rest)
    WpqwReachTrace::CALLS.inc
    WpqwReachTrace.record("new", pattern, rest.first, caller(1, 3))
    super
  end

  def compile(pattern, *rest)
    WpqwReachTrace::CALLS.inc
    WpqwReachTrace.record("compile", pattern, rest.first, caller(1, 3))
    super
  end
end

module WpqwReachTrace::BlankHook
  def blank?
    if WpqwReachTrace::WIDE.include?(encoding.name)
      line = "pid=#{Process.pid} blank-enc=#{encoding.name} len=#{bytesize} " \
             "where=#{caller(1, 2).first(2).map(&:to_s).join(' | ')}"
      File.open(WpqwReachTrace::LOG, "a") { |f| f.puts line }
    end
    super
  end
end

String.prepend(WpqwReachTrace::BlankHook)
Regexp.singleton_class.prepend(WpqwReachTrace::Hook)
WpqwReachTrace.boot

at_exit do
  File.open(WpqwReachTrace::LOG, "a") do |f|
    f.puts "exit pid=#{Process.pid} regexp_calls=#{WpqwReachTrace::CALLS.value}"
  end
end
