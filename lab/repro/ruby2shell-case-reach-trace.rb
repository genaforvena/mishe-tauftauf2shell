# frozen_string_literal: true
# Loaded with RUBYOPT=-r... into an unmodified stock Sinatra/Rails lab server.
# Observability only: logs String case-conversion receivers that could carry the
# CVE-2026-132825 single-byte expansion trigger (0xDF in a 1-byte encoding,
# UTF-8 "ß", or a wide encoding), plus a live-hook counter. No request-path
# middleware, no memory writes, no application changes. Loopback only.

module CaseReachTrace
  LOG = ENV.fetch("CASE_REACH_LOG", "/tmp/case-reach.log")
  MUTEX = Mutex.new
  METHODS = %i[upcase downcase swapcase casecmp? upcase! downcase! swapcase!].freeze
  WIDE = %w[UTF-16LE UTF-16BE UTF-32LE UTF-32BE UTF-16 UTF-32].freeze
  COUNT = Class.new do
    attr_reader :value
    def initialize = @value = 0
    def inc = MUTEX.synchronize { @value += 1 }
  end.new

  def self.suspect?(str)
    return false unless str.is_a?(String)

    enc = str.encoding.name
    return true if WIDE.include?(enc)
    return true if str.bytes.include?(0xdf) && enc != "UTF-8"
    return true if enc == "UTF-8" && str.bytes.each_cons(2).any? { |a, b| a == 0xc3 && b == 0x9f }

    false
  rescue Exception
    false
  end

  def self.record(kind, receiver, stack, control = nil)
    if ENV["CASE_REACH_LOG_ALL"] || suspect?(receiver) || control
      bytes = receiver.is_a?(String) ? receiver.bytes.first(64).map { |b| "%02x" % b }.join : ""
      where = stack.first(3).map { |s| s.to_s.sub(%r{\A.*?/gems/}, "gems/") }.join(" | ")
      line = "pid=#{Process.pid} #{kind} enc=#{receiver.respond_to?(:encoding) ? receiver.encoding.name : receiver.class.name} " \
             "len=#{receiver.respond_to?(:bytesize) ? receiver.bytesize : -1} " \
             "suspect=#{suspect?(receiver)} bytes=#{bytes} where=#{where}"
      line += " control=#{control}" if control
      MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts line } }
    end
  rescue Exception => e # observability must not alter the request path
    MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "trace-error=#{e.class}: #{e.message}" } }
  end

  def self.boot = MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "boot pid=#{Process.pid} hook=installed" } }
end

module CaseReachTrace::Hook
  CaseReachTrace::METHODS.each do |name|
    define_method(name) do |*args, &block|
      CaseReachTrace::COUNT.inc
      CaseReachTrace.record(name, self, caller(1, 4))
      super(*args, &block)
    end
  end
end

String.prepend(CaseReachTrace::Hook)
CaseReachTrace.boot

# Positive controls: the ASCII canary proves interception of a real call; the
# synthetic record proves the classifier flags a 0xDF ISO-8859-1 receiver
# without invoking a vulnerable conversion at boot.
"CASECANARY123".upcase
CaseReachTrace.record("control", "\xdf".dup.force_encoding(Encoding::ISO_8859_1), [], "synthetic-0xdf-iso8859-1")

at_exit do
  File.open(CaseReachTrace::LOG, "a") do |f|
    f.puts "exit pid=#{Process.pid} case_calls=#{CaseReachTrace::COUNT.value}"
  end
end
