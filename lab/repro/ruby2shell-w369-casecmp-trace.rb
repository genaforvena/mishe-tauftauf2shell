# frozen_string_literal: true
# W369 observability-only preload for unmodified stock Sinatra/Rails lab apps.
# Logs BOTH operands of every String#casecmp? / String#casecmp call, with
# encoding, length, leading bytes and sharp-s parity, so a request path with
# two wire-controlled odd-count operands would be visible. No request-path
# middleware, no memory writes, no application changes. Loopback only.
#
# RUBYOPT=-r<this file> CASE_PAIR_LOG=<path> <stock app>
# CASE_PAIR_CONTROL=0 disables the boot control (used for valgrind arms).

module CasePairTrace
  LOG = ENV.fetch("CASE_PAIR_LOG", "/tmp/case-pair.log")
  MUTEX = Mutex.new
  COUNT = Class.new do
    attr_reader :value
    def initialize = @value = 0
    def inc = MUTEX.synchronize { @value += 1 }
  end.new

  def self.desc(value)
    return "nil" if value.nil?
    return "#{value.class}" unless value.is_a?(String)

    bytes = value.bytes
    formatted = bytes.first(48).map { |b| "%02x" % b }.join
    "%s len=%d prefix=%s sharp_s=%d odd=%s" % [
      value.encoding.name, bytes.length, formatted,
      bytes.count(0xdf), bytes.count(0xdf).odd?
    ]
  end

  def self.suspect?(value)
    return false unless value.is_a?(String)
    return false if value.encoding == Encoding::UTF_8

    value.bytes.include?(0xdf) || %w[UTF-16LE UTF-16BE UTF-32LE UTF-32BE].include?(value.encoding.name)
  rescue Exception
    false
  end

  def self.record(kind, receiver, arg, stack)
    COUNT.inc
    where = stack.first(4).map { |s| s.to_s.sub(%r{\A.*?/gems/}, "gems/") }.join(" | ")
    line = "pid=#{Process.pid} #{kind} recv[#{desc(receiver)}] arg[#{desc(arg)}] " \
           "recv_suspect=#{suspect?(receiver)} arg_suspect=#{suspect?(arg)} where=#{where}"
    MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts line } }
  rescue Exception => e
    MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "trace-error=#{e.class}: #{e.message}" } }
  end

  def self.boot = MUTEX.synchronize { File.open(LOG, "a") { |f| f.puts "boot pid=#{Process.pid} hook=installed" } }
end

module CasePairTrace::Hook
  def casecmp?(other)
    CasePairTrace.record("casecmp?", self, other, caller(1, 4))
    super
  end

  def casecmp(other)
    CasePairTrace.record("casecmp", self, other, caller(1, 4))
    super
  end
end

String.prepend(CasePairTrace::Hook)
CasePairTrace.boot

# Hook-liveness control: a real casecmp? with two odd sharp-s operands. It runs
# only at boot in observability mode, never in a valgrind arm and never on wire.
if ENV.fetch("CASE_PAIR_CONTROL", "1") != "0"
  left = ("a" + "\xdf" * 21).dup.force_encoding(Encoding::ISO_8859_1)
  right = ("a" + "\xdf" * 23).dup.force_encoding(Encoding::ISO_8859_1)
  left.casecmp?(right)
end

at_exit do
  File.open(CasePairTrace::LOG, "a") do |f|
    f.puts "exit pid=#{Process.pid} cmp_calls=#{CasePairTrace::COUNT.value}"
  end
end
