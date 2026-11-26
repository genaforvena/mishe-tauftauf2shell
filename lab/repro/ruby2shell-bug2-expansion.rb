#!/usr/bin/env ruby
# GHSA-87fm-7w84-j2px reopen-condition check.
#
# The Bug 2 int-wrap needs ~2^32 output bytes. Peak mapping-buffer memory is
# inversely related to the input's byte-expansion ratio, so a codepoint with
# >3:1 output/input could fit the wrap under a 2 GiB cgroup where U+0390
# (2 B -> 6 B, 3:1) cannot. This script measures the maximum byte-expansion
# ratio of String#upcase over every Unicode scalar value, using the real
# affected build's case-mapping tables rather than a source-table parse.
#
# Usage: RUBY script.rb [op]   (op = upcase | downcase | swapcase; default upcase)
$stdout.sync = true
op = (ARGV.fetch(0, "upcase")).to_sym
abort "unsupported op: #{op}" unless [:upcase, :downcase, :swapcase].include?(op)

max_ratio = 0.0
max_cps = []
checked = 0
0x0000.upto(0x10ffff) do |cp|
  next if cp >= 0xd800 && cp <= 0xdfff
  s = begin
    cp.chr(Encoding::UTF_8)
  rescue ArgumentError, RangeError
    next
  end
  checked += 1
  out = s.public_send(op)
  next if out.bytesize <= s.bytesize
  r = out.bytesize.to_f / s.bytesize
  if r > max_ratio + 1e-9
    max_ratio = r
    max_cps = [cp]
  elsif (r - max_ratio).abs <= 1e-9
    max_cps << cp
  end
end

puts "op=#{op} checked=#{checked} max_byte_expansion=#{format('%.6f', max_ratio)}"
puts "achievers=#{max_cps.first(16).map { |c| format('U+%04X', c) }.join(' ')}" \
     + (max_cps.size > 16 ? " (+#{max_cps.size - 16} more)" : "")
puts "verdict=#{max_ratio > 3.0 ? 'GT3_RATIO_EXISTS' : 'NO_RATIO_GT3'}"
