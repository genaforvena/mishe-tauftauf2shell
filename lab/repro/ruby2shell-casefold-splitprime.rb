#!/usr/bin/env ruby
# frozen_string_literal: true
# Usage: ruby ruby2shell-casefold-splitprime.rb SO BIGLEN FRONTLEN [COUNT]
# For each fold candidate: fill a large freed chunk with the fold's second
# byte, split it, compile the one-byte-exact /needle/i and report match?.
require ARGV.fetch(0)
biglen   = Integer(ARGV.fetch(1))
frontlen = Integer(ARGV.fetch(2))
count    = Integer(ARGV.fetch(3) || "1")

# [name, needle byte, codepoint, fold's 2nd byte]
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

count.times do
  CASES.each do |name, needle, cp, fold2|
    Ruby2ShellCasefoldSplitprime.prepare(fold2, biglen, frontlen)
    match = Regexp.new(needle.chr, Regexp::IGNORECASE).match?(cp.chr(Encoding::UTF_8))
    puts "ruby=#{RUBY_VERSION} big=#{biglen} front=#{frontlen} case=#{name} prime=%02x match=%s" %
         [fold2, match]
  end
end
