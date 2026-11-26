#!/usr/bin/env ruby
# frozen_string_literal: true
# Usage: ruby ruby2shell-casefold-splitprime-tight.rb SO BIGLEN FRONTLEN [COUNT]
require ARGV.fetch(0)
biglen   = Integer(ARGV.fetch(1))
frontlen = Integer(ARGV.fetch(2))
count    = Integer(ARGV.fetch(3) || "1")

CASES = [
  ["FB00", 0x66, 0xfb00, 0x66],
  ["FB01", 0x66, 0xfb01, 0x69],
  ["FB02", 0x66, 0xfb02, 0x6c],
  ["FB03", 0x66, 0xfb03, 0x66],
  ["00DF", 0x73, 0x00df, 0x73],
  ["1E9E", 0x73, 0x1e9e, 0x73],
  ["FB05", 0x73, 0xfb05, 0x74],
  ["FB06", 0x73, 0xfb06, 0x74]
].freeze

count.times do
  CASES.each do |name, needle, cp, fold2|
    match = Ruby2ShellCasefoldSplitprimeTight.try(fold2, biglen, frontlen, needle, cp)
    puts "ruby=#{RUBY_VERSION} big=#{biglen} front=#{frontlen} case=#{name} prime=%02x match=%s" %
         [fold2, match]
  end
end
