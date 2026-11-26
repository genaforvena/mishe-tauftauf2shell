#!/usr/bin/env ruby
# frozen_string_literal: true
# UTF-8 shape of the Onigmo case-insensitive optimizer OOB read
# (regexec.c:4278 str_lower_case_match, fixed in 3.4.13 by the
# `if (tend - t < lowlen) return 0;` guard at regexec.c:4298).
#
# The compiled regexp's optimized exact string is one byte ("s" / "i").
# A subject whose full case fold is longer (U+00DF -> "ss", U+1E9E -> "SS",
# U+0130 -> "i" + combining dot) makes the comparison walk past that
# one-byte buffer. Run one case per process: affected ASan builds abort.
CASES = {
  "sharp-s" => ["s", "\u00df"],
  "sharp-cap" => ["s", "\u1e9e"],
  "dotted-i" => ["i", "\u0130"],
  "ascii-match" => ["s", "S"],
  "ascii-miss" => ["s", "t"]
}.freeze

name = ARGV[0] or abort "usage: #{$PROGRAM_NAME} sharp-s|sharp-cap|dotted-i|ascii-match|ascii-miss"
src, subject = CASES.fetch(name)
match = Regexp.new(src, Regexp::IGNORECASE).match(subject)
puts("case=#{name} match=#{!match.nil?}")
