#!/usr/bin/env ruby
# frozen_string_literal: true
# Analysis-only probe for the remaining 3.4.12 regexec.c case-fold guards:
# OP_EXACT1_IC (fixed 3.4.13 regexec.c:2751 `len != enclen(...)`) and
# OP_EXACTN_IC (fixed 3.4.13 regexec.c:2844 `len > endp - p`).
# Anchored shapes bypass the reg->exact slow search whose 4278 over-read is
# already documented. One shape per fresh ASan process; no wire/app/marker.
$stdout.sync = true

SHARP = "\u00df"      # folds to "ss"
CAP_SHARP = "\u1e9e"  # folds to "ss"
FFI = "\uFB03"        # folds to "ffi"
IOTA_DIA = "\u0390"   # folds to iota + diaeresis + acute (6 UTF-8 bytes)
LONG_S = "\u017f"     # folds to "s" (one byte), control

CASES = [
  ["a1-sharp",      '\As',                   SHARP],
  ["a1-capsharp",   '\As',                   CAP_SHARP],
  ["a1-ffi",        '\Af',                   FFI],
  ["a1-iota-dia",   '\Ai',                   IOTA_DIA],
  ["a1-long-s",     '\As',                   LONG_S],
  ["an-ss-sharp",   '\Ass',                  SHARP],
  ["an-3-sharp",    '\Asss',                 "s#{SHARP}"],
  ["an-iota-dia",   '\Ass',                  IOTA_DIA],
  ["an-ffi",        '\Aff',                  FFI],
  ["noanchor-sharp", 's',                    SHARP],
  ["an-foldlit-sharp",  '\A' + SHARP,             SHARP],
  ["an-foldlit-greek",  '\A' + SHARP,             IOTA_DIA],
  ["an-foldlit-ffi",    '\A' + FFI,               IOTA_DIA],
  ["lookbehind",       '(?<=a)s',                 "a#{SHARP}"],
  ["an-dot-foldlit-greek", '\A.' + SHARP,         'a' + IOTA_DIA],
  ["an-dot-s-greek",       '\A.' + SHARP,      's' + IOTA_DIA],
  ["an-2dot-ss-greek",  '\A..' + SHARP,        'ss' + IOTA_DIA],
  ["alt",           '\A(?:s|t)',             SHARP],
  ["a1-tail115",    '\As' + ('a' * 115),     SHARP + ('a' * 115)],
  ["a1-tail116",    '\As' + ('a' * 116),     SHARP + ('a' * 116)]
].freeze

selected = ARGV[0]
CASES.each do |name, source, subject|
  next if selected && name != selected
  begin
    re = Regexp.new(source, Regexp::IGNORECASE)
    result = re.match?(subject.encode(Encoding::UTF_8))
    puts "case=#{name} ruby=#{RUBY_VERSION} match=#{result}"
  rescue StandardError => e
    puts "case=#{name} ruby=#{RUBY_VERSION} error=#{e.class}"
  end
end
