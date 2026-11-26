#!/usr/bin/env ruby
# frozen_string_literal: true
# Analysis-only probe for the 3.4.13 compile-time Onigmo guards that the
# case-fold match-time lanes never exercise:
#   regparse.c:1569 check_code_point (call sites 6329/6389),
#   regparse.c:4043 invalid group-name error string,
#   regparse.c:4779 precise multi-byte length for numeric escapes,
#   regparse.c:6595 parse depth,
#   regcomp.c:3426 update_string_node_case_fold,
#   regcomp.c:3507 expand_case_fold_string_alt.
# One shape per fresh ASan process; no wire/app/marker.
$stdout.sync = true

LATIN1 = Encoding::ISO_8859_1

CASES = [
  ['cp-too-big-x',        '\x{110000}',     Encoding::UTF_8],
  ['cp-too-big-u',        '\u{110000}',     Encoding::UTF_8],
  ['cp-surrogate',        '\x{d800}',       Encoding::UTF_8],
  ['cp-max-valid',        '\x{10ffff}',     Encoding::UTF_8],
  ['cp-above-bmp-fold',   '(?i:\x{1e9e})',  Encoding::UTF_8],
  ['hex-cont',            '\x80',           Encoding::UTF_8],
  ['hex-overlong',        '\xc0\x80',       Encoding::UTF_8],
  ['hex-out-of-range',    '\xf5\x80\x80\x80', Encoding::UTF_8],
  ['hex-latin1-fold',     '(?i:\xff)',      LATIN1],
  ['hex-latin1-sharp',    '(?i:\xdf)',      LATIN1],
  ['fold-sharp-latin1',   'ß',              LATIN1],
  ['fold-sharp-utf8',     'ß',              Encoding::UTF_8],
  ['fold-cap-sharp',      'ẞ',              Encoding::UTF_8],
  ['fold-ligature',       'ﬀ',              Encoding::UTF_8],
  ['raw-u16-unpaired-hi', "\x00\xd8".b, Encoding::UTF_16LE],
  ['raw-u16-unpaired-lo', "\x00\xdc".b, Encoding::UTF_16LE],
  ['raw-u32-unpaired-hi', "\x00\x00\xd8\x00".b, Encoding::UTF_32LE],
  ['raw-u16-valid-pair',  "\x00\xd8\x00\xdc".b, Encoding::UTF_16LE],
  ['fold-iota',           'ΐ',              Encoding::UTF_8],
  ['fold-alt-latin1',     '(?i:ß|x)',       LATIN1],
  ['fold-alt-utf8',       '(?i:ﬀ|s)',      Encoding::UTF_8],
  ['group-name-bad',      '(?<\R>x)',       Encoding::UTF_8],
  ['group-name-call',     '(?<n>a)\k<n>',   Encoding::UTF_8],
  ['nest-2000',           '(?:' * 2000 + 'a' + ')' * 2000, Encoding::UTF_8],
  ['nest-4000',           '(?:' * 4000 + 'a' + ')' * 4000, Encoding::UTF_8],
  ['nest-quant-2000',     '(?:a)' + '?' * 2000, Encoding::UTF_8],
  ['fold-invalid-latin1', '(?i:ß\u0000)',   LATIN1]
].freeze

selected = ARGV[0]
CASES.each do |name, source, enc|
  next if selected && name != selected
  begin
    str = source.dup.force_encoding(enc)
    re = Regexp.new(str, Regexp::IGNORECASE)
    puts "case=#{name} ruby=#{RUBY_VERSION} enc=#{enc} compiled=#{re.source.bytesize}"
  rescue StandardError => e
    puts "case=#{name} ruby=#{RUBY_VERSION} enc=#{enc} error=#{e.class}"
  end
end
