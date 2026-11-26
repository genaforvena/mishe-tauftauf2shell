#!/usr/bin/env ruby
# frozen_string_literal: true
# Analysis-only probe for the unconsumed regexec.c:1893 fix hunk
# (string_cmp_ic lacks an s2 >= text_end guard in 3.4.12).
# Usage: ruby ruby2shell-casefold-backref-ic.rb
$stdout.sync = true

CASES = [
  ["sss-then-two-long-s", "(sss)\\1",      "ss\u017f\u017f"],
  ["ssss-then-three-long-s", "(ssss)\\1",  "ssss\u017f\u017f\u017f"],
  ["s-then-long-s",   "(s)\\1",         "s\u017f"],
  ["ss-then-dotted",  "(ss)\\1",        "ss\u0130"],
  ["ss-then-cap-sharp", "(ss)\\1",      "ss\u1e9e"],
  ["s-then-sharp",    "(s)\\1",         "s\u00df"],
  ["ascii-control",   "(ss)\\1",        "ssss"],
  ["miss-control",    "(ss)\\1",        "ssx"]
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
