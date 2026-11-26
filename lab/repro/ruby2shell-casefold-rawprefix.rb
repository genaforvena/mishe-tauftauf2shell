#!/usr/bin/env ruby
# frozen_string_literal: true
# Analysis-only probe for the untripped OP_EXACTN_IC guard (3.4.13
# regexec.c:2844 `if (len > endp - p) goto fail;`). Each pair has a shared raw
# UTF-8 first byte, but the subject's case-fold is longer than the pattern's.
# One shape per fresh ASan process; no wire/app/marker.
$stdout.sync = true

PAIRS = {
  'p0100' => [0x0100, 0x0130],  # raw C4.. vs C4.., fold 2 vs 3
  'p017f' => [0x017f, 0x0149],  # raw C5.. vs C5.., fold 1 vs 3
  'p01c0' => [0x01c0, 0x01f0],  # raw C7.. vs C7.., fold 2 vs 3
  'p0200' => [0x0200, 0x023a],  # raw C8.. vs C8.., fold 2 vs 3
  'p0380' => [0x0380, 0x0390],  # raw CD.. vs CD.., fold 2 vs 6
  'p0580' => [0x0580, 0x0587],  # raw D5.. vs D5.., fold 2 vs 4
  'p1c80' => [0x1c80, 0x1f52],  # raw E1.. vs E1.., fold 2 vs 6
  'p212a' => [0x212a, 0x2000],  # raw E2.. vs E2.., fold 1 vs 3
  'pa78d' => [0xa78d, 0xa000],  # raw EA.. vs EA.., fold 2 vs 3
  'pfb00' => [0xfb00, 0xfb13]   # raw EF.. vs EF.., fold 2 vs 4
}.freeze

name = ARGV[0]
pattern_cp, subject_cp = PAIRS.fetch(name)
pattern = pattern_cp.chr(Encoding::UTF_8)
subject = subject_cp.chr(Encoding::UTF_8)
re = Regexp.new("\\A#{pattern}", Regexp::IGNORECASE)
match = re.match?(subject)
puts "case=#{name} ruby=#{RUBY_VERSION} match=#{match} " \
     "pattern=U+%04X subject=U+%04X " \
     "pattern_fold=#{pattern.downcase(:fold).bytesize} " \
     "subject_fold=#{subject.downcase(:fold).bytesize}" % [pattern_cp, subject_cp]
