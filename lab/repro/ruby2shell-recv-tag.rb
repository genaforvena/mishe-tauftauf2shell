# W366: receiver-side encoding-tag sweep for String#casecmp? (CVE-2026-132825).
# str_casecmp_p (string.c:4369-4377) gates on rb_enc_compatible, then folds each
# operand with its own encoding. enc_compatible_latter (encoding.c:1069-1128)
# returns the partner encoding whenever the receiver is 7-bit and
# ASCII-compatible, independent of the receiver's tag; a non-7-bit receiver
# with a non-7-bit argument fails compatibility and returns nil.
#
# The argument is always a 7-bit prefix plus N ISO-8859-1 0xDF bytes, which
# folds 0xDF -> "ss" through the one-byte case_map overflow. Only the receiver
# shape varies:
#
#   ascii_recv          ASCII-8BIT 7-bit receiver (W365 positive control)
#   usascii_recv        US-ASCII 7-bit receiver
#   utf8_7bit_recv      UTF-8 7-bit receiver
#   utf8_nonascii_recv  UTF-8 receiver with U+00E9 (non-7-bit)
#   latin_nonascii_recv ISO-8859-1 receiver with 0xE9 (non-7-bit)
#
# Run: lab/build/plain/ruby-3.4.12-plain/bin/ruby <this> 27 usascii_recv
n = (ARGV[0] || 27).to_i
mode = ARGV[1] || 'ascii_recv'

receiver = case mode
           when 'ascii_recv'          then ("a" + "s" * 54).b
           when 'usascii_recv'        then ("a" + "s" * 54).force_encoding(Encoding::US_ASCII)
           when 'utf8_7bit_recv'      then ("a" + "s" * 54).force_encoding(Encoding::UTF_8)
           when 'utf8_nonascii_recv'  then ("\xC3\xA9".b + "s" * 54).force_encoding(Encoding::UTF_8)
           when 'latin_nonascii_recv' then ("\xE9".b + "s" * 54).force_encoding(Encoding::ISO_8859_1)
           else abort "unknown mode #{mode}"
           end
arg = ("a".b + "\xDF".b * n).force_encoding(Encoding::ISO_8859_1)

begin
  result = receiver.casecmp?(arg).inspect
rescue => e
  result = "error:#{e.class}:#{e.message}"
end
print "N=#{n} mode=#{mode} enc1=#{receiver.encoding} valid1=#{receiver.valid_encoding? ? 'v' : '?'} "
print "len1=#{receiver.bytesize} enc2=#{arg.encoding} len2=#{arg.bytesize} result=#{result}\n"
