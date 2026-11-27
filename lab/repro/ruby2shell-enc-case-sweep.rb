# frozen_string_literal: false
# W348: stock String case-map differential over the 14 single-byte encodings
# whose case_map loop guard changed in the 3.4.12 -> 3.4.13 fix series.
# No harness-defined coercion objects: every arm is a plain Ruby String call.
require "digest"

enc_name, op, count = ARGV
abort "ENC arm=none" unless enc_name && op && count

ENCODINGS = %w[
  ISO-8859-1 ISO-8859-2 ISO-8859-3 ISO-8859-4 ISO-8859-9 ISO-8859-10
  ISO-8859-13 ISO-8859-14 ISO-8859-15 ISO-8859-16
  Windows-1250 Windows-1252 Windows-1254 Windows-1257
].freeze
abort "ENC enc=unknown:#{enc_name}" unless ENCODINGS.include?(enc_name)

begin
  s = ("\xDF".b * count.to_i).force_encoding(Encoding.find(enc_name))
  r = case op
      when "upcase" then s.upcase
      when "fold" then s.downcase(:fold)
      when "swapcase" then s.swapcase
      else abort "ENC op=unknown:#{op}"
      end
  puts "ENC enc=#{enc_name} op=#{op} n=#{count} len=#{r.bytesize} " \
       "sha=#{Digest::SHA256.hexdigest(r.b)} tail=#{r.bytes.last(8).pack("C*").unpack1("H*")}"
rescue => e
  puts "ENC enc=#{enc_name} op=#{op} n=#{count} ERR=#{e.class}:#{e.message}"
end
