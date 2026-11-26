# frozen_string_literal: true
# One case per process: an ASan report aborts the interpreter.
# Usage: ruby case-reach-asan.rb METHOD ENCODING N [SHAPE]
#   METHOD = upcase | downcase | downcase!
#   ENCODING = ASCII-8BIT | ISO-8859-1 | UTF-8
#   SHAPE = plain | ctype | host (wire-shaped receivers from the stock survey)
mode, enc_name, count, shape = ARGV
count = count.to_i
source = case shape
         when "ctype" then "text/\xdf/plain".dup
         when "host" then "127.0.0.1, foo\xdf.example".dup
         else enc_name == "UTF-8" ? ("ß" * count).dup : ("\xdf" * count).dup
         end
source.force_encoding(enc_name)
result = source.public_send(mode) || source
head = result.bytes.first(8).map { |b| "%02x" % b }.join
puts "mode=#{mode} enc=#{source.encoding.name} shape=#{shape} in=#{source.bytesize} out=#{result.bytesize} head=#{head}"
