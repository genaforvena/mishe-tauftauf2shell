#!/usr/bin/env ruby
# Adjacent Ruby 3.4.12 lane: rb_memsearch_qs_utf8_hash (re.c:173) reads up to
# three bytes past the current byte without an end bound. The 3.4.13 fix adds
# `e` and returns early near a truncated multibyte lead. Both strings here are
# plain Ruby Strings with UTF-8 encoding; no debugger, shim or monkey patch.
#
#   ruby ruby2shell-qs-utf8.rb [pattern|haystack|safe] [length]
mode = ARGV[0] || 'pattern'
len = Integer(ARGV[1] || '200')
utf8 = Encoding::UTF_8
case mode
when 'pattern'
  needle = ('A' * 40 + "\xF0").force_encoding(utf8).dup
  hay = ('B' * len).force_encoding(utf8).dup
when 'haystack'
  needle = ('A' * 40).force_encoding(utf8).dup
  hay = ('B' * len + "\xF0").force_encoding(utf8).dup
when 'safe'
  needle = ('A' * 40).force_encoding(utf8).dup
  hay = ('B' * len).force_encoding(utf8).dup
else
  abort "unknown mode: #{mode}"
end
puts "#{mode} len=#{len} include=#{hay.include?(needle).inspect}"
