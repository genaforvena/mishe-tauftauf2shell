# Adjacent Ruby 3.4.12 -> 3.4.13 candidate: stale match offsets after a
# user conversion callback. Stock String methods only: no monkey patch,
# debugger, tracer or wire request. Modes are selected by ARGV[0].
mode = ARGV[0]

case mode
when "write-attack", "write-safe"
  $s = "abcdef".dup
  repl = Object.new
  repl.define_singleton_method(:to_str) do
    $s.replace("X") if mode == "write-attack"
    "Y"
  end
  begin
    $s[/abc/] = repl
    puts "ok len=#{$s.bytesize} #{$s.inspect}"
  rescue => e
    puts "raised #{e.class}: #{e.message}"
  end
when "read-attack", "read-safe"
  $s = "abcdef".dup
  idx = Object.new
  idx.define_singleton_method(:to_int) do
    $s.replace("X") if mode == "read-attack"
    1
  end
  begin
    puts "result=#{$s[/(abc)(def)/, idx].inspect} len=#{$s.bytesize}"
  rescue => e
    puts "raised #{e.class}: #{e.message}"
  end
when "chomp"
  s = ("\x0a\x00".b)[1, 1].force_encoding(Encoding::UTF_16LE)
  puts "result=#{s.chomp.inspect} len=#{s.bytesize}"
else
  warn "usage: #{$PROGRAM_NAME} write-attack|write-safe|read-attack|read-safe|chomp"
  exit 2
end
