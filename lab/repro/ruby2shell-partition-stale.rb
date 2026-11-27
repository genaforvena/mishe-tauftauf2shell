# W334: adjacent stale tail bound in String#rpartition (Ruby 3.4.12).
# The 3.4.13 guard is `long rpos = pos + RSTRING_LEN(sep); if (rpos > RSTRING_LEN(str)) goto failed;`
# (string.c:11127-11131). Without it, a UTF-16LE receiver whose last character
# is matched with a separator one code unit longer yields a negative tail
# length passed to memcpy in str_subseq (string.c:3045).
# Local script execution only; no network, no debugger write.
arm = ENV.fetch("W334_ARM", "rp_n1")

case arm
when /\Arp_n(\d+)\z/
  n = Regexp.last_match(1).to_i
  str = ("A" * n).force_encoding(Encoding::UTF_16LE)
  sep = ("A\x00" * n).force_encoding(Encoding::UTF_16LE)
  p str.rpartition(sep)
when "rp_gen"
  k = Integer(ENV.fetch("W334_K", "0"))
  str = ("A\x00" * k + "A").force_encoding(Encoding::UTF_16LE)
  sep = ("A\x00" * (k + 1)).force_encoding(Encoding::UTF_16LE)
  STDERR.write("str=#{str.bytesize} sep=#{sep.bytesize} ")
  p str.rpartition(sep)
when /\Ap_n(\d+)\z/
  n = Regexp.last_match(1).to_i
  str = ("A" * n).force_encoding(Encoding::UTF_16LE)
  sep = ("A\x00" * n).force_encoding(Encoding::UTF_16LE)
  p str.partition(sep)
when "rp_to_str"
  str = ("h\xc3\xa9llo" * 1000).force_encoding(Encoding::UTF_8)
  obj = Object.new
  obj.define_singleton_method(:to_str) do
    str.replace("h\xc3\xa9".force_encoding(Encoding::UTF_8))
    "-"
  end
  p str.rpartition(obj)
when "rp_ascii"
  p "foo-bar".rpartition("-")
else
  abort "unknown W334_ARM #{arm}"
end
