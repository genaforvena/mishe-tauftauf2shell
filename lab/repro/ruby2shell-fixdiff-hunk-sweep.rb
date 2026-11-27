# frozen_string_literal: false
# W347: coercion-free differential over unexamined hunks of the pinned
# 3.4.12 -> 3.4.13 string.c fix series. No harness-defined to_str/to_int:
# every arm is reachable from plain Ruby String/IO calls.
arm = ARGV[0]
abort "SWEEP arm=none" unless arm

def summary(name, value)
  bytes = value.is_a?(String) ? value.bytes : value.to_s.bytes
  puts "SWEEP arm=#{name} len=#{value.is_a?(String) ? value.bytesize : bytes.size} " \
       "enc=#{value.is_a?(String) ? value.encoding.to_s : '-'} " \
       "tail=#{bytes.last(16).pack('C*').unpack1('H*')}"
end

def show(name)
  yield
rescue => e
  puts "SWEEP arm=#{name} ERR=#{e.class}:#{e.message}"
end

case arm
when "embed-promote"
  show(arm) do
    s = "\u3042".encode("UTF-16LE")
    s << ("X".encode("UTF-16LE") * 4100)
    summary(arm, s)
  end
when "tmp-frozen-io"
  show(arm) do
    frozen = ("\u3042" * 2100).encode("UTF-16LE").freeze
    File.open("/dev/null", "wb") { |io| io.write(frozen) }
    summary(arm, frozen)
  end
when "subseq"
  show(arm) do
    s = ("\u3042\u3044" * 2100).encode("UTF-16LE")
    a = s[0, 4]
    a << "Z".encode("UTF-16LE")
    summary(arm, a)
  end
when "succ"
  show(arm) do
    s = ("\u3042\uFFFE" * 2100).encode("UTF-16LE")
    summary(arm, s.succ)
  end
when "reverse"
  show(arm) do
    s = ("ab\u3042" * 1400).encode("UTF-16LE")
    summary(arm, s.reverse)
  end
when "split"
  show(arm) do
    s = ("a\u3042b" * 1400).encode("UTF-16LE")
    parts = s.split("\u3042".encode("UTF-16LE"), -1)
    summary(arm, parts.last)
  end
when "chomp"
  show(arm) do
    s = ("\u3042" * 2100 + "\r\n").encode("UTF-16LE")
    summary(arm, s.chomp)
  end
when "scrub"
  show(arm) do
    s = ("\xff\u3042" * 2100).force_encoding("UTF-8")
    summary(arm, s.scrub("?"))
  end
when "index-bounds"
  show(arm) do
    s = ("a\u3042b" * 1400).encode("UTF-16LE")
    summary(arm, s.rindex("\u3042b".encode("UTF-16LE"), 4).to_s)
  end
else
  abort "SWEEP arm=unknown:#{arm}"
end
