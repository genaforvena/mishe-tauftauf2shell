# W346 (W343 named follow-up): dynamic falsifier for the gem-source survey.
# A gem-defined coercion object (pure to_str/to_int) is passed as the pad /
# width of String#ljust on a 4096-byte UTF-16LE receiver. W341/W342 need the
# hook to MUTATE the receiver's encoding between the stale termlen snapshot
# (string.c:10879) and str_enc_new (:10909); a pure coercion cannot.
# Usage: lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#          lab/repro/ruby2shell-gem-coerce-probe.rb [plain|gem]
# Every arm must be MUTATED=false with clean rc on vulnerable AND fixed.
mode = (ARGV[0] || "plain")

receiver = ("A" * 4096).dup.force_encoding(Encoding::UTF_16LE)

# Shape 1: a pure to_str pad, exactly like Mime::Type / Sinatra::MimeType /
# ActionView::Template::Text / Brakeman::FilePath / RBS::ToStr — returns a
# stored/dup US-ASCII string, never touches the receiver.
pad = Object.new
pad.define_singleton_method(:to_str) { "Z".dup.force_encoding(Encoding::US_ASCII) }
before = [receiver.bytesize, receiver.encoding.to_s]
begin
  out = receiver.ljust(8200, pad)
  rc = 0
rescue => e
  out = nil
  rc = "#{e.class}: #{e.message}"
end
after = [receiver.bytesize, receiver.encoding.to_s]
printf("GEMCOERCE mode=%s arm=to_str_pad rc=%s outlen=%s outenc=%s before=%s after=%s MUTATED=%s\n",
       mode, rc, out ? (out.bytesize rescue "?") : "-", out ? (out.encoding.to_s rescue "?") : "-",
       before.inspect, after.inspect, before != after)

# Shape 2: a pure to_int width, exactly like RBS::UnitTest::Convertibles::ToInt
# — returns a stored Integer, never touches the receiver.
width = Object.new
width.define_singleton_method(:to_int) { 8200 }
before = [receiver.bytesize, receiver.encoding.to_s]
begin
  out = receiver.ljust(width, "Z")
  rc = 0
rescue => e
  out = nil
  rc = "#{e.class}: #{e.message}"
end
after = [receiver.bytesize, receiver.encoding.to_s]
printf("GEMCOERCE mode=%s arm=to_int_width rc=%s outlen=%s outenc=%s before=%s after=%s MUTATED=%s\n",
       mode, rc, out ? (out.bytesize rescue "?") : "-", out ? (out.encoding.to_s rescue "?") : "-",
       before.inspect, after.inspect, before != after)
