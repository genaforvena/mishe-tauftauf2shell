# W346: real gem-defined coercion classes as String#ljust pads on a
# 4096-byte UTF-16LE receiver. Every to_str below is pure (returns a
# stored/dup string), so rb_enc_check at string.c:10883 rejects the mismatch
# and no stale-termlen write occurs. Runs on the two plain builds only;
# the ASan builds have no gems installed. Corroborates the 4-build mimic
# falsifier in ruby2shell-gem-coerce-probe.rb.
require 'action_dispatch/http/mime_type'
require 'action_view/template/text'

def probe(label, pad)
  receiver = ("A" * 4096).dup.force_encoding(Encoding::UTF_16LE)
  before = [receiver.bytesize, receiver.encoding.to_s]
  begin
    out = receiver.ljust(8200, pad)
    result = "outlen=#{out.bytesize} outenc=#{out.encoding}"
  rescue => e
    result = "#{e.class}: #{e.message}"
  end
  after = [receiver.bytesize, receiver.encoding.to_s]
  printf("REALGEM pad=%-28s result=%s before=%s after=%s MUTATED=%s\n",
         label, result.inspect[0, 92], before.inspect, after.inspect, before != after)
end

probe("Mime::Type", Mime::Type.lookup("text/html"))
probe("AV::Template::Text", ActionView::Template::Text.new("hello"))
begin
  require 'sinatra/base'
  probe("Sinatra::Request::AcceptEntry", Sinatra::Request::AcceptEntry.new("text/html"))
rescue LoadError => e
  puts "SKIP sinatra: #{e.message}"
end
