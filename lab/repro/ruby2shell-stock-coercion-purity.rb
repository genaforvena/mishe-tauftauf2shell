# W344 (W342 named follow-up): do STOCK to_str/to_int coercions mutate a
# separate String's encoding or length? This is the falsifier for reaching
# W341/W342's stale-termlen write without a caller-defined hook object.
# Usage: lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#          lab/repro/ruby2shell-stock-coercion-purity.rb
# Every MUTATED=false is a closure; any MUTATED=true reopens the lane.
require 'uri'

def probe(label, target, obj, meth)
  before = [target.bytesize, target.encoding.to_s]
  begin
    out = obj.__send__(meth)
    ok = true
  rescue => e
    out = "#{e.class}: #{e.message}"
    ok = false
  end
  after = [target.bytesize, target.encoding.to_s]
  printf("PROBE %-28s class=%-20s ok=%-5s out=%s before=%s after=%s MUTATED=%s\n",
         label, obj.class, ok, out.inspect[0, 48], before.inspect, after.inspect,
         before != after)
end

target = ("A" * 4096).dup.force_encoding(Encoding::UTF_16LE)
probe("String#to_str", target, target, :to_str)
probe("NameErrorMesg#to_str", target, NameError.new("boom", target).message, :to_str)
probe("Integer#to_int", target, 1, :to_int)
probe("Float#to_int", target, 1.5, :to_int)
begin
  require 'fiddle'
  probe("Fiddle::Pointer#to_str", target, Fiddle::Pointer[target], :to_str)
  probe("Fiddle::Pointer#to_int", target, Fiddle::Pointer[target], :to_int)
rescue LoadError => e
  puts "SKIP fiddle: #{e.message} (source survey only on this build)"
end
probe("URI::Generic#to_str", target, URI.parse("http://example.com/a?b=c"), :to_str)

# Stock consumer: URI::Generic#query= dups the to_str result before it
# force_encodes/delete!/gsub!s it, so the caller's String is untouched.
query = ("x" * 64).dup.force_encoding(Encoding::UTF_16LE)
before = [query.bytesize, query.encoding.to_s]
uri = URI.parse("http://example.com/")
uri.query = query
after = [query.bytesize, query.encoding.to_s]
printf("PROBE %-28s stored_enc=%-12s before=%s after=%s MUTATED=%s\n",
       "URI::Generic#query=", uri.query.encoding.to_s, before.inspect,
       after.inspect, before != after)
