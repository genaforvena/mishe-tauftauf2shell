# One ActiveSupport::Inflector method on one string, for ASan case-fold tests.
# argv: METHOD WORD   (METHOD in pluralize|singularize|camelize|titleize)
require "active_support/inflector"
require "active_support/core_ext/string/inflections"

method, word = ARGV
raise "usage: METHOD WORD" unless method && word
puts "case=method=#{method} word=#{word.bytes.map { |b| "%02x" % b }.join}"
result = word.public_send(method)
puts "result=#{result.inspect}"
