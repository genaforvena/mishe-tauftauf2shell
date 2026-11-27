# Harness-only address measurement for the pinned 3.4.11 repeat-ID write.
# The pattern is the exact wire pattern from ruby2shell-onigmo-repeat-wire.py
# wrapped the way Rails wraps it; no claim about wire-only input is made here.
Regexp.timeout = nil
pattern = File.read(ARGV.fetch(0))
subject = "# " + ("x" * Integer(ARGV.fetch(1, "2000")))
regexp = Regexp.new("#\\s*(#{pattern}):?\\s*(.*)$")
2.times do |i|
  match = regexp.match(subject)
  puts "MATCH #{i + 1} #{!match.nil?}"
end
