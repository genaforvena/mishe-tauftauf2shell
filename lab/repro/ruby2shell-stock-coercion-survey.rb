# Read-only survey for the coercion our adjacent stale-backref lane needs:
# a stock caller of String#[regexp] = val whose RHS is a non-String with a
# mutating to_str. Parses .rb source with Ripper; prints every index
# assignment whose key looks like a Regexp plus every stock to_str method.
# No process is executed, no request is sent, no Ruby object is inspected.
# Usage: ruby this.rb ROOT [ROOT ...]
require 'ripper'
KEY_NAMES = /\A(?:re|regex|regexp|pattern|pat|rx|matcher|match)\z/i
def first_line(node)
  return nil unless node.is_a?(Array)
  if node.length == 3 && node.last.is_a?(Array) &&
     node.last.length == 2 && node.last.all? { |v| v.is_a?(Integer) }
    return node.last.first
  end
  node.each do |child|
    found = first_line(child)
    return found if found
  end
  nil
end

def key_flag?(key)
  return false unless key.is_a?(Array)
  return true if key[0] == :regexp_literal
  text = key.inspect
  return true if text.include?('Regexp.new')
  if key[0] == :vcall && key[1].is_a?(Array) && key[1][0] == :@ident
    return true if KEY_NAMES.match?(key[1][1].to_s)
  end
  false
end

def walk(node, path, lines, assigns, to_strs)
  return unless node.is_a?(Array)
  if node[0] == :assign && node[1].is_a?(Array) && node[1][0] == :aref_field
    args = node[1][2]
    keys = args.is_a?(Array) && args[0] == :args_add_block ? args[1] : []
    key = keys.first
    if key_flag?(key)
      line = first_line(key) || first_line(node[1]) || 1
      text = lines[line - 1].to_s.strip
      rhs = node[2].is_a?(Array) ? node[2][0].to_s : '?'
      assigns << [path, line, rhs, text]
    end
  end
  if node[0] == :def && node[1].is_a?(Array) && node[1][0] == :@ident &&
     node[1][1] == 'to_str'
    line = first_line(node[1]) || 1
    body = lines[(line - 1), 5].to_a.each_with_index.map { |l, i| "#{line + i}: #{l.strip}" }
    to_strs << [path, line, body]
  end
  node.each { |child| walk(child, path, lines, assigns, to_strs) if child.is_a?(Array) }
end

roots = ARGV
abort 'usage: ruby stock-coercion-survey.rb ROOT [ROOT ...]' if roots.empty?
files = roots.flat_map { |root| Dir.glob("#{root}/**/*.rb") }.sort
assigns = []
to_strs = []
parse_errors = []
files.each do |path|
  source = File.binread(path).force_encoding(Encoding::UTF_8)
  next unless source.valid_encoding?
  lines = source.lines
  sexp = Ripper.sexp(source)
  if sexp.nil?
    parse_errors << path
    next
  end
  walk(sexp, path, lines, assigns, to_strs)
end

puts "SURVEY roots=#{roots.length} rb_files=#{files.length} parse_errors=#{parse_errors.length}"
parse_errors.each { |path| puts "UNKNOWN parse: #{path}" }
puts "--- index assignments with Regexp-looking keys (#{assigns.length}) ---"
assigns.each { |path, line, rhs, text| puts "#{path}:#{line} rhs=#{rhs} | #{text}" }
puts "--- stock to_str definitions (#{to_strs.length}) ---"
to_strs.each do |path, line, body|
  puts "#{path}:#{line}"
  body.each { |l| puts "  #{l}" }
end
