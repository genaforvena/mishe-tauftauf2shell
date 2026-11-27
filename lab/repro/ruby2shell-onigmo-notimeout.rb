# Diagnostic-only: gdb slows the repeat-ID match past Rails 8.1's 1 s
# Regexp.timeout. This does not change the pattern, the wire input or the
# overflow; it only lets the gdb-watched request reach regexec.c:3845.
class << Regexp
  alias_method :onigmo_original_timeout_set, :timeout=
  def timeout=(value)
    onigmo_original_timeout_set(value == 1 ? nil : value)
  end
end
