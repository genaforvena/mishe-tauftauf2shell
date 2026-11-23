# W148 tcache/fastbin reuse probe, fixed-address debug variant.
# The chosen free lands the forged 0x31 chunk in a small-bin allocator list;
# its protected next link is read at the next free entry, after libc wrote it.
# A later malloc that sees the decoded head will pop the wire-chosen chunk.
set pagination off
set confirm off
set print pretty off
set breakpoint pending on
set disable-randomization on
set $rb = 0
set $matched = 0
set $seen = 0
set $expected = 0
set $bin = -1
set $kind = 0
set $pops = 0

break THeaderTransport.cpp:301
commands 1
 silent
 set $rb = rBuf_.get()
 printf "ANCHOR rbuf=%p sz=%u\n", $rb, sz
 continue
end

break __libc_free
commands 2
 silent
 if $matched == 0
  if $rb != 0 && $rdi == $rb+512
   set $matched = 1
   printf "MATCHFREE mem=%p target=%p\n", $rdi, $rb+512
  end
 else
  if $seen == 0
   set $seen = 1
   set $user = (unsigned long long)$rb + 512
   set $hdr = $user - 16
   set $saved = *(unsigned long long*)$user
   set $expected = $saved ^ ($user >> 12)
   set $i = 0
   while $i < 64
    if tcache->entries[$i] == $user && $bin < 0
     set $bin = $i
     set $kind = 1
    end
    set $i = $i + 1
   end
   set $i = 0
   while $i < 10
    if main_arena.fastbinsY[$i] == $hdr && $bin < 0
     set $bin = $i
     set $kind = 2
    end
    set $i = $i + 1
   end
   printf "LINK saved=0x%llx decoded_head=0x%llx kind=%d bin=%d hdr=%p\n", $saved, $expected, $kind, $bin, $hdr
  end
 end
 continue
end

break __libc_malloc if $seen == 1
commands 3
 silent
 set $j = 0
 while $j < 64
  if tcache->entries[$j] == $expected
   set $pops = $pops + 1
   printf "POP_CANDIDATE list=tcache n=%d size=%lu bin=%d head=%p\n", $pops, $rdi, $j, tcache->entries[$j]
  end
  set $j = $j + 1
 end
 set $j = 0
 while $j < 10
  if main_arena.fastbinsY[$j] == $expected
   set $pops = $pops + 1
   printf "POP_CANDIDATE list=fastbin n=%d size=%lu bin=%d head=%p\n", $pops, $rdi, $j, main_arena.fastbinsY[$j]
  end
  set $j = $j + 1
 end
 continue
end

run
printf "END matched=%d seen=%d kind=%d bin=%d pops=%d\n", $matched, $seen, $kind, $bin, $pops
