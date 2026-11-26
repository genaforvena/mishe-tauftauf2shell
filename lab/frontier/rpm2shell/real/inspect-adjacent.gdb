set pagination off
set confirm off
cd ..
set breakpoint pending on
set environment RPM_CONFIGDIR /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/install-vuln/lib/rpm
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2242
commands
  silent
  printf "BEFORE_BUF=%p LSIZE=%lld ADJacent=%p\n", buf, lsize, *(void **)(buf+0x20)
  if *(void **)(buf+0x20) != 0
    printf "ADJ_TARGET_STRING:\n"
    x/s *(char **)(buf+0x20)
    printf "ADJ_TARGET_WORDS:\n"
    x/8gx *(char **)(buf+0x20)
  end
  printf "ADJ_BYTES:\n"
  x/8gx buf+0x20
  continue
end
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2243
commands
  silent
  printf "AFTER_BUF=%p LSIZE=%lld ADJacent=%p\n", buf, lsize, *(void **)(buf+0x20)
  continue
end
run real/attack.rpm > /dev/null
