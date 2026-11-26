set pagination off
set confirm off
cd ..
set breakpoint pending on
set environment RPM_CONFIGDIR /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/install-vuln/lib/rpm
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2242
commands
  silent
  printf "BEFORE_BUF=%p LSIZE=%lld ADJacent=%p\n", buf, lsize, *(void **)(buf+0x20)
  x/8gx buf-16
  continue
end
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2243
commands
  silent
  printf "AFTER_BUF=%p LSIZE=%lld ADJacent=%p\n", buf, lsize, *(void **)(buf+0x20)
  x/8gx buf-16
  rwatch *(long *)(buf+0x20)
  continue
end
run real/attack.rpm > /dev/null
