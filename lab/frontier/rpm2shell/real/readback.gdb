set pagination off
cd ..
set breakpoint pending on
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2243
commands
  silent
  printf "REAL_CONSUMER_BUF=%p LSIZE=%lld\n", buf, lsize
  x/64bx buf
  x/2gx buf-16

  quit
end
run real/attack.rpm > /dev/null
