set pagination off
cd ..
set breakpoint pending on
break /home/mesh-home/mishe-tauftauf2shell/lab/frontier/rpm2shell/src/rpm/lib/rpmfi.cc:2243
commands
  silent
  printf "SCALED_BUF=%p LSIZE=%lld\n", buf, lsize
  x/s buf
  x/16bx buf+4080
  x/2gx buf+4088
  quit
end
run real/scaled/attack-4096.rpm > /dev/null
