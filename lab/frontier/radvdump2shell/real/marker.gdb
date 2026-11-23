set pagination off
set confirm off
break radvdump.c:381
commands
  silent
  printf "\n=== AT 381 (BEFORE RETURN) ===\n"
  p &addr
  p rinfo
  p system
  printf "=== CONTINUING INTO EPILOGUE/ROP ===\n"
  continue
end
run
