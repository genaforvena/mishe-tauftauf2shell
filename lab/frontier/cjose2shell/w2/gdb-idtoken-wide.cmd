# W195: extend the real-consumer CEK forward scan from W189's 2 KiB to ~8 KiB.
# Prediction to test: a pointer-bearing object (heap or code/data address) may
# sit beyond W189's window and still be inside a plausible OOB write range.
set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/gdb-idtoken-wide.log
set logging overwrite on
set logging enabled on
break AES_unwrap_key
commands
 silent
 set $w2w_cek = $rdx
 printf "W2W_UNWRAP_ENTRY cek=%p inlen=%d\n", $w2w_cek, (int)$r8d
 printf "W2W_MAPPINGS_BEGIN\n"
 info proc mappings
 printf "W2W_MAPPINGS_END\n"
 printf "W2W_HEAP_WIDE_BEGIN\n"
 x/1024gx $w2w_cek+32
 printf "W2W_HEAP_WIDE_END\n"
 continue
end
break _cjose_jwe_calc_auth_tag
commands
 silent
 printf "W2W_CALC_AUTH_TAG enc_delta=%ld\n", (char*)$rdi-(char*)$w2w_cek
 continue
end
run
printf "W2W_POST_RUN_REACHED\n"
