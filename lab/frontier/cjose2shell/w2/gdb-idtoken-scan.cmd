set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/gdb-idtoken-scan.log
set logging overwrite on
set logging enabled on
break AES_unwrap_key
commands
 silent
 set $w2s_cek = $rdx
 printf "W2S_UNWRAP_ENTRY cek=%p inlen=%d\n", $w2s_cek, (int)$r8d
 printf "W2S_MAPPINGS_BEGIN\n"
 info proc mappings
 printf "W2S_MAPPINGS_END\n"
 printf "W2S_HEAP_BEFORE_BEGIN\n"
 x/256gx $w2s_cek+32
 printf "W2S_HEAP_BEFORE_END\n"
 continue
end
break _cjose_jwe_calc_auth_tag
commands
 silent
 printf "W2S_CALC_AUTH_TAG enc_delta=%ld\n", (char*)$rdi-(char*)$w2s_cek
 printf "W2S_HEAP_AFTER_BEGIN\n"
 x/256gx $w2s_cek+32
 printf "W2S_HEAP_AFTER_END\n"
 continue
end
run
printf "W2S_POST_RUN_REACHED\n"
bt 20
