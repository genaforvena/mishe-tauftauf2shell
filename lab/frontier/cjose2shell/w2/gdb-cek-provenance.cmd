# W189: measure CEK allocation/free provenance in the real mod_auth_openidc
# consumer. Logs every CEK release and the final AES-KW unwrap CEK so we can
# tell whether a wire-driven state-cookie teardown hole is reused as the
# id_token CEK, and what the forward region holds at that moment.
set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/gdb-cek-provenance.log
set logging overwrite on
set logging enabled on

break _cjose_release_cek
commands
 silent
 printf "W2P_CEK_RELEASE ptr=%p len=%ld\n", *(void **)$rdi, (long)$rsi
 continue
end

break _cjose_jwe_set_cek_aes_cbc
commands
 silent
 printf "W2P_SET_CEK_CBC jwe=%p jwk=%p random=%d\n", (void*)$rdi, (void*)$rsi, (int)$edx
 continue
end

break AES_unwrap_key
commands
 silent
 set $w2p_cek = $rdx
 printf "W2P_UNWRAP cek=%p inlen=%d\n", (void*)$w2p_cek, (int)$r8d
 printf "W2P_HEAP_BEFORE_BEGIN\n"
 x/64gx $w2p_cek+32
 printf "W2P_HEAP_BEFORE_END\n"
 continue
end

break _cjose_jwe_calc_auth_tag
commands
 silent
 printf "W2P_CALC_AUTH_TAG delta=%ld\n", (char*)$rdi-(char*)$w2p_cek
 printf "W2P_HEAP_AFTER_BEGIN\n"
 x/64gx $w2p_cek+32
 printf "W2P_HEAP_AFTER_END\n"
 continue
end

run
printf "W2P_POST_RUN_REACHED\n"
bt 12
