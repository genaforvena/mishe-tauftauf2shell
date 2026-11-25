set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/w217/evidence/gdb-w217-zero.log
set logging overwrite on
set logging enabled on
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W2E_KW_DECRYPT raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break AES_unwrap_key
commands
 silent
 printf "W2E_UNWRAP_KEY_REACHED\n"
 continue
end
break jwe.c:602
commands
 silent
 printf "W2E_POST_UNWRAP cek=%p cek_len_before=%lu hdr=%p dat=%p\n", jwe->cek, (unsigned long)jwe->cek_len, jwe->hdr, jwe->dat
 x/24gx jwe->cek-16
 continue
end
run
bt 12
