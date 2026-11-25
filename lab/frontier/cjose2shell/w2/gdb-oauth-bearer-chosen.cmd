set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/oauth-bearer-chosen-gdb.log
set logging overwrite on
set logging enabled on
break oidc_oauth_validate_jwt_access_token
commands
 silent
 printf "W2BC_OAUTH_VALIDATE_JWT_REACHED\n"
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W2BC_AES_KW_DECRYPT_REACHED raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break AES_unwrap_key
commands
 silent
 printf "W2BC_AES_UNWRAP_KEY_REACHED\n"
 continue
end
break jwe.c:602
commands
 silent
 printf "W2BC_POST_UNWRAP cek_len_before=%lu\n", (unsigned long)jwe->cek_len
 x/48bx jwe->cek
 continue
end
run
