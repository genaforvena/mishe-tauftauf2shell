set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/w219/evidence/gdb-b-base.log
set logging overwrite on
set logging enabled on

break oidc_oauth_validate_jwt_access_token
commands
 silent
 printf "W219_OAUTH_VALIDATE_REACHED\n"
 continue
end
break oidc_jwe_decrypt_impl
commands
 silent
 printf "W219_JWE_DECRYPT_IMPL_REACHED\n"
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W219_KW_DECRYPT raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break jwe.c:595
commands
 silent
 printf "W219_PRE_UNWRAP cek=%p\n", jwe->cek
 x/8gx jwe->cek+0x80
 continue
end
break AES_unwrap_key
commands
 silent
 printf "W219_UNWRAP_KEY_REACHED\n"
 continue
end
break jwe.c:602
commands
 silent
 printf "W219_POST_UNWRAP cek=%p cek_len_before=%lu\n", jwe->cek, (unsigned long)jwe->cek_len
 x/24gx jwe->cek-16
 continue
end
run
bt 12
