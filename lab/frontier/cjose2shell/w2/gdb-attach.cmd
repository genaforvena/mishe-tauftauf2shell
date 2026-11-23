set pagination off
set confirm off
set print elements 0
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/gdb-attach.log
set logging overwrite on
set logging enabled on
break oidc_handle_logout_backchannel
commands
 silent
 printf "W2_BACKCHANNEL_HIT\n"
 continue
end
break oidc_jwe_decrypt_impl
commands
 silent
 printf "W2_OIDC_JWE_DECRYPT_IMPL_REACHED alg=%s\n", alg
 continue
end
break cjose_jwe_decrypt
commands
 silent
 printf "W2_CJOSE_JWE_DECRYPT_REACHED jwk_kty=%d\n", (int)jwk->kty
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W2_AES_KW_DECRYPT_REACHED raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break AES_unwrap_key
commands
 silent
 printf "W2_AES_UNWRAP_KEY_REACHED inlen=%lu\n", (unsigned long)inlen
 continue
end
continue
