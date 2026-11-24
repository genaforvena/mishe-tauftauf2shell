set pagination off
set confirm off
set print elements 0
set breakpoint pending on
set logging file /home/mesh-home/mishe-tauftauf2shell/lab/frontier/cjose2shell/w2/evidence/gdb-idtoken-chosen.log
set logging overwrite on
set logging enabled on
break oidc_proto_parse_idtoken
commands
 silent
 printf "W2C_PARSE_IDTOKEN_REACHED\n"
 continue
end
break oidc_jwe_decrypt_impl
commands
 silent
 printf "W2C_OIDC_JWE_DECRYPT_IMPL_REACHED\n"
 continue
end
break cjose_jwe_decrypt
commands
 silent
 printf "W2C_CJOSE_JWE_DECRYPT_REACHED jwk_kty=%d\n", (int)jwk->kty
 continue
end
break _cjose_jwe_decrypt_ek_aes_kw
commands
 silent
 printf "W2C_AES_KW_DECRYPT_REACHED raw_len=%lu cek_len=%lu jwk_kty=%d\n", (unsigned long)recipient->enc_key.raw_len, (unsigned long)jwe->cek_len, (int)jwk->kty
 continue
end
break AES_unwrap_key
commands
 silent
 set $w2c_cek = $rdx
 printf "W2C_UNWRAP_ENTRY cek=%p inlen=%d\n", $w2c_cek, (int)$r8d
 printf "W2C_PRE_GX cek-16..\n"
 x/12gx $w2c_cek-16
 printf "W2C_PRE_BX cek..\n"
 x/96bx $w2c_cek
 continue
end
break _cjose_jwe_calc_auth_tag
commands
 silent
 printf "W2C_CALC_AUTH_TAG enc=%p delta=%ld\n", $rdi, (char*)$rdi-(char*)$w2c_cek
 printf "W2C_POST_GX cek+32..\n"
 x/3gx $w2c_cek+32
 printf "W2C_POST_BX cek+32..\n"
 x/24bx $w2c_cek+32
 continue
end
run
printf "W2C_POST_RUN_REACHED\n"
bt 25
