set pagination off
set confirm off
handle SIGUSR1 nostop noprint pass
handle SIGUSR2 nostop noprint pass
break nx_secure_x509_certificate_verify.c:270
commands
  silent
  printf "=== CRAFTED TLS VERIFY HIT (post-RSA) ===\n"
  bt 3
  printf "parsed modulus_length=%u exponent_length=%u sig_length=%u\n", issuer_certificate->nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length, issuer_certificate->nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent_length, certificate->nx_secure_x509_signature_data_length
  printf "bytes 504..527 of decrypted_signature (512 = first past the array):\n"
  x/24bx decrypted_signature+504
  continue
end
run
