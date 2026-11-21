#ifndef IPERF_CONFIG_H
#define IPERF_CONFIG_H
/* Minimal config for the extracted harness: the pinned iperf_auth.c needs
   only HAVE_SSL to compile decrypt_rsa_message with OpenSSL 3. */
#define HAVE_SSL 1
#endif
