/*
 * crypto_utils.c - thin wrappers around OpenSSL's EVP API.
 *
 * Hashing:    SHA-256
 * Signatures: ECDSA over NIST P-256 with SHA-256
 * Key file:   private key PEM encrypted with AES-256-CBC using the
 *             librarian's password, so a stolen key file is useless on its own.
 */
#include "crypto_utils.h"

#include <fcntl.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void print_openssl_error(const char *context)
{
    unsigned long e = ERR_get_error();
    if (e) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof buf);
        fprintf(stderr, "ERROR: %s (%s)\n", context, buf);
    } else {
        fprintf(stderr, "ERROR: %s\n", context);
    }
    ERR_clear_error();
}

void bytes_to_hex(const unsigned char *in, size_t len, char *out)
{
    static const char hx[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hx[in[i] >> 4];
        out[2 * i + 1] = hx[in[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char *hex, unsigned char *out, size_t max, size_t *out_len)
{
    size_t n = strlen(hex);
    if (n % 2 != 0 || n / 2 > max)
        return -1;
    for (size_t i = 0; i < n / 2; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    *out_len = n / 2;
    return 0;
}

int sha256_hex(const void *data, size_t len, char out[HASH_HEX_LEN])
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (EVP_Digest(data, len, md, &md_len, EVP_sha256(), NULL) != 1 || md_len != 32) {
        print_openssl_error("SHA-256 computation failed");
        return -1;
    }
    bytes_to_hex(md, md_len, out);
    return 0;
}

EVP_PKEY *generate_keypair(void)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &key) <= 0) {
        print_openssl_error("ECDSA key generation failed");
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

int save_keypair(EVP_PKEY *key, const char *priv_path, const char *pub_path,
                 const char *passphrase)
{
    /* Private key: created with owner-only permissions from the start */
    int fd = open(priv_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(priv_path);
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }
    int ok = PEM_write_PrivateKey(fp, key, EVP_aes_256_cbc(),
                                  (unsigned char *)passphrase, (int)strlen(passphrase),
                                  NULL, NULL);
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok) {
        print_openssl_error("could not write private key");
        unlink(priv_path);
        return -1;
    }

    fp = fopen(pub_path, "w");
    if (!fp) {
        perror(pub_path);
        return -1;
    }
    ok = PEM_write_PUBKEY(fp, key);
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok) {
        print_openssl_error("could not write public key");
        return -1;
    }
    return 0;
}

EVP_PKEY *load_private_key(const char *path, const char *passphrase)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return NULL;
    }
    /* With a NULL callback, OpenSSL treats the last argument as the passphrase */
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, (void *)passphrase);
    fclose(fp);
    if (!key)
        ERR_clear_error();
    return key;
}

EVP_PKEY *load_public_key(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror(path);
        return NULL;
    }
    EVP_PKEY *key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!key)
        print_openssl_error("could not read public key");
    return key;
}

int sign_data(EVP_PKEY *priv, const unsigned char *data, size_t len,
              unsigned char *sig, unsigned int *sig_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sl = SIG_MAX_LEN;
    int rc = -1;
    if (ctx && EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv) == 1 &&
        EVP_DigestSign(ctx, sig, &sl, data, len) == 1) {
        *sig_len = (unsigned int)sl;
        rc = 0;
    } else {
        print_openssl_error("signing failed");
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

int verify_signature(EVP_PKEY *pub, const unsigned char *data, size_t len,
                     const unsigned char *sig, unsigned int sig_len)
{
    if (!pub || sig_len == 0 || sig_len > SIG_MAX_LEN)
        return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int valid = 0;
    if (ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pub) == 1)
        valid = (EVP_DigestVerify(ctx, sig, sig_len, data, len) == 1);
    EVP_MD_CTX_free(ctx);
    ERR_clear_error();   /* a bad signature leaves errors on the queue */
    return valid;
}
