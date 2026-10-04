/*
 * crypto_utils.h - SHA-256 hashing and ECDSA signing via OpenSSL.
 */
#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <openssl/evp.h>
#include <stddef.h>

#include "common.h"

void print_openssl_error(const char *context);

/* SHA-256 of data, written as 64 lowercase hex chars + '\0'. Returns 0 on success. */
int  sha256_hex(const void *data, size_t len, char out[HASH_HEX_LEN]);

void bytes_to_hex(const unsigned char *in, size_t len, char *out);
int  hex_to_bytes(const char *hex, unsigned char *out, size_t max, size_t *out_len);

/* ECDSA key management (curve P-256 / prime256v1) */
EVP_PKEY *generate_keypair(void);
/* Private key is written AES-256 encrypted with passphrase, file mode 0600. */
int       save_keypair(EVP_PKEY *key, const char *priv_path, const char *pub_path,
                       const char *passphrase);
EVP_PKEY *load_private_key(const char *path, const char *passphrase);
EVP_PKEY *load_public_key(const char *path);

/* Returns 0 on success; sig must hold SIG_MAX_LEN bytes. */
int sign_data(EVP_PKEY *priv, const unsigned char *data, size_t len,
              unsigned char *sig, unsigned int *sig_len);
/* Returns 1 if valid, 0 if not. */
int verify_signature(EVP_PKEY *pub, const unsigned char *data, size_t len,
                     const unsigned char *sig, unsigned int sig_len);

#endif /* CRYPTO_UTILS_H */
