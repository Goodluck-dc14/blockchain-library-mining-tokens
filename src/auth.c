/*
 * auth.c - librarian authentication.
 *
 * The password is never stored. librarian.dat holds:
 *     username:iterations:salt_hex:pbkdf2_hash_hex
 * using PBKDF2-HMAC-SHA256 with a random 16-byte salt and 100,000 iterations.
 * Hashes are compared in constant time, and failed logins are rate limited.
 */
#include "auth.h"

#include <ctype.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "common.h"
#include "crypto_utils.h"
#include "util.h"

#define PBKDF2_ITERATIONS  100000
#define SALT_LEN           16
#define DK_LEN             32
#define MAX_LOGIN_ATTEMPTS 3
#define MIN_PASSWORD_LEN   8

int auth_exists(void)
{
    return access(AUTH_FILE, F_OK) == 0;
}

int read_password(const char *prompt, char *buf, size_t n)
{
    struct termios old_t, quiet_t;
    int hide = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &old_t) == 0;

    printf("%s", prompt);
    fflush(stdout);
    if (hide) {
        quiet_t = old_t;
        quiet_t.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet_t);
    }
    int rc = read_line(NULL, buf, n);
    if (hide) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_t);
        printf("\n");
    }
    return rc;
}

static int derive_key(const char *pass, const unsigned char *salt, int iterations,
                      unsigned char out[DK_LEN])
{
    if (PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_LEN, iterations,
                          EVP_sha256(), DK_LEN, out) != 1) {
        print_openssl_error("password hashing failed");
        return -1;
    }
    return 0;
}

static int valid_username(const char *u)
{
    size_t n = strlen(u);
    if (n < 3 || n >= USERNAME_MAX)
        return 0;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)u[i]) && u[i] != '_')
            return 0;
    return 1;
}

int auth_setup(char *user, size_t user_n, char *pass, size_t pass_n)
{
    char confirm[PASSWORD_MAX];

    printf("\n=== First-time setup: create the librarian account ===\n");
    printf("This account signs every lending record. The password also\n");
    printf("encrypts the ECDSA private key, so don't lose it.\n\n");

    for (;;) {
        int rc = read_line("Librarian username (3-31 letters, digits or _): ", user, user_n);
        if (rc == -1)
            return -1;
        trim(user);
        if (rc == 0 && valid_username(user))
            break;
        printf("ERROR: Invalid username.\n");
    }

    for (;;) {
        int rc = read_password("Password (min 8 characters): ", pass, pass_n);
        if (rc == -1)
            return -1;
        if (rc == -2 || strlen(pass) < MIN_PASSWORD_LEN) {
            printf("ERROR: Password must be %d-%d characters.\n", MIN_PASSWORD_LEN, PASSWORD_MAX - 1);
            continue;
        }
        rc = read_password("Confirm password: ", confirm, sizeof confirm);
        if (rc == -1) {
            OPENSSL_cleanse(pass, pass_n);
            return -1;
        }
        if (strcmp(pass, confirm) != 0) {
            printf("ERROR: Passwords do not match.\n");
            continue;
        }
        break;
    }
    OPENSSL_cleanse(confirm, sizeof confirm);

    unsigned char salt[SALT_LEN], dk[DK_LEN];
    char salt_hex[2 * SALT_LEN + 1], dk_hex[2 * DK_LEN + 1];
    if (RAND_bytes(salt, SALT_LEN) != 1) {
        print_openssl_error("random number generation failed");
        return -1;
    }
    if (derive_key(pass, salt, PBKDF2_ITERATIONS, dk) != 0)
        return -1;
    bytes_to_hex(salt, SALT_LEN, salt_hex);
    bytes_to_hex(dk, DK_LEN, dk_hex);
    OPENSSL_cleanse(dk, sizeof dk);

    int fd = open(AUTH_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        perror(AUTH_FILE);
        return -1;
    }
    FILE *fp = fdopen(fd, "w");
    if (!fp) {
        close(fd);
        return -1;
    }
    int ok = fprintf(fp, "%s:%d:%s:%s\n", user, PBKDF2_ITERATIONS, salt_hex, dk_hex) > 0;
    if (fclose(fp) != 0)
        ok = 0;
    if (!ok) {
        fprintf(stderr, "ERROR: Could not write %s\n", AUTH_FILE);
        unlink(AUTH_FILE);
        return -1;
    }
    printf("[OK] Librarian account created (password stored as salted PBKDF2-SHA256 hash).\n");
    return 0;
}

int auth_login(char *user, size_t user_n, char *pass, size_t pass_n)
{
    char line[512];
    FILE *fp = fopen(AUTH_FILE, "r");
    if (!fp) {
        perror(AUTH_FILE);
        return -1;
    }
    if (!fgets(line, sizeof line, fp)) {
        fclose(fp);
        fprintf(stderr, "ERROR: %s is empty or unreadable.\n", AUTH_FILE);
        return -1;
    }
    fclose(fp);
    line[strcspn(line, "\r\n")] = '\0';

    char *f[5];
    unsigned char salt[SALT_LEN], stored[DK_LEN];
    size_t salt_len = 0, hash_len = 0;
    if (split_fields(line, ':', f, 5) != 4 || atoi(f[1]) < 1000 ||
        hex_to_bytes(f[2], salt, SALT_LEN, &salt_len) != 0 || salt_len != SALT_LEN ||
        hex_to_bytes(f[3], stored, DK_LEN, &hash_len) != 0 || hash_len != DK_LEN) {
        fprintf(stderr, "ERROR: %s is malformed.\n", AUTH_FILE);
        return -1;
    }
    int iterations = atoi(f[1]);

    for (int attempt = 1; attempt <= MAX_LOGIN_ATTEMPTS; attempt++) {
        if (read_line("Username: ", user, user_n) == -1)
            return -1;
        trim(user);
        int rc = read_password("Password: ", pass, pass_n);
        if (rc == -1)
            return -1;

        unsigned char dk[DK_LEN];
        int user_ok = strcmp(user, f[0]) == 0;
        int pass_ok = rc == 0 && derive_key(pass, salt, iterations, dk) == 0 &&
                      CRYPTO_memcmp(dk, stored, DK_LEN) == 0;
        OPENSSL_cleanse(dk, sizeof dk);

        if (user_ok && pass_ok) {
            printf("[OK] Welcome, %s. Signed in as LIBRARIAN.\n", user);
            return 0;
        }
        OPENSSL_cleanse(pass, pass_n);
        printf("ERROR: Invalid username or password (attempt %d of %d).\n",
               attempt, MAX_LOGIN_ATTEMPTS);
        sleep(1);   /* slows down password guessing */
    }
    printf("ERROR: Too many failed attempts. Exiting.\n");
    return -1;
}
