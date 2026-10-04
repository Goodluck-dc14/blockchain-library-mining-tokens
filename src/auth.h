/*
 * auth.h - librarian account (authentication) handling.
 */
#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>

#define USERNAME_MAX 32
#define PASSWORD_MAX 128

int auth_exists(void);
/* Reads a password without echoing it to the terminal. Same return codes as read_line. */
int read_password(const char *prompt, char *buf, size_t n);
/* First-run: creates the librarian account. Password is returned so it can encrypt the key. */
int auth_setup(char *user, size_t user_n, char *pass, size_t pass_n);
/* Login with up to 3 attempts. Returns 0 on success, -1 on failure/lockout. */
int auth_login(char *user, size_t user_n, char *pass, size_t pass_n);

#endif /* AUTH_H */
