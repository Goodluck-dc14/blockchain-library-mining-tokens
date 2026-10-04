/*
 * util.c - input handling and string helpers.
 */
#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

int read_line(const char *prompt, char *buf, size_t n)
{
    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }
    if (!fgets(buf, (int)n, stdin))
        return -1;

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[--len] = '\0';
    } else if (!feof(stdin)) {
        /* line was longer than the buffer: discard the rest of it */
        int c;
        while ((c = getchar()) != '\n' && c != EOF)
            ;
        buf[0] = '\0';
        return -2;
    }
    if (len > 0 && buf[len - 1] == '\r')   /* Windows line endings */
        buf[--len] = '\0';
    return 0;
}

void trim(char *s)
{
    size_t len = strlen(s), start = 0;
    while (start < len && isspace((unsigned char)s[start]))
        start++;
    while (len > start && isspace((unsigned char)s[len - 1]))
        len--;
    memmove(s, s + start, len - start);
    s[len - start] = '\0';
}

void str_upper(char *s)
{
    for (; *s; s++)
        *s = (char)toupper((unsigned char)*s);
}

int is_valid_id(const char *s, size_t cap)
{
    size_t n = strlen(s);
    if (n == 0 || n >= cap)
        return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isalnum(c) && c != '-' && c != '_')
            return 0;
    }
    return 1;
}

int safe_copy(char *dst, size_t cap, const char *src)
{
    size_t n = strlen(src);
    if (n >= cap) {
        if (cap > 0)
            dst[0] = '\0';
        return -1;
    }
    memcpy(dst, src, n + 1);
    return 0;
}

void format_time(time_t t, char *out, size_t n)
{
    struct tm tmv;
    if (localtime_r(&t, &tmv) && strftime(out, n, "%Y-%m-%d %H:%M:%S", &tmv) > 0)
        return;
    snprintf(out, n, "%lld", (long long)t);
}

void format_duration(long s, char *out, size_t n)
{
    if (s >= 86400 && s % 86400 == 0)
        snprintf(out, n, "%ld day(s)", s / 86400);
    else if (s >= 3600 && s % 3600 == 0)
        snprintf(out, n, "%ld hour(s)", s / 3600);
    else
        snprintf(out, n, "%ld second(s)", s);
}

int split_fields(char *s, char delim, char **out, int max)
{
    int n = 0;
    out[n++] = s;
    for (char *p = s; *p; p++) {
        if (*p == delim) {
            *p = '\0';
            if (n >= max)
                return max + 1;
            out[n++] = p + 1;
        }
    }
    return n;
}
