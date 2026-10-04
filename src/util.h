/*
 * util.h - small input/string helpers used across the program.
 */
#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <time.h>

/* Reads one line from stdin. Returns 0 on success, -1 on EOF, -2 if too long. */
int  read_line(const char *prompt, char *buf, size_t n);
void trim(char *s);
void str_upper(char *s);
/* 1 if s is 1..cap-1 chars of letters, digits, '-' or '_' */
int  is_valid_id(const char *s, size_t cap);
/* Copies src into dst. Returns -1 (and leaves dst empty) if it would not fit. */
int  safe_copy(char *dst, size_t cap, const char *src);
void format_time(time_t t, char *out, size_t n);
void format_duration(long seconds, char *out, size_t n);
/* Splits s in place on delim. Returns field count, or max+1 if there were too many. */
int  split_fields(char *s, char delim, char **out, int max);

#endif /* UTIL_H */
