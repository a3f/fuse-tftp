/*
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#ifndef LIB_BUSYBOX_H_
#define LIB_BUSYBOX_H_

#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/poll.h>
#include <string.h>

typedef struct len_and_sockaddr {
	socklen_t len;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} u;
} len_and_sockaddr;

ssize_t safe_read(int fd, void *buf, size_t count);

ssize_t full_read(int fd, void *buf, size_t len);

ssize_t safe_write(int fd, const void *buf, size_t count);

ssize_t full_write(int fd, const void *buf, size_t len);

int safe_poll(struct pollfd *ufds, nfds_t nfds, int timeout);

len_and_sockaddr* str2sockaddr(const char *host, int port,
			       sa_family_t af, int ai_flags);

char* is_prefixed_with(const char *string, const char *key);

static inline char* safe_strncpy(char *dst, const char *src, size_t size)
{
	if (!size) return dst;
	dst[--size] = '\0';
	return strncpy(dst, src, size);
}

void setsockopt_reuseaddr(int fd);

const char* nth_string(const char *strings, int n);

unsigned bb_lookup_port(const char *port, const char *protocol, unsigned default_port);

void set_nport(struct sockaddr *sa, unsigned port);

#endif
