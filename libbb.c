/* vi: set sw=4 ts=4: */
/*
 * A simple tftp client/server for busybox.
 * Tries to follow RFC1350.
 * Only "octet" mode supported.
 * Optional blocksize negotiation (RFC2347 + RFC2348)
 *
 * Copyright (C) 2001 Magnus Damm <damm@opensource.se>
 *
 * Parts of the code based on:
 *
 * atftp:  Copyright (C) 2000 Jean-Pierre Lefebvre <helix@step.polymtl.ca>
 *                        and Remi Lefebvre <remi@debian.org>
 *
 * utftp:  Copyright (C) 1999 Uwe Ohse <uwe@ohse.de>
 *
 * tftpd added by Denys Vlasenko & Vladimir Dronnikov
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stddef.h>
#include "libbb.h"

#define LSA_LEN_SIZE offsetof(len_and_sockaddr, u)

ssize_t safe_read(int fd, void *buf, size_t count)
{
	ssize_t n;

	for (;;) {
		n = read(fd, buf, count);
		if (n >= 0 || errno != EINTR)
			break;
		errno = 0;
	}

	return n;
}

ssize_t full_read(int fd, void *buf, size_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;

	while (len) {
		cc = safe_read(fd, buf, len);

		if (cc < 0) {
			if (total) {
				/* we already have some! */
				/* user can do another read to know the error code */
				return total;
			}
			return cc; /* read() returns -1 on failure. */
		}
		if (cc == 0)
			break;
		buf = ((char *)buf) + cc;
		total += cc;
		len -= cc;
	}

	return total;
}

int safe_poll(struct pollfd *ufds, nfds_t nfds, int timeout)
{
	while (1) {
		int n = poll(ufds, nfds, timeout);
		if (n >= 0)
			return n;
		/* Make sure we inch towards completion */
		if (timeout > 0)
			timeout--;
		/* E.g. strace causes poll to return this */
		if (errno == EINTR)
			continue;
		/* Kernel is very low on memory. Retry. */
		/* I doubt many callers would handle this correctly! */
		if (errno == ENOMEM)
			continue;
		perror("poll");
		return n;
	}
}

len_and_sockaddr* str2sockaddr(
		const char *host, int port,
		sa_family_t af,
		int ai_flags)
{
	int rc;
	len_and_sockaddr *r;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	const char *org_host = host; /* only for error msg */
	const char *cp;
	struct addrinfo hint;

	if (is_prefixed_with(host, "local:")) {
		struct sockaddr_un *sun;

		r = calloc(1, LSA_LEN_SIZE + sizeof(struct sockaddr_un));
		if (!r)
			return NULL;

		r->len = sizeof(struct sockaddr_un);
		r->u.sa.sa_family = AF_UNIX;
		sun = (struct sockaddr_un *)&r->u.sa;
		safe_strncpy(sun->sun_path, host + 6, sizeof(sun->sun_path));
		return r;
	}

	r = NULL;

	/* Ugly parsing of host:addr */
	if (host[0] == '[') {
		/* Even uglier parsing of [xx]:nn */
		host++;
		cp = strchr(host, ']');
		if (!cp || (cp[1] != ':' && cp[1] != '\0')) {
			/* Malformed: must be [xx]:nn or [xx] */
			fprintf(stderr, "bad address '%s'\n", org_host);
			return NULL;
		}
	} else {
		cp = strrchr(host, ':');
		if (cp && strchr(host, ':') != cp) {
			/* There is more than one ':' (e.g. "::1") */
			cp = NULL; /* it's not a port spec */
		}
	}
	if (cp) { /* points to ":" or "]:" */
		int sz = cp - host + 1;

		host = safe_strncpy(alloca(sz), host, sz);
		if (*cp != ':') {
			cp++; /* skip ']' */
			if (*cp == '\0') /* [xx] without port */
				goto skip;
		}
		cp++; /* skip ':' */
		port = strtoul(cp, NULL, 10);
		if (errno || (unsigned)port > 0xffff) {
			fprintf(stderr, "bad port spec '%s'\n", org_host);
			return NULL;
		}
 skip: ;
	}

	/* Next two if blocks allow to skip getaddrinfo()
	 * in case host name is a numeric IP(v6) address.
	 * getaddrinfo() initializes DNS resolution machinery,
	 * scans network config and such - tens of syscalls.
	 */
	/* If we were not asked specifically for IPv6,
	 * check whether this is a numeric IPv4 */
	if(af != AF_INET6) {
		struct in_addr in4;
		if (inet_aton(host, &in4) != 0) {
			r = calloc(1, LSA_LEN_SIZE + sizeof(struct sockaddr_in));
			if (!r)
				return NULL;
			r->len = sizeof(struct sockaddr_in);
			r->u.sa.sa_family = AF_INET;
			r->u.sin.sin_addr = in4;
			goto set_port;
		}
	}

	/* If we were not asked specifically for IPv4,
	 * check whether this is a numeric IPv6 */
	if (af != AF_INET) {
		struct in6_addr in6;
		if (inet_pton(AF_INET6, host, &in6) > 0) {
			r = calloc(1, LSA_LEN_SIZE + sizeof(struct sockaddr_in6));
			if (!r)
				return NULL;
			r->len = sizeof(struct sockaddr_in6);
			r->u.sa.sa_family = AF_INET6;
			r->u.sin6.sin6_addr = in6;
			goto set_port;
		}
	}

	memset(&hint, 0 , sizeof(hint));
	hint.ai_family = af;
	/* Need SOCK_STREAM, or else we get each address thrice (or more)
	 * for each possible socket type (tcp,udp,raw...): */
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = ai_flags;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		fprintf(stderr, "bad address '%s'\n", org_host);
		goto ret;
	}
	used_res = result;

	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			break;
		}
	}

	r = malloc(LSA_LEN_SIZE + used_res->ai_addrlen);
	if (!r)
		return NULL;
	r->len = used_res->ai_addrlen;
	memcpy(&r->u.sa, used_res->ai_addr, used_res->ai_addrlen);

set_port:
	set_nport(&r->u.sa, htons(port));
ret:
	if (result)
		freeaddrinfo(result);
	return r;
}

char* is_prefixed_with(const char *string, const char *key)
{
	while (*key != '\0') {
		if (*key != *string)
			return NULL;
		key++;
		string++;
	}
	return (char*)string;
}

void setsockopt_reuseaddr(int fd)
{
	int optval = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
}

const char* nth_string(const char *strings, int n)
{
	while (n) {
		if (*strings++ == '\0') {
			if (*strings == '\0') /* reached end of strings */
				break;
			n--;
		}
	}
	return strings;
}

ssize_t safe_write(int fd, const void *buf, size_t count)
{
	ssize_t n;

	for (;;) {
		n = write(fd, buf, count);
		if (n >= 0 || errno != EINTR)
			break;
		/* Some callers set errno=0, are upset when they see EINTR.
		 * Returning EINTR is wrong since we retry write(),
		 * the "error" was transient.
		 */
		errno = 0;
		/* repeat the write() */
	}

	return n;
}

ssize_t full_write(int fd, const void *buf, size_t len)
{
	ssize_t cc;
	ssize_t total;

	total = 0;

	while (len) {
		cc = safe_write(fd, buf, len);

		if (cc < 0) {
			if (total) {
				/* we already wrote some! */
				/* user can do another write to know the error code */
				return total;
			}
			return cc;  /* write() returns -1 on failure. */
		}

		total += cc;
		buf = ((const char *)buf) + cc;
		len -= cc;
	}

	return total;
}

/* Return port number for a service.
 * If "port" is a number use it as the port.
 * If "port" is a name it is looked up in /etc/services,
 * if it isnt found return default_port
 */
unsigned bb_lookup_port(const char *port, const char *protocol, unsigned default_port)
{
	unsigned port_nr = default_port;
	if (port) {
		int old_errno;

		/* Since this is a lib function, we're not allowed to reset errno to 0.
		 * Doing so could break an app that is deferring checking of errno. */
		old_errno = errno;
		port_nr = strtoul(port, NULL, 10);
		if (errno || port_nr > 65535) {
			struct servent *tserv = getservbyname(port, protocol);
			port_nr = default_port;
			if (tserv)
				port_nr = ntohs(tserv->s_port);
//FIXME: else: port string was garbage, but we don't report that???
		}
		errno = old_errno;
	}
	return (uint16_t)port_nr;
}

void set_nport(struct sockaddr *sa, unsigned port)
{
	if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (void*) sa;
		sin6->sin6_port = port;
		return;
	}
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void*) sa;
		sin->sin_port = port;
		return;
	}
	/* What? UNIX socket? IPX?? :) */
}
