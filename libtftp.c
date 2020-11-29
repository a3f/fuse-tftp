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
 * Licensed under GPLv2 or later, see file COPYING in this source tree.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <poll.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "tftp.h"

#include "libbb.h"

#define TFTP_BLKSIZE_DEFAULT       512  /* according to RFC 1350, don't change */
/* Was 50 ms but users asked to bump it up a bit */
#define TFTP_TIMEOUT_MS            100
#define TFTP_MAXTIMEOUT_MS        2000
#define TFTP_NUM_RETRIES            12  /* number of backed-off retries */

/* opcodes we support */
#define TFTP_RRQ   1
#define TFTP_WRQ   2
#define TFTP_DATA  3
#define TFTP_ACK   4
#define TFTP_ERROR 5
#define TFTP_OACK  6

/* error codes sent over network (we use only 0, 1, 3 and 8) */
/* generic (error message is included in the packet) */
#define ERR_UNSPEC   0
#define ERR_NOFILE   1
#define ERR_ACCESS   2
/* disk full or allocation exceeded */
#define ERR_WRITE    3
#define ERR_OP       4
#define ERR_BAD_ID   5
#define ERR_EXIST    6
#define ERR_BAD_USER 7
#define ERR_BAD_OPT  8

static const char errcode_str[] =
	"\0"
	"file not found\0"
	"access violation\0"
	"disk full\0"
	"bad operation\0"
	"unknown transfer id\0"
	"file already exists\0"
	"no such user\0"
	"bad option";

static int tftp_xlate_err(int err)
{
	switch (err) {
	case ERR_NOFILE:
		return -ENOENT;
	case ERR_ACCESS:
		return -EACCES;
	case ERR_WRITE:
		return -EDQUOT;
	case ERR_OP:
		return -EINVAL;
	case ERR_EXIST:
		return -EEXIST;
	case ERR_BAD_ID:
		return -EPERM;
	}

	return err;
}

static inline bool is_verbose(int flags)
{
	return flags & TFTP_FLAG_VERBOSE;
}

#define G_error_pkt_reason (error_pkt.payload[3])
#define G_error_pkt_str    ((char*)(error_pkt.payload + 4))

static int tftp_protocol(len_and_sockaddr *peer_lsa,
						 int local_fd, const char * remote_file,
						 int flags)
{
	struct pollfd pfd[1];
#define socket_fd (pfd[0].fd)
	int len;
	int send_len;
	int ret;
	bool finished = 0;
	uint16_t opcode;
	uint16_t block_nr;
	uint16_t recv_blk;
	int retries, waittime_ms;
	int io_bufsize = TFTP_BLKSIZE_DEFAULT + 4;
	char *cp;
	bool first_packet = true;
	struct tftp_packet {
		/* u16 TFTP_ERROR; u16 reason; both network-endian, then error text: */
		uint8_t payload[4 + 32];
	} error_pkt = {0};


	/* Can't use RESERVE_CONFIG_BUFFER here since the allocation
	 * size varies meaning BUFFERS_GO_ON_STACK would fail.
	 *
	 * We must keep the transmit and receive buffers separate
	 * in case we rcv a garbage pkt - we need to rexmit the last pkt.
	 */
	char *xbuf = malloc(io_bufsize);
	if (!xbuf)
		return -ENOMEM;

	char *rbuf = malloc(io_bufsize);
	if (!rbuf) {
		ret = -ENOMEM;
		goto free_bufs;
	}


	socket_fd = socket(peer_lsa->u.sa.sa_family, SOCK_DGRAM, 0);
	if (socket_fd < 0) {
		ret = -errno;
		goto free_bufs;
	}
	setsockopt_reuseaddr(socket_fd);

	/* Examples of network traffic.
	 * Note two cases when ACKs with block# of 0 are sent.
	 *
	 * Download without options:
	 * tftp -> "\0\1FILENAME\0octet\0"
	 *         "\0\3\0\1FILEDATA..." <- tftpd
	 * tftp -> "\0\4\0\1"
	 * ...
	 * Download with option of blksize 16384:
	 * tftp -> "\0\1FILENAME\0octet\0blksize\00016384\0"
	 *         "\0\6blksize\00016384\0" <- tftpd
	 * tftp -> "\0\4\0\0"
	 *         "\0\3\0\1FILEDATA..." <- tftpd
	 * tftp -> "\0\4\0\1"
	 * ...
	 * Upload without options:
	 * tftp -> "\0\2FILENAME\0octet\0"
	 *         "\0\4\0\0" <- tftpd
	 * tftp -> "\0\3\0\1FILEDATA..."
	 *         "\0\4\0\1" <- tftpd
	 * ...
	 * Upload with option of blksize 16384:
	 * tftp -> "\0\2FILENAME\0octet\0blksize\00016384\0"
	 *         "\0\6blksize\00016384\0" <- tftpd
	 * tftp -> "\0\3\0\1FILEDATA..."
	 *         "\0\4\0\1" <- tftpd
	 * ...
	 */
	block_nr = 1;
	cp = xbuf + 2;

	/* tftp */

	/* We can't (and don't really need to) bind the socket:
	 * we don't know from which local IP datagrams will be sent,
	 * but kernel will pick the same IP every time (unless routing
	 * table is changed), thus peer will see dgrams consistently
	 * coming from the same IP.
	 * We would like to connect the socket, but since peer's
	 * UDP code can be less perfect than ours, _peer's_ IP:port
	 * in replies may differ from IP:port we used to send
	 * our first packet. We can connect() only when we get
	 * first reply. */

	/* build opcode */
	opcode = TFTP_RRQ;
	/* add filename and mode */
	/* fill in packet if the filename fits into xbuf */
	len = strlen(remote_file);
	if (len + 3 + sizeof("octet") >= io_bufsize) {
		fprintf(stderr, "remote filename is too long\n");
		ret = -EIO;
		goto close_socket;
	}
	cp = stpcpy(cp, remote_file) + 1;
	/* add "mode" part of the packet */
	cp = stpcpy(cp, "octet") + 1;

	/* First packet is built, so skip packet generation */
	goto send_pkt;

	/* Using mostly goto's - continue/break will be less clear
	 * in where we actually jump to */
	while (1) {
		/* Build ACK or DATA */
		cp = xbuf + 2;
		*((uint16_t*)cp) = htons(block_nr);
		cp += 2;
		block_nr++;
		opcode = TFTP_ACK;
send_pkt:
		/* Send packet */
		*((uint16_t*)xbuf) = htons(opcode); /* fill in opcode part */
		send_len = cp - xbuf;
		/* NB: send_len value is preserved in code below
		 * for potential resend */

		retries = TFTP_NUM_RETRIES;  /* re-initialize */
		waittime_ms = TFTP_TIMEOUT_MS;

send_again:
		if (is_verbose(flags)) {
			fprintf(stderr, "sending %d bytes\n", send_len);
			for (cp = xbuf; cp < &xbuf[send_len]; cp++)
				fprintf(stderr, "%02x ", (unsigned char) *cp);
			fprintf(stderr, "\n");
		}

		ret = sendto(socket_fd, xbuf, send_len, 0, &peer_lsa->u.sa, peer_lsa->len);
		if (ret < 0) {
			ret = -errno;
			goto close_socket;
		}

		/* Was it final ACK? then exit */
		if (finished && (opcode == TFTP_ACK)) {
			ret = 0;
			goto close_socket;
		}

recv_again:
		/* Receive packet */
		/*pfd[0].fd = socket_fd;*/
		pfd[0].events = POLLIN;

		ret = safe_poll(pfd, 1, waittime_ms);
		switch (ret) {
		default:
			goto close_socket;
		case 0:
			retries--;
			if (retries == 0) {
				fprintf(stderr, "timeout\n");
				ret = -ETIMEDOUT;
				goto close_socket; /* no err packet sent */
			}

			/* exponential backoff with limit */
			waittime_ms += waittime_ms/2;
			if (waittime_ms > TFTP_MAXTIMEOUT_MS) {
				waittime_ms = TFTP_MAXTIMEOUT_MS;
			}

			goto send_again; /* resend last sent pkt */
		case 1:
			if (first_packet) {
				/* tftp (not tftpd!) receiving 1st packet */
				first_packet = false;
				len = recvfrom(socket_fd, rbuf, io_bufsize, 0,
							   &peer_lsa->u.sa, &peer_lsa->len);
				/* Our first dgram went to port 69
				 * but reply may come from different one.
				 * Remember and use this new port (and IP) */
				if (len >= 0) {
					ret = connect(socket_fd, &peer_lsa->u.sa, peer_lsa->len);
					if (ret < 0)
						goto close_socket;
				}
			} else {
				/* tftpd, or not the very first packet:
				 * socket is connect()ed, can just read from it. */
				/* Don't full_read()!
				 * This is not TCP, one read == one pkt! */
				len = safe_read(socket_fd, rbuf, io_bufsize);
				if (len < 0)
					goto close_socket;
			}
			if (len < 0) {
				ret = -EIO;
				goto send_read_err_pkt;
			}
			if (len < 4) { /* too small? */
				goto recv_again;
			}
		}

		/* Process recv'ed packet */
		opcode = ntohs( ((uint16_t*)rbuf)[0] );
		recv_blk = ntohs( ((uint16_t*)rbuf)[1] );

		if (is_verbose(flags))
			fprintf(stderr, "received %d bytes: %04x %04x\n", len, opcode, recv_blk);

		if (opcode == TFTP_ERROR) {

			const char *msg = "unknown";

			if (len > 4 && rbuf[4] != '\0') {
				msg = &rbuf[4];
				rbuf[io_bufsize - 1] = '\0'; /* paranoia */
				ret = -EIO;
			} else if (recv_blk <= 8) {
				msg = nth_string(errcode_str, recv_blk);
				ret = tftp_xlate_err(recv_blk);
			}
			fprintf(stderr, "server error: (%u) %s\n", recv_blk, msg);
			goto close_socket;
		}

		/* block_nr is already advanced to next block# we expect
		 * to get / block# we are about to send next time */

		if (opcode == TFTP_DATA) {
			if (recv_blk == block_nr) {
				int sz;
				sz = full_write(local_fd, &rbuf[4], len - 4);
				if (sz != len - 4) {
					strcpy(G_error_pkt_str, "write error");
					G_error_pkt_reason = ERR_WRITE;
					ret = sz;
					goto send_err_pkt;
				}
				if (sz != TFTP_BLKSIZE_DEFAULT) {
					finished = 1;
				}
				continue; /* send ACK */
			}
			/* Disabled to cope with servers with Sorcerer's Apprentice Syndrome */
#if 0
			if (recv_blk == (block_nr - 1)) {
				/* Server lost our TFTP_ACK.  Resend it */
				block_nr = recv_blk;
				continue;
			}
#endif
		}

		/* Awww... recv'd packet is not recognized! */
		goto recv_again;
		/* why recv_again? - rfc1123 says:
		 * "The sender (i.e., the side originating the DATA packets)
		 *  must never resend the current DATA packet on receipt
		 *  of a duplicate ACK".
		 * DATA pkts are resent ONLY on timeout.
		 * Thus "goto send_again" will be a bad mistake above.
		 * See:
		 * http://en.wikipedia.org/wiki/Sorcerer's_Apprentice_Syndrome
		 */
	} /* end of "while (1)" */

close_socket:
	close(socket_fd);

free_bufs:
	free(rbuf);
	free(xbuf);

	if (finished && !ret)
		return 0;

send_read_err_pkt:
	strcpy(G_error_pkt_str, "read error");
send_err_pkt:
	if (G_error_pkt_str[0])
		fprintf(stderr, "%s\n", G_error_pkt_str);

	error_pkt.payload[1] = TFTP_ERROR;
	sendto(socket_fd, error_pkt.payload, 4 + 1 + strlen(G_error_pkt_str), 0,
		   &peer_lsa->u.sa, peer_lsa->len);

	return ret;
}

int do_tftp(const char *addr, const char *remote, int local_fd, int flags)
{
	len_and_sockaddr *peer_lsa;

	int result;
	int port;

	port = bb_lookup_port("69", "udp", 69);
	peer_lsa = str2sockaddr(addr, port, AF_UNSPEC, 0);
	if (!peer_lsa)
		return -EINVAL;

	if (is_verbose(flags))
		fprintf(stderr, "using remote_file '%s', local_file_d '%d'\n",
				remote, local_fd);

	result = tftp_protocol(peer_lsa, local_fd, remote, flags);

	return result;
}
