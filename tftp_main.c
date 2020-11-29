#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <fcntl.h>

#include "tftp.h"

static int usage(const char *argv0)
{
	fprintf(stderr, "USAGE: %s [-v] addr remote_file local_file\n", argv0);
	return 1;
}

int main(int argc, char *argv[])
{
	int flags = 0;
	int opt, fd;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
		case 'v':
			flags |= TFTP_FLAG_VERBOSE;
			break;
		default: /* '?' */
			return usage(argv[0]);
		}
	}

	if (argc - optind != 3)
		return usage(argv[0]);

	argv += optind;
	argc -= optind;

	fd = open(argv[2], O_WRONLY | O_TRUNC | O_CREAT, 0644);
	if (fd < 0)
		return fd;

	return do_tftp(argv[0], argv[1], fd, flags);
}
