/*
  Copyright (C) 2020       Ahmad Fatoum <ahmad@a3f.at>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#define _XOPEN_SOURCE 700

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include "tftp.h"
#include "glue.h"

int tftp_open(const char *remote_path)
{
	char fname[] = "/tmp/tftp-fuse.XXXXXX";
	int fd, ret;

	fd = mkstemp(fname);
	if (fd < 0)
		return -errno;

	unlink(fname);

	ret = do_tftp("localhost", remote_path, fd, 0);
	if (ret < 0) {
		close(fd);
		return ret;
	}

	return fd;
}
