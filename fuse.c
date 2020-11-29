/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>
  Copyright (C) 2020       Ahmad Fatoum <ahmad@a3f.at>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

#define FUSE_USE_VERSION 31

#define _GNU_SOURCE

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

#include "glue.h"

static inline int64_t xmp_xlate(int64_t ret)
{
	if (ret == -1)
		return -errno;

	return ret;
}

static void *xmp_init(struct fuse_conn_info *conn,
		      struct fuse_config *cfg)
{
	(void) conn;
	cfg->use_ino = 1;

	/* Pick up changes from lower filesystem right away. This is
	   also necessary for better hardlink support. When the kernel
	   calls the unlink() handler, it does not know the inode of
	   the to-be-removed entry and can therefore not invalidate
	   the cache of the associated inode - resulting in an
	   incorrect st_nlink value being reported for any remaining
	   hardlinks to this inode. */
	cfg->entry_timeout = 0;
	cfg->attr_timeout = 0;
	cfg->negative_timeout = 0;

	return NULL;
}

static int xmp_getattr(const char *path, struct stat *stbuf,
		       struct fuse_file_info *fi)
{
	(void) fi;
	int ret, fd;

	ret = lstat(path, stbuf);
	if (ret == 0)
		return 0;

	if (ret == -1 && errno != ENOENT)
		return -errno;

	fd = tftp_open(path);
	if (fd < 0)
		return fd;

	ret = fstat(fd, stbuf);
	close(fd);
	return xmp_xlate(ret);
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int ret;

	ret = readlink(path, buf, size - 1);
	if (ret >= 0) {
		buf[ret] = '\0';
		return 0;
	}

	if (ret == -1 && errno != ENOENT)
		return -errno;

	/* FIXME breaks users that use readlink to check for existance */
	return -EINVAL;
}

static int xmp_create(const char *path, mode_t mode,
		      struct fuse_file_info *fi)
{
	return -EROFS;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int fd;

	if (fi->flags & O_WRONLY)
		return -EROFS;

	fd = open(path, fi->flags);
	if (fd >= 0)
		goto success;

	if (fd == -1 && errno != ENOENT)
		return -errno;

	fd = tftp_open(path);
	if (fd < 0)
		return fd;
success:
	fi->fh = fd;
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	(void)path;
	(void)fi;

	return xmp_xlate(pread(fi->fh, buf, size, offset));
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void)path;

	return -EPERM;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	(void) path;

	return xmp_xlate(close(fi->fh));
}

static off_t xmp_lseek(const char *path, off_t off, int whence, struct fuse_file_info *fi)
{
	(void)path;

	return xmp_xlate(lseek(fi->fh, off, whence));
}

static const struct fuse_operations xmp_oper = {
	.init           = xmp_init,
	.getattr	= xmp_getattr,
	.readlink	= xmp_readlink,
	.create		= xmp_create,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.release	= xmp_release,
	.lseek		= xmp_lseek,
};

int main(int argc, char *argv[])
{
	/* Don't mask creation mode, kernel already did that */
	umask(0);
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
