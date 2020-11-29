#ifndef TFTP_H_

#define TFTP_FLAG_VERBOSE	1

int do_tftp(const char *addr,
	    const char *remote, int local_d,
	    int flags);

#endif
