#ifndef TFTP_H_

#define TFTP_FLAG_VERBOSE	1
#define TFTP_FLAG_QUERY_TSIZE	2

int do_tftp(const char *addr,
	    const char *remote, int local_d,
	    int flags);

#endif
