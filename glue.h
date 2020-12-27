#ifndef GLUE_H_
#define GLUE_H_

int tftp_open(const char *tftpserv, const char *remote_path);
int tftp_get_tsize(const char *tftpserv, const char *remote_path);

#endif
