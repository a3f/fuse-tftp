project('tftp', 'c', license: 'GPL-2.0', version: '0.001')
libtftp_src = ['libtftp.c', 'libbb.c']

libtftp = static_library('tftp', ['libtftp.c', 'libbb.c'])
tftp = executable('tftp', 'tftp_main.c', link_with: libtftp)

libfuse3 = dependency('fuse3')

executable('tftpfs', 'fuse.c', dependencies: libfuse3)
