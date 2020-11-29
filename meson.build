project('tftp', 'c', license: 'GPL-2.0', version: '0.001')
libtftp_src = ['libtftp.c', 'libbb.c']

libtftp = static_library('tftp', ['libtftp.c', 'libbb.c'])
tftp = executable('tftp', 'tftp_main.c', link_with: libtftp)

libfuse3 = dependency('fuse3')

fuse_src = [ 'fuse.c', 'glue.c' ]

executable('tftpfs', fuse_src, dependencies: libfuse3, link_with: libtftp, install: true)
