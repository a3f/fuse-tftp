# fuse-tftp

    $ meson build .                       # configure project
    $ ninja -C build                      # build project
    $ ./build/tftp localhost test test    # downloads file test
    $ mkdir /tmp/tftpfs                   # create mountpoint
    $ ./build/tftpfs /tmp/tftpfs          # mount
    $ cp /tmp/tftpfs/test test            # downloads file test
    $ fusermount -u /tmp/tftpfs           # unmount

## How?

The filesystem tries to resolve files in the underlying directory over which
it was mounted. If that fails, it tries to fetch it over TFTP.

Only read access is supported. Listing file isn't possible over TFTP.
Requires the `tsize` (transmission size) extension to be supported by the
server for `stat(2)` to work.

## Why?

Didn't pan out for intended use case. Perhaps it's useful to someone else.

## Dependencies

`meson`, `fuse3`, `libfuse3-dev`, some C99 compiler detected by meson.

## License

Project is based on Busybox' tftp and the passthrough example of libfuse.
Idea inspired by the tftp Filesystem in the barebox bootloader.

This program can be distributed under the terms of the GNU GPLv2.
See the accompanying COPYING file.
