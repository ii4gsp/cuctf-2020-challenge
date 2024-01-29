#!/bin/sh

qemu-system-x86_64 \
    -m 2G \
    -nographic \
    -kernel "./bzImage" \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic=-1 pti=on nosmap kaslr min_addr=4096" \
    -no-reboot \
    -cpu qemu64,+smep \
    -monitor /dev/null \
    -initrd "./initramfs.cpio" \
    -smp 2\
    -smp cores=2 \
    -smp threads=1 \
    -s \
