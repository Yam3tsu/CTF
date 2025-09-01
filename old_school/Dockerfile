FROM archlinux@sha256:5b1b7713182110aee0829fa9cc0571c451b391f0ad2bbafcf7a4ba907ee72ec3 AS chroot

COPY playground /app/run
COPY libc.so.6 /app/libc.so.6
COPY ld-linux-x86-64.so.2 /app/ld-linux-x86-64.so.2

FROM ghcr.io/madrhacks/jail:latest

COPY --from=chroot / /srv

ENV FLAG_PATH=/app/flag
ENV ENV_GLIBC_TUNABLES=glibc.malloc.mmap_max=0:glibc.malloc.tcache_count=0:glibc.malloc.tcache_max=0
ENV TIMEOUT=240
