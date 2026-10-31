# syntax=docker/dockerfile:1

# ---- Build stage ----
FROM alpine:3.20 AS builder

RUN apk add --no-cache \
        gcc \
        musl-dev \
        make \
        readline-dev \
        libcap-dev \
        libjpeg-turbo-dev \
        openssl-dev \
        openssl-libs-static \
        readline-static \
        libjpeg-turbo-static \
        libcap-static \
        ncurses-static \
        zlib-static

WORKDIR /build

COPY makefile ./makefile
COPY src ./src

# Build arguments mirror the makefile toggles.
ARG USE_OPENSSL=0
ARG USE_VNCSNAPSHOT=0

# Static link so the runtime image needs no shared libraries.
# musl is stricter than glibc about transitive includes: readline.h does not
# pull in <stdio.h> and <sys/socket.h> does not pull in <sys/time.h>.
# Force-include both to keep the upstream source untouched.
# Static readline also needs ncurses (tputs) explicitly, since the linker
# cannot resolve it transitively as it does in a dynamic build.
RUN make USE_OPENSSL=${USE_OPENSSL} USE_VNCSNAPSHOT=${USE_VNCSNAPSHOT} \
        CFLAGS="-g -Wall -pthread -include stdio.h -include sys/time.h" \
        LDFLAGS="-static" \
        LDLIBS="-lcap -lreadline -lncurses -ljpeg -pthread" \
    && strip vncsnatch

# ---- Runtime stage ----
# The binary is fully static, so the runtime image only needs the scanner
# itself. The tools/generate_csv.py helper is a dev-time utility and is run on
# the host with python3, not inside this image.
FROM alpine:3.20 AS runtime

# curl + CA certs download the IP-to-country database; gzip handles compressed
# sources; envsubst (gettext) expands ${VAR} API tokens in custom URLs.
RUN apk add --no-cache curl ca-certificates gzip gettext

COPY --from=builder /build/vncsnatch /usr/local/bin/vncsnatch
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/vncsnatch

# Run as an unprivileged user. /data is owned by it so the bind mount is
# writable. The ICMP fast-path still needs CAP_NET_RAW (cap_add=NET_RAW);
# without it the scanner falls back to TCP connect checks, which need no
# privileges, so the container is useful even as a plain non-root user.
RUN addgroup -S -g 1000 vnc \
    && adduser -S -u 1000 -G vnc -h /data vnc \
    && mkdir -p /data \
    && chown -R vnc:vnc /data
USER vnc

# Default output and working directory are bind-mount friendly.
WORKDIR /data
VOLUME ["/data"]

# The scanner runs to completion rather than serving, so the health check just
# confirms the binary is present and runnable (and its deps resolve).
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD vncsnatch --help >/dev/null 2>&1 || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
