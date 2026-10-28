# syntax=docker/dockerfile:1
#
# Minimal transparent Tor gateway for vncsnatch. It runs tor with a TransPort
# and DNSPort and installs iptables rules that redirect all TCP (and DNS) from
# the shared network namespace through Tor. vncsnatch joins this namespace with
# network_mode: "service:tor" (see docker-compose.tor.yml), so its scans exit
# via Tor without any application-level proxy support.
#
# This image is self-contained and pinned, rather than depending on an external
# image, so what routes your traffic is auditable here.
FROM alpine:3.20

RUN apk add --no-cache tor iptables curl

COPY torrc /etc/tor/torrc
COPY tor-gateway.sh /usr/local/bin/tor-gateway.sh
RUN chmod +x /usr/local/bin/tor-gateway.sh

# NET_ADMIN (for iptables) is required at run time; see docker-compose.tor.yml.
# Transparent routing is TCP-only; non-TCP traffic other than DNS is dropped.
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 \
    CMD curl -s --socks5 127.0.0.1:9050 https://check.torproject.org/api/ip \
        | grep -q '"IsTor":true' || exit 1

ENTRYPOINT ["tor-gateway.sh"]
