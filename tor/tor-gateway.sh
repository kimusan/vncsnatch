#!/bin/sh
# Transparent Tor gateway: start tor, then redirect all TCP + DNS from this
# network namespace through it with iptables. Processes running as the tor user
# are exempted so tor's own traffic can leave. TCP-only; other non-DNS, non-TCP
# traffic is rejected.
set -eu

TRANS_PORT=9040
DNS_PORT=53          # dnsmasq listens here; forwards to tor's DNSPort (9053)
TOR_UID="$(id -u tor)"

# Only loopback is exempt from Tor. RFC1918 is deliberately NOT exempt: the
# upstream DNS resolver and scan targets may live in private ranges, and they
# must still exit via Tor rather than leak directly. DNS (below) is redirected
# before any address match, so name resolution always goes through Tor too.
NON_TOR="127.0.0.0/8"

echo "tor-gateway: starting tor..." >&2
tor -f /etc/tor/torrc &
tor_pid=$!

# Wait for the SOCKS port to accept connections (tor bootstrapped enough).
echo "tor-gateway: waiting for tor to bootstrap..." >&2
i=0
while [ "$i" -lt 60 ]; do
    if curl -s --socks5 127.0.0.1:9050 --max-time 5 \
            https://check.torproject.org/api/ip 2>/dev/null | grep -q IsTor; then
        break
    fi
    kill -0 "$tor_pid" 2>/dev/null || { echo "tor-gateway: tor exited early" >&2; exit 1; }
    i=$((i + 1))
    sleep 2
done

# Start the local DNS forwarder (dnsmasq :53 -> tor DNSPort 127.0.0.1:9053).
echo "tor-gateway: starting dnsmasq DNS forwarder..." >&2
dnsmasq -C /etc/dnsmasq.conf
# dnsmasq runs as root here, so exempt root-owned DNS in nat below is not
# needed; dnsmasq forwards to tor over loopback.

echo "tor-gateway: installing iptables redirect rules..." >&2
iptables -F
iptables -t nat -F

# Block IPv6 entirely so nothing can leak outside Tor over v6 (Tor transparent
# routing here is IPv4-only). Ignore failures if ip6tables is unavailable.
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -F 2>/dev/null || true
    ip6tables -P OUTPUT DROP 2>/dev/null || true
    ip6tables -P INPUT DROP 2>/dev/null || true
    ip6tables -P FORWARD DROP 2>/dev/null || true
fi

# NAT: let tor's own traffic out untouched; redirect DNS and TCP into tor.
iptables -t nat -A OUTPUT -m owner --uid-owner "$TOR_UID" -j RETURN
# The scanner cannot set `dns:` under this network mode, so its lookups go to
# whatever resolver its resolv.conf names. Capture all DNS (UDP+TCP :53),
# wherever addressed, and send it to tor's DNSPort before any net match.
iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports "$DNS_PORT"
for net in $NON_TOR; do
    iptables -t nat -A OUTPUT -d "$net" -j RETURN
done
iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports "$TRANS_PORT"

# Filter: allow loopback, tor user, and already-redirected traffic. Packets
# REDIRECTed in nat now target local tor ports (loopback), so the loopback
# accept covers them; established/related covers the return path. Everything
# else is rejected so nothing leaks outside Tor.
iptables -A OUTPUT -m owner --uid-owner "$TOR_UID" -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp --dport "$DNS_PORT" -j ACCEPT
iptables -A OUTPUT -p tcp --dport "$DNS_PORT" -j ACCEPT
iptables -A OUTPUT -p tcp --dport "$TRANS_PORT" -j ACCEPT
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
for net in $NON_TOR; do
    iptables -A OUTPUT -d "$net" -j ACCEPT
done
iptables -A OUTPUT -j REJECT

echo "tor-gateway: ready. All TCP from this namespace now exits via Tor." >&2

# Reap tor; keep the container alive as long as tor runs.
wait "$tor_pid"
