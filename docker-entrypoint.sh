#!/bin/sh
# Entrypoint for the vncsnatch container.
#
# If no IP2Location CSV is supplied with -f/--file, download an IP-to-country
# database and pass it to vncsnatch. The parser reads several public layouts
# directly (from,to,CC and CIDR,...,CC,...), so no conversion is needed. The
# file is cached under /data and reused across runs; refresh with DB_REFRESH=1.
#
# Environment variables:
#   DB_URL        Replace the entire source list (space/newline-separated).
#                 Use this where the default hosts are blocked (e.g. behind a
#                 regional firewall) to point at your own mirror.
#   DB_URL_EXTRA  Prepend extra sources to the default list (tried first), so
#                 you add a preferred mirror without losing the fallbacks.
#   DB_HEADER     Extra HTTP header sent with every request, for providers that
#                 require an API key, e.g. "Authorization: Bearer <key>".
#                 Values support ${VAR} expansion from the environment.
#   DB_CACHE         Cache path (default /data/ip-country.csv).
#   DB_REFRESH=1     Force re-download even if the cache exists.
#   DB_MAX_AGE_DAYS  Re-download when the cache is older than this many days
#                    (default 7; 0 = never expire, keep the cache forever).
#   DB_AUTO_REFRESH  Set to 1 to run a background refresher during a scan that
#                    re-checks the cache age on an interval and refreshes it.
#   DB_REFRESH_INTERVAL  Background refresher interval in seconds (default
#                    86400 = daily). Only matters with DB_AUTO_REFRESH=1.
#   DB_OUTPUT_DIR Output dir injected as -O when the caller gives none
#                 (default /data/output); set empty to disable.
#
# The scanner can also be driven entirely from the environment (handy with a
# compose "environment:" block). Each flag has a dedicated variable; anything
# given on the command line overrides it:
#   VNC_COUNTRY (-c)        VNC_FILE (-f)            VNC_WORKERS (-w)
#   VNC_TIMEOUT (-t)        VNC_PORTS (-p)           VNC_RATE (-R)
#   VNC_PASSWORD (-P)       VNC_PASSWORD_FILE (-F)   VNC_OUTPUT_DIR (-O)
#   VNC_ALLOW_CIDR (-A)     VNC_DENY_CIDR (-D)       VNC_DELAY_ATTEMPTS (-T)
#   VNC_RESULTS (-o)        VNC_QUALITY (-Q)         VNC_RECT (-x)
#   VNC_RESUME=1 (-r)       VNC_VERBOSE=1 (-v)       VNC_QUIET=1 (-q)
#   VNC_ALLOWBLANK=1 (-b)   VNC_ARGS (free-form extra flags)
#
# All variable values are expanded, so secrets can be passed separately, e.g.
#   -e IP2LOCATION_TOKEN=abc \
#   -e DB_URL='https://www.ip2location.com/download/?token=${IP2LOCATION_TOKEN}&file=DB1LITECSV'
set -eu

# When routed through the Tor gateway (docker-compose.tor.yml), DNS must resolve
# via the gateway's local forwarder. Docker forbids setting `dns:` under
# network_mode: service:*, and a NAT redirect of UDP/53 is unreliable on some
# runtimes (Docker Desktop), so the overlay sets VNC_RESOLV=127.0.0.1 and we
# write resolv.conf directly here. Requires running as root (the overlay does).
if [ -n "${VNC_RESOLV:-}" ]; then
    if printf 'nameserver %s\n' "$VNC_RESOLV" > /etc/resolv.conf 2>/dev/null; then
        echo "vncsnatch: resolv.conf set to $VNC_RESOLV (Tor DNS)" >&2
    else
        echo "vncsnatch: WARNING could not write /etc/resolv.conf (need root)" >&2
    fi
fi

# Default sources: a mix of repos, providers and hosts so no single outage is
# fatal. The parser reads all of these layouts directly:
#   sapics/ip-location-db  -> from,to,CC          (GeoLite2 and DB-IP)
#   datasets/geoip2-ipv4   -> CIDR,...,CC,Country (independent repo)
# Each GitHub repo is also offered via the jsDelivr CDN as a host fallback.
DEFAULT_DB_URL="https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-country/geolite2-country-ipv4.csv
https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/geolite2-country/geolite2-country-ipv4.csv
https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-country/dbip-country-ipv4.csv
https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/dbip-country/dbip-country-ipv4.csv
https://raw.githubusercontent.com/datasets/geoip2-ipv4/main/data/geoip2-ipv4.csv
https://cdn.jsdelivr.net/gh/datasets/geoip2-ipv4@main/data/geoip2-ipv4.csv"

# Expand only ${VAR} references (via envsubst), never command substitution, so
# an API token in a URL is filled from the environment safely.
expand_vars() {
    if command -v envsubst >/dev/null 2>&1; then
        printf '%s' "$1" | envsubst
    else
        printf '%s' "$1"
    fi
}

# ASN database sources (from,to,ASN,"Org"), used for --mode asn/both. Same
# provider/host mix as the country list. Override with ASN_DB_URL / extend with
# ASN_DB_URL_EXTRA, mirroring DB_URL / DB_URL_EXTRA.
DEFAULT_ASN_DB_URL="https://raw.githubusercontent.com/sapics/ip-location-db/main/geolite2-asn/geolite2-asn-ipv4.csv
https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/geolite2-asn/geolite2-asn-ipv4.csv
https://raw.githubusercontent.com/sapics/ip-location-db/main/dbip-asn/dbip-asn-ipv4.csv
https://cdn.jsdelivr.net/gh/sapics/ip-location-db@main/dbip-asn/dbip-asn-ipv4.csv"

# DB_URL replaces the list; DB_URL_EXTRA prepends to it.
DB_URL="$(expand_vars "${DB_URL:-$DEFAULT_DB_URL}")"
if [ -n "${DB_URL_EXTRA:-}" ]; then
    DB_URL="$(expand_vars "$DB_URL_EXTRA")
$DB_URL"
fi
DB_CACHE="${DB_CACHE:-/data/ip-country.csv}"

ASN_DB_URL="$(expand_vars "${ASN_DB_URL:-$DEFAULT_ASN_DB_URL}")"
if [ -n "${ASN_DB_URL_EXTRA:-}" ]; then
    ASN_DB_URL="$(expand_vars "$ASN_DB_URL_EXTRA")
$ASN_DB_URL"
fi
ASN_DB_CACHE="${ASN_DB_CACHE:-/data/ip-asn.csv}"

# Map VNC_* environment variables to CLI flags so the scanner can be driven
# entirely from a compose "environment:" block. Flags given on the command line
# take precedence (they are appended after these, and getopt keeps the last
# value). VNC_ARGS is a free-form string of extra flags for anything without a
# dedicated variable. Only applied to a normal scan, not to fetch-db/--help.
add_flag() {
    [ -n "$2" ] && env_args="$env_args $1 $2"
    return 0
}
build_env_args() {
    env_args=""
    add_flag -c "${VNC_COUNTRY:-}"
    add_flag -f "${VNC_FILE:-}"
    add_flag --mode "${VNC_MODE:-}"
    add_flag --asn "${VNC_ASN:-}"
    add_flag --asn-file "${VNC_ASN_FILE:-}"
    add_flag -w "${VNC_WORKERS:-}"
    add_flag -t "${VNC_TIMEOUT:-}"
    add_flag -p "${VNC_PORTS:-}"
    add_flag -R "${VNC_RATE:-}"
    add_flag -P "${VNC_PASSWORD:-}"
    add_flag -F "${VNC_PASSWORD_FILE:-}"
    add_flag -O "${VNC_OUTPUT_DIR:-}"
    add_flag -A "${VNC_ALLOW_CIDR:-}"
    add_flag -D "${VNC_DENY_CIDR:-}"
    add_flag -T "${VNC_DELAY_ATTEMPTS:-}"
    add_flag -o "${VNC_RESULTS:-}"
    add_flag -Q "${VNC_QUALITY:-}"
    add_flag -x "${VNC_RECT:-}"
    [ "${VNC_RESUME:-0}" = "1" ] && env_args="$env_args -r"
    [ "${VNC_VERBOSE:-0}" = "1" ] && env_args="$env_args -v"
    [ "${VNC_QUIET:-0}" = "1" ] && env_args="$env_args -q"
    [ "${VNC_ALLOWBLANK:-0}" = "1" ] && env_args="$env_args -b"
    [ -n "${VNC_ARGS:-}" ] && env_args="$env_args ${VNC_ARGS}"
    printf '%s' "$env_args"
}

# Prepend env-derived flags to the command line (word-split intentional).
ENV_ARGS="$(build_env_args)"
if [ -n "$ENV_ARGS" ] && [ "${1:-}" != "fetch-db" ]; then
    case "${1:-}" in
        -h|--help) ;;  # leave help alone
        *) set -- $ENV_ARGS "$@" ;;
    esac
fi

# Detect whether the caller already provided a CSV path, an output dir, an ASN
# database path, and which target mode is active.
has_file=0
has_outdir=0
has_asnfile=0
scan_mode="country"
prev=""
for arg in "$@"; do
    case "$arg" in
        -f|--file|-f*|--file=*) has_file=1 ;;
        -O|--output-dir|-O*|--output-dir=*) has_outdir=1 ;;
        -M|--metadata-dir|-M*|--metadata-dir=*) has_outdir=1 ;;
        --asn-file|--asn-file=*) has_asnfile=1 ;;
        --mode=*) scan_mode="${arg#--mode=}" ;;
    esac
    [ "$prev" = "--mode" ] && scan_mode="$arg"
    prev="$arg"
done

# Keep all output (screenshots, metadata, results) on the mounted volume by
# defaulting the output directory to /data/output when the caller gives none.
# DB_OUTPUT_DIR overrides the target; set it empty to disable the injection.
OUTPUT_DIR="${DB_OUTPUT_DIR-/data/output}"

# Download a single URL to a temp file. Returns 0 only on a non-empty result.
# Honours DB_HEADER (e.g. an API-key auth header) and transparently gunzips a
# gzip-compressed response so .csv.gz sources work too.
fetch_one() {
    url="$1"
    dst="$2"
    if command -v curl >/dev/null 2>&1; then
        if [ -n "${DB_HEADER:-}" ]; then
            curl -fSL --retry 2 --connect-timeout 15 -H "$DB_HEADER" \
                -o "$dst" "$url" || return 1
        else
            curl -fSL --retry 2 --connect-timeout 15 -o "$dst" "$url" || return 1
        fi
    else
        if [ -n "${DB_HEADER:-}" ]; then
            wget --header="$DB_HEADER" -O "$dst" "$url" || return 1
        else
            wget -O "$dst" "$url" || return 1
        fi
    fi
    [ -s "$dst" ] || return 1
    # Transparently decompress a gzip payload (magic bytes 1f 8b).
    if [ "$(head -c 2 "$dst" | od -An -tx1 | tr -d ' \n')" = "1f8b" ]; then
        gzip -dc "$dst" > "${dst}.un" 2>/dev/null && mv "${dst}.un" "$dst" || {
            rm -f "${dst}.un"
            return 1
        }
    fi
    [ -s "$dst" ]
}

# Age of a file in whole days, or a large number if it does not exist.
file_age_days() {
    if [ ! -f "$1" ]; then
        echo 999999
        return
    fi
    now=$(date +%s)
    mtime=$(date -r "$1" +%s 2>/dev/null || stat -c %Y "$1" 2>/dev/null || echo "$now")
    echo $(( (now - mtime) / 86400 ))
}

# download_db <cache-path> <url-list> <label>
# Reuse the cached file unless missing, DB_REFRESH=1, or older than
# DB_MAX_AGE_DAYS (default 7; 0 = never expire). A refresh downloads to a temp
# file and atomically swaps it in, so a failed download keeps the old copy.
download_db() {
    cache="$1"
    urls="$2"
    label="$3"
    max_age="${DB_MAX_AGE_DAYS:-7}"
    if [ "${DB_REFRESH:-0}" != "1" ] && [ -s "$cache" ]; then
        age="$(file_age_days "$cache")"
        if [ "$max_age" = "0" ] || [ "$age" -lt "$max_age" ]; then
            echo "vncsnatch: using cached $label $cache (age ${age}d, max ${max_age}d)" >&2
            return 0
        fi
        echo "vncsnatch: cached $label is ${age}d old (>= ${max_age}d), refreshing..." >&2
    fi

    echo "vncsnatch: fetching $label..." >&2
    tmp="${cache}.tmp.$$"
    for url in $urls; do
        echo "  trying: $url" >&2
        if fetch_one "$url" "$tmp"; then
            mv -f "$tmp" "$cache"   # atomic replace of the previous database
            echo "  saved: $cache" >&2
            return 0
        fi
        rm -f "$tmp"
    done

    rm -f "$tmp"
    if [ -s "$cache" ]; then
        echo "vncsnatch: download failed; keeping existing $label $cache" >&2
        return 0
    fi
    echo "vncsnatch: could not download $label from any source." >&2
    return 1
}

# Country database (default target).
maybe_download() {
    download_db "$DB_CACHE" "$DB_URL" "IP-to-country database"
}

# ASN database (for --mode asn/both).
maybe_download_asn() {
    download_db "$ASN_DB_CACHE" "$ASN_DB_URL" "ASN database"
}

# Background refresher: while a long scan runs, periodically re-check the cache
# age and refresh it safely (download to temp, atomic swap, old file replaced
# only on success). Enabled with DB_AUTO_REFRESH=1; the check interval is
# DB_REFRESH_INTERVAL seconds (default 86400 = daily). Low overhead: it sleeps
# between checks and only downloads when the cache has actually aged out.
start_background_refresher() {
    [ "${DB_AUTO_REFRESH:-0}" = "1" ] || return 0
    interval="${DB_REFRESH_INTERVAL:-86400}"
    (
        while true; do
            sleep "$interval" || break
            # maybe_download is a no-op unless the cache is older than max age.
            maybe_download >/dev/null 2>&1 || true
        done
    ) &
    echo "vncsnatch: background db refresher on (every ${interval}s, max age ${DB_MAX_AGE_DAYS:-7}d)" >&2
}

# "fetch-db" downloads the database(s) and exits without scanning. It honours
# the cache TTL, so it is safe to call periodically (e.g. host cron); add
# "force" to download unconditionally, and "asn" to fetch the ASN database.
# Useful for pre-seeding and CI.
if [ "${1:-}" = "fetch-db" ]; then
    want_force=0
    want_asn=0
    for a in "$@"; do
        [ "$a" = "force" ] && want_force=1
        [ "$a" = "asn" ] && want_asn=1
    done
    rc=0
    if [ "$want_asn" -eq 1 ]; then
        if [ "$want_force" -eq 1 ]; then DB_REFRESH=1 maybe_download_asn; else maybe_download_asn; fi
        rc=$?
    else
        if [ "$want_force" -eq 1 ]; then DB_REFRESH=1 maybe_download; else maybe_download; fi
        rc=$?
    fi
    exit $rc
fi

# --help/-h or no args: run vncsnatch untouched (no download, no output dir).
if [ "$#" -eq 0 ]; then
    exec vncsnatch
fi
case "$1" in
    -h|--help) exec vncsnatch "$@" ;;
esac

# Build the argument list, injecting -O /data/output when the caller gave no
# output directory so results land on the mounted volume.
set -- "$@"
if [ "$has_outdir" -eq 0 ] && [ -n "$OUTPUT_DIR" ]; then
    set -- -O "$OUTPUT_DIR" "$@"
fi

# For ASN / both modes, provision the ASN database and inject --asn-file when
# the caller gave none.
case "$scan_mode" in
    asn|both)
        if [ "$has_asnfile" -eq 0 ]; then
            maybe_download_asn
            set -- "$@" --asn-file "$ASN_DB_CACHE"
        fi
        ;;
esac

# Auto-download the country database unless one was supplied, or the mode is
# asn-only (which needs no country database).
if [ "$has_file" -eq 0 ] && [ "$scan_mode" != "asn" ]; then
    maybe_download
    set -- -f "$DB_CACHE" "$@"
fi

start_background_refresher
exec vncsnatch "$@"
