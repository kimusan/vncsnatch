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

# DB_URL replaces the list; DB_URL_EXTRA prepends to it.
DB_URL="$(expand_vars "${DB_URL:-$DEFAULT_DB_URL}")"
if [ -n "${DB_URL_EXTRA:-}" ]; then
    DB_URL="$(expand_vars "$DB_URL_EXTRA")
$DB_URL"
fi
DB_CACHE="${DB_CACHE:-/data/ip-country.csv}"

# Map VNC_* environment variables to CLI flags so the scanner can be driven
# entirely from a compose "environment:" block. Flags given on the command line
# take precedence (they are appended after these, and getopt keeps the last
# value). VNC_ARGS is a free-form string of extra flags for anything without a
# dedicated variable. Only applied to a normal scan, not to fetch-db/--help.
build_env_args() {
    env_args=""
    add() { [ -n "$2" ] && env_args="$env_args $1 $2"; }
    add -c "${VNC_COUNTRY:-}"
    add -f "${VNC_FILE:-}"
    add -w "${VNC_WORKERS:-}"
    add -t "${VNC_TIMEOUT:-}"
    add -p "${VNC_PORTS:-}"
    add -R "${VNC_RATE:-}"
    add -P "${VNC_PASSWORD:-}"
    add -F "${VNC_PASSWORD_FILE:-}"
    add -O "${VNC_OUTPUT_DIR:-}"
    add -A "${VNC_ALLOW_CIDR:-}"
    add -D "${VNC_DENY_CIDR:-}"
    add -T "${VNC_DELAY_ATTEMPTS:-}"
    add -o "${VNC_RESULTS:-}"
    add -Q "${VNC_QUALITY:-}"
    add -x "${VNC_RECT:-}"
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

# Detect whether the caller already provided a CSV path and/or an output dir.
has_file=0
has_outdir=0
for arg in "$@"; do
    case "$arg" in
        -f|--file|-f*|--file=*) has_file=1 ;;
        -O|--output-dir|-O*|--output-dir=*) has_outdir=1 ;;
        -M|--metadata-dir|-M*|--metadata-dir=*) has_outdir=1 ;;
    esac
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

maybe_download() {
    # Reuse the cached database on the volume unless it is missing, a refresh is
    # forced, or it is older than the configured max age (default 7 days).
    # DB_MAX_AGE_DAYS=0 disables the age check (cache never expires).
    max_age="${DB_MAX_AGE_DAYS:-7}"
    if [ "${DB_REFRESH:-0}" != "1" ] && [ -s "$DB_CACHE" ]; then
        age="$(file_age_days "$DB_CACHE")"
        if [ "$max_age" = "0" ] || [ "$age" -lt "$max_age" ]; then
            echo "vncsnatch: using cached database $DB_CACHE (age ${age}d, max ${max_age}d)" >&2
            return 0
        fi
        echo "vncsnatch: cached database is ${age}d old (>= ${max_age}d), refreshing..." >&2
    fi

    echo "vncsnatch: fetching IP-to-country database..." >&2
    tmp="${DB_CACHE}.tmp.$$"
    # Download into a temp file first so the existing cache stays intact until a
    # new copy is fully in hand. Only once a source succeeds do we swap it in and
    # drop the old file; if every source fails the old cache is left untouched.
    for url in $DB_URL; do
        echo "  trying: $url" >&2
        if fetch_one "$url" "$tmp"; then
            mv -f "$tmp" "$DB_CACHE"   # atomic replace of the previous database
            echo "  saved: $DB_CACHE" >&2
            return 0
        fi
        rm -f "$tmp"
    done

    rm -f "$tmp"
    if [ -s "$DB_CACHE" ]; then
        echo "vncsnatch: download failed; keeping existing cache $DB_CACHE" >&2
        return 0
    fi
    echo "vncsnatch: could not download a database from any source." >&2
    echo "  set DB_URL to a reachable CSV, or pass -f /data/<file>.csv" >&2
    return 1
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

# "fetch-db" downloads the database and exits without scanning. It honours the
# cache TTL, so it is safe to call periodically (e.g. from host cron); add
# "force" to download unconditionally. Useful for pre-seeding and CI.
if [ "${1:-}" = "fetch-db" ]; then
    if [ "${2:-}" = "force" ]; then
        DB_REFRESH=1 maybe_download
    else
        maybe_download
    fi
    exit $?
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

# Auto-download a database when none was supplied with -f/--file.
if [ "$has_file" -eq 0 ]; then
    maybe_download
    set -- -f "$DB_CACHE" "$@"
fi

start_background_refresher
exec vncsnatch "$@"
