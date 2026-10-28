![vncsnatch screenshot](https://raw.githubusercontent.com/kimusan/vncsnatch/main/assets/screenshot.png)

# Intro

This is a fun little project inspired by [vncresolver.com](https://vncresolver.com). This program takes
the address list from [ip2location.com](https://ip2location.com) and then scans all ip addresses
from a given country for open VNC entities.

If the VNC is open, it will create a screenshot called IP.jpg.

You will be amazed how much critical infrastructure is accessible this way.

## Usage

```bash
make all
./vncsnatch
```

Install or uninstall:

```bash
make install
make uninstall
```

Grant ICMP capability without running as root:

```bash
make caps
```

Non-interactive example:

```bash
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -w 8 -t 30 -p 5900,5901
```

Password list + metadata example:

```bash
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -F passwords.txt -M metadata
```

Results export example:

```bash
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -o results.csv
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -o results.jsonl
```

## Docker

A multi-stage `Dockerfile` builds a fully static binary on Alpine, so the
runtime image is small (~19 MB, including `curl` for the auto-download) with no
shared-library dependencies. It runs as an unprivileged user (`vnc`, uid 1000)
and carries a `HEALTHCHECK` that confirms the binary is runnable.

Build the image:

```bash
docker build -t vncsnatch .
```

Run it. Mount a host directory to `/data` so the container can read the input
CSV and write screenshots/metadata/results back to the host. The container's
working directory is `/data`, so relative paths resolve there:

```bash
docker run --rm -v "$PWD/data:/data" vncsnatch \
    -c DK -f /data/IP2LOCATION-LITE-DB1.CSV -o /data/results.csv
```

Because the container runs as uid 1000, a bind-mounted `/data` must be writable
by that uid. Create it owned by 1000 (`mkdir -p data && sudo chown 1000:1000
data`), run as your own id (`--user "$(id -u):$(id -g)"`), or use a named
volume (`-v vncdata:/data`), which is owned correctly out of the box.

The ICMP reachability fast-path needs `CAP_NET_RAW`. Without it the scanner
falls back to TCP connect checks, so grant the capability only if you want the
faster path:

```bash
docker run --rm --cap-add=NET_RAW -v "$PWD/data:/data" vncsnatch \
    -c DK -f /data/IP2LOCATION-LITE-DB1.CSV
```

### Automatic database download

If you do **not** pass `-f/--file`, the container downloads an IP-to-country
database for you on first run and caches it at `/data/ip-country.csv`. Because
`/data` is a mounted volume the cache survives across runs, so later runs do not
re-download; it is refreshed automatically only once it is older than
`DB_MAX_AGE_DAYS` (7 by default). So this just works:

```bash
docker run --rm -v "$PWD/data:/data" vncsnatch -c DK -o /data/results.csv
```

The parser reads several public layouts directly, so the default sources are a
mix of repositories, providers and hosts and are tried in order until one
succeeds (no single outage is fatal):

- `sapics/ip-location-db` — GeoLite2 and DB-IP country data (`from,to,CC`)
- `datasets/geoip2-ipv4` — independent repo (`CIDR,…,CC,Country`)
- each GitHub repo is also offered through the jsDelivr CDN as a host fallback

A refresh downloads into a temporary file first and only swaps it in once a
source succeeds, so if every source is unreachable the existing cache is kept
and the scan still runs with it.

Pre-seed or refresh the cache without scanning (`fetch-db` respects the TTL;
add `force` to download unconditionally):

```bash
docker run --rm -v "$PWD/data:/data" vncsnatch fetch-db
docker run --rm -v "$PWD/data:/data" vncsnatch fetch-db force
```

For `--mode asn`/`both` the ASN database (`from,to,ASN,"Org"`, from
`sapics/ip-location-db` geolite2-asn / dbip-asn) is downloaded and cached the
same way at `/data/ip-asn.csv`; pre-seed it with `fetch-db asn`:

```bash
docker run --rm -v "$PWD/data:/data" vncsnatch fetch-db asn
docker run --rm -v "$PWD/data:/data" vncsnatch --mode asn --asn org:cloudflare
```

To keep the database current over time, either run `fetch-db` periodically from
the host scheduler (cron), or set `DB_AUTO_REFRESH=1` so a long-running scan
re-checks and refreshes the cache in the background on `DB_REFRESH_INTERVAL`.

### Environment variables

Configure the auto-download with these (all optional):

| Variable | Default | Purpose |
| --- | --- | --- |
| `DB_URL` | built-in source list | Replace the entire source list. Use where the default hosts are blocked (e.g. behind a regional firewall) to point at your own mirror. Space/newline-separated. |
| `DB_URL_EXTRA` | *(empty)* | Prepend extra sources to the default list (tried first), so you add a preferred mirror without losing the fallbacks. |
| `DB_HEADER` | *(empty)* | Extra HTTP header sent with every request, for providers that need an API key, e.g. `Authorization: Bearer <key>`. |
| `DB_CACHE` | `/data/ip-country.csv` | Where the database is cached on the volume. |
| `DB_REFRESH` | `0` | Set to `1` to force a re-download even if the cache exists. |
| `DB_MAX_AGE_DAYS` | `7` | Re-download when the cached database is older than this many days. `0` keeps the cache forever. |
| `DB_AUTO_REFRESH` | `0` | Set to `1` to run a background refresher during a scan that re-checks the cache age and refreshes it on an interval. |
| `DB_REFRESH_INTERVAL` | `86400` | Background refresher interval in seconds (default daily). Only used with `DB_AUTO_REFRESH=1`. |
| `ASN_DB_URL` | built-in ASN list | Like `DB_URL`, but for the ASN database (`--mode asn`/`both`). |
| `ASN_DB_URL_EXTRA` | *(empty)* | Like `DB_URL_EXTRA`, for the ASN database. |
| `ASN_DB_CACHE` | `/data/ip-asn.csv` | Where the ASN database is cached on the volume. |

`${VAR}` references inside `DB_URL`/`DB_URL_EXTRA` are expanded from the
environment, so an API token can be supplied as a separate variable rather than
baked into the URL:

```bash
# Your own mirror first, built-in sources as fallback:
docker run --rm -v "$PWD/data:/data" \
    -e DB_URL_EXTRA="https://mirror.example/ip-country.csv" \
    vncsnatch -c DK -o /data/results.csv

# A provider that requires an API key:
docker run --rm -v "$PWD/data:/data" \
    -e API_TOKEN=your-token \
    -e DB_URL='https://provider.example/download?file=country-csv&token=${API_TOKEN}' \
    vncsnatch -c DK
```

A gzip-compressed response (`.csv.gz`) is decompressed automatically.

Any CSV that uses one of the supported layouts works, whether downloaded or
supplied with `-f`:

- IP2Location LITE DB1: `"from","to","CC","Country Name"` (quoted decimal)
- `sapics/ip-location-db`: `from,to,CC` (unquoted, dotted IPs)
- `datasets/geoip2-ipv4`: `network/prefix,…,CC,Country,…` (CIDR + columns)

### Driving the scanner from the environment

Every CLI flag has a matching `VNC_*` environment variable, so the scanner can
be configured entirely from a compose `environment:` block (or `-e` flags) with
no command line. Anything passed on the command line overrides the variable.

| Variable | Flag | Variable | Flag |
| --- | --- | --- | --- |
| `VNC_COUNTRY` | `-c` | `VNC_ALLOW_CIDR` | `-A` |
| `VNC_FILE` | `-f` | `VNC_DENY_CIDR` | `-D` |
| `VNC_WORKERS` | `-w` | `VNC_DELAY_ATTEMPTS` | `-T` |
| `VNC_TIMEOUT` | `-t` | `VNC_RESULTS` | `-o` |
| `VNC_PORTS` | `-p` | `VNC_QUALITY` | `-Q` |
| `VNC_RATE` | `-R` | `VNC_RECT` | `-x` |
| `VNC_PASSWORD` | `-P` | `VNC_RESUME=1` | `-r` |
| `VNC_PASSWORD_FILE` | `-F` | `VNC_VERBOSE=1` | `-v` |
| `VNC_OUTPUT_DIR` | `-O` | `VNC_QUIET=1` | `-q` |
| `VNC_ALLOWBLANK=1` | `-b` | `VNC_ARGS` | *(free-form extra flags)* |
| `VNC_MODE` | `--mode` | `VNC_ASN` | `--asn` |
| `VNC_ASN_FILE` | `--asn-file` | | |

```bash
docker run --rm -v "$PWD/data:/data" \
    -e VNC_COUNTRY=DK -e VNC_WORKERS=8 -e VNC_RESULTS=/data/results.csv \
    vncsnatch
```

### docker compose

`docker-compose.yml` wires up the `./data` bind mount and the `NET_RAW`
capability. Override the command per run:

```bash
docker compose run --rm vncsnatch \
    -c DK -f /data/IP2LOCATION-LITE-DB1.CSV -o /data/results.csv
```

Or configure everything through the environment and just start the service:

```bash
docker compose run --rm -e VNC_COUNTRY=DK -e VNC_RESULTS=/data/results.csv \
    vncsnatch
```

Build-time toggles mirror the makefile and are passed as build args:

```bash
docker build --build-arg USE_OPENSSL=1 -t vncsnatch .
```

The `tools/generate_csv.py` helper is a dev-time utility and is not shipped in
the image; run it on the host with `python3` as shown under [Tools](#tools).

## Dependencies

- libcapability (usually default everywhere)
- libreadline
- libjpeg (required for clean-room `vncgrab` screenshots)
- an [IP2location](https://ip2location.com) lite csv file (can be downloaded for free)
- [vncsnapshot](https://github.com/shamun/vncsnapshot") (optional) for legacy capture

## Options

```
-c, --country CODE   Two-letter country code (e.g., DK)
-f, --file PATH      IP2Location/country CSV file path
    --mode MODE      Target selection: country (default), asn, both
    --asn SPEC       ASN filter: numbers and/or org:name substrings,
                     comma-separated (e.g. 13335,AS15169,org:cloudflare)
    --asn-file PATH  ASN database CSV (from,to,ASN,"Org")
-w, --workers N      Number of worker threads (max 256)
-t, --timeout SEC    Snapshot timeout in seconds (default 60)
-p, --ports LIST     Comma-separated VNC ports (default 5900,5901)
-r, --resume         Resume from .line checkpoint
-R, --rate N         Limit scans to N IPs per second
-P, --password PASS  Use PASS for VNC auth (if required)
-F, --password-file  Read passwords from file (one per line)
-M, --metadata-dir   Alias for --output-dir
-O, --output-dir     Root output directory (default output/CC)
-A, --allow-cidr     Comma-separated CIDR allowlist
-D, --deny-cidr      Comma-separated CIDR denylist
-T, --delay-attempts Delay between password attempts (ms)
-o, --results PATH   Write results summary to PATH
-b, --allowblank     Allow blank (all black) screenshots
-B, --ignoreblank    Skip blank (all black) screenshots (default)
-Q, --quality N      JPEG quality 1-100 (default 100)
-x, --rect SPEC      Capture sub-rect (wxh+x+y)
-v, --verbose        Print per-host progress output
-q, --quiet          Suppress progress output
-h, --help           Show this help message
```

## Scanning by ASN

Instead of (or in addition to) a country, you can target an autonomous system
with `--mode` and `--asn`:

- `--mode country` (default): country ranges, as before.
- `--mode asn`: ranges from an ASN database matching `--asn`; no country needed.
- `--mode both`: country ranges intersected with the ASN filter.

`--asn` takes a comma-separated list. Each item is either an ASN number
(`13335`, or `AS13335`) or an organisation-name substring (`org:cloudflare`,
case-insensitive). A range matches if any item matches.

```bash
# Everything Cloudflare (by number or name), from an ASN CSV:
./vncsnatch --mode asn --asn 13335,org:cloudflare --asn-file asn-ipv4.csv

# Only Google-owned ranges located in Denmark:
./vncsnatch --mode both -c DK --asn org:google \
    -f country.csv --asn-file asn-ipv4.csv
```

The ASN database is the `from,to,ASN,"Org"` CSV layout published by
`sapics/ip-location-db` (geolite2-asn / dbip-asn). In Docker it is downloaded
automatically for `--mode asn`/`both`; see the Docker section.

## Clean-room vncgrab

Default builds use the clean-room `vncgrab` module (no external dependency).
If you want to use `vncsnapshot`, build with `USE_VNCSNAPSHOT=1`.

To build with `vncsnapshot`:

```bash
make USE_VNCSNAPSHOT=1
```

If you want to keep OpenSSL available for other work, you can still link it:

```bash
make USE_OPENSSL=1
```

Convenience target:

```bash
make cleanroom
```

## Notes

- The scanner now runs concurrently and shows a live progress line unless `-v` or `-q` is set.
- If you want to resume, use `-r` and the `.line` file will be used as a checkpoint offset.
- Resume checkpoints are scoped by country code and include counters (online/vnc/noauth/auth) so progress resumes accurately.
- If the program has `cap_net_raw`/`cap_net_admin` or runs as root, it can use ICMP to skip offline hosts faster. Without those capabilities, the scanner falls back to fast TCP connect checks for the configured ports.
- Metadata and screenshots are written under `output/CC/` by default.
- Password files are read line-by-line; blank lines and lines starting with `#` are ignored.
- Results export writes CSV by default; use `.json` or `.jsonl` to emit JSON lines.
- CIDR filters accept comma-separated IPv4 CIDR blocks (e.g., `10.0.0.0/8,192.168.0.0/16`).

## Tests

Run the local protocol regression tests:

```bash
make test
```

## Tools

Generate a custom IP2Location-style CSV from manual ranges:

```bash
python3 tools/generate_csv.py -c SE -n Sweden -r 5.26.179.17 -r 2.16.63.0-2.16.63.9 -o custom.csv
```

Interactive mode with CIDR support:

```bash
python3 tools/generate_csv.py --interactive
```

## IMPORTANT

You might wanna run this via tor or other proxy as some internet provides
do not like you scanning and connecting to a lot of IP addresses.

## Credits

Big thanks to the developers of vncsnapshot, this project would
not be possible without them!
The program is hacked together by me, [Kim Schulz](https://schulz.dk) for the fun of it.

Find me at [social.data.coop/@kimschulz (mastodon)](https://social.data.coop/@kimschulz) and [kimschulz.bsky.social (bluesky)](https://kimschulz.bsky.social)

## Disclaimer

This was written purly for informational/educational purposes only.
You can use/modify this as you please, however, I (Kim Schulz) am not responsible
for any legal problems you may face using this information.

## License

MIT. See `LICENSE`.
