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

Non-interactive example:

```bash
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -w 8 -t 30 -p 5900,5901
```

Password list + metadata example:

```bash
./vncsnatch -c DK -f /path/to/IP2LOCATION-LITE-DB1.CSV -F passwords.txt -M metadata
```

## Dependencies

- libcapability (usually default everywhere)
- libreadline
- libjpeg
- an [IP2location](https://ip2location.com) lite csv file (can be downloaded for free)
- [vncsnapshot](https://github.com/shamun/vncsnapshot") to take screenshots

## Options

```
-c, --country CODE   Two-letter country code (e.g., DK)
-f, --file PATH      IP2Location CSV file path
-w, --workers N      Number of worker threads
-t, --timeout SEC    Snapshot timeout in seconds (default 60)
-p, --ports LIST     Comma-separated VNC ports (default 5900,5901)
-r, --resume         Resume from .line checkpoint
-R, --rate N         Limit scans to N IPs per second
-P, --password PASS  Use PASS for VNC auth (if required)
-F, --password-file  Read passwords from file (one per line)
-M, --metadata-dir   Output per-host metadata JSON files
-b, --allowblank     Allow blank (all black) screenshots
-B, --ignoreblank    Skip blank (all black) screenshots (default)
-Q, --quality N      JPEG quality 1-100 (default 100)
-x, --rect SPEC      Capture sub-rect (wxh+x+y)
-v, --verbose        Print per-host progress output
-q, --quiet          Suppress progress output
-h, --help           Show this help message
```

## Clean-room vncgrab (in progress)

The codebase includes a clean-room `vncgrab` module to replace the external
`vncsnapshot` dependency. By default the build still uses `vncsnapshot`.

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
- If the program has `cap_net_raw`/`cap_net_admin` or runs as root, it can use ICMP to skip offline hosts faster. Without those capabilities, the "online" stat is not available.
- Metadata is written per detected VNC server in the metadata directory (default `metadata/`).
- Password files are read line-by-line; blank lines and lines starting with `#` are ignored.

## Tests

Run the local protocol regression tests:

```bash
make test
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
