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

## Dependencies

- libcapability (usually default everywhere)
- libreadline
- an [IP2location](https://ip2location.com) lite csv file (can be downloaded for free)
- [vncsnapshot](https://github.com/shamun/vncsnapshot") to take screenshots

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
