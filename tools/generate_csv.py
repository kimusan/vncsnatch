#!/usr/bin/env python3
import argparse
import ipaddress
import sys


def parse_range(value):
  value = value.strip()
  if "-" in value:
    start_str, end_str = value.split("-", 1)
    start = int(ipaddress.IPv4Address(start_str.strip()))
    end = int(ipaddress.IPv4Address(end_str.strip()))
  else:
    ip = int(ipaddress.IPv4Address(value))
    start = ip
    end = ip
  if start > end:
    raise ValueError("range start > end")
  return start, end


def main():
  parser = argparse.ArgumentParser(
      description="Generate IP2Location-style CSV for vncsnatch")
  parser.add_argument("-c", "--country", required=True,
                      help="Two-letter country code (e.g., SE)")
  parser.add_argument("-n", "--country-name", required=True,
                      help="Country name (e.g., Sweden)")
  parser.add_argument("-r", "--range", action="append", required=True,
                      help="IP range (single IP or start-end), repeatable")
  parser.add_argument("-o", "--output", default="custom.csv",
                      help="Output CSV path (default custom.csv)")
  args = parser.parse_args()

  if len(args.country) != 2:
    print("Country code must be 2 letters", file=sys.stderr)
    return 1

  rows = []
  for value in args.range:
    start, end = parse_range(value)
    rows.append((start, end))

  rows.sort()
  with open(args.output, "w", encoding="utf-8") as f:
    for start, end in rows:
      f.write(f"\"{start}\",\"{end}\",\"{args.country.upper()}\","
              f"\"{args.country_name}\"\n")
  print(f"Wrote {len(rows)} ranges to {args.output}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
