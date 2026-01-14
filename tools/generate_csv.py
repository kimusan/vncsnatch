#!/usr/bin/env python3
import argparse
import ipaddress
import sys


def parse_range(value):
  value = value.strip()
  if "/" in value:
    net = ipaddress.IPv4Network(value, strict=False)
    start = int(net.network_address)
    end = int(net.broadcast_address)
  elif "-" in value:
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


def prompt_nonempty(label):
  while True:
    value = input(label).strip()
    if value:
      return value


def prompt_ranges():
  print("Enter IP ranges (single IP, start-end, or CIDR). Blank line to finish.")
  ranges = []
  while True:
    value = input("range> ").strip()
    if not value:
      break
    try:
      parse_range(value)
    except Exception as exc:
      print(f"Invalid range: {exc}")
      continue
    ranges.append(value)
  return ranges


def main():
  parser = argparse.ArgumentParser(
      description="Generate IP2Location-style CSV for vncsnatch")
  parser.add_argument("-c", "--country",
                      help="Two-letter country code (e.g., SE)")
  parser.add_argument("-n", "--country-name",
                      help="Country name (e.g., Sweden)")
  parser.add_argument("-r", "--range", action="append",
                      help="IP range (single IP or start-end), repeatable")
  parser.add_argument("--cidr", action="append",
                      help="CIDR range (repeatable)")
  parser.add_argument("-o", "--output", default="custom.csv",
                      help="Output CSV path (default custom.csv)")
  parser.add_argument("--interactive", action="store_true",
                      help="Prompt for input interactively")
  args = parser.parse_args()

  if args.interactive:
    if args.country or args.country_name or args.range or args.cidr:
      print("Interactive mode ignores -c/-n/-r/--cidr inputs.", file=sys.stderr)
    country = prompt_nonempty("Country code (e.g., SE): ").upper()
    if len(country) != 2:
      print("Country code must be 2 letters", file=sys.stderr)
      return 1
    country_name = prompt_nonempty("Country name (e.g., Sweden): ")
    ranges = prompt_ranges()
    if not ranges:
      print("No ranges provided", file=sys.stderr)
      return 1
    output = input("Output file (default custom.csv): ").strip() or "custom.csv"
  else:
    if not args.country or not args.country_name:
      print("Country code and country name are required", file=sys.stderr)
      return 1
    country = args.country.upper()
    country_name = args.country_name
    output = args.output

    if len(country) != 2:
      print("Country code must be 2 letters", file=sys.stderr)
      return 1
    ranges = []
    if args.range:
      ranges.extend(args.range)
    if args.cidr:
      ranges.extend(args.cidr)
    if not ranges:
      print("At least one range or CIDR is required", file=sys.stderr)
      return 1

  rows = []
  for value in ranges:
    start, end = parse_range(value)
    rows.append((start, end))

  rows.sort()
  with open(args.output, "w", encoding="utf-8") as f:
    for start, end in rows:
      f.write(f"\"{start}\",\"{end}\",\"{country}\","
              f"\"{country_name}\"\n")
  print(f"Wrote {len(rows)} ranges to {output}")
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
