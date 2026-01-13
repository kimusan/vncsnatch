#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cc=${CC:-gcc}
bin_dir="$root_dir/tests/bin"
mkdir -p "$bin_dir"

echo "Building test helper..."
$cc -g -Wall -I"$root_dir" \
  -o "$bin_dir/test_security" \
  "$root_dir/tests/test_security.c" \
  "$root_dir/network_utils.c" \
  "$root_dir/misc_utils.c" \
  -lcap

vncgrab_cflags=()
vncgrab_ldflags=(-ljpeg)
if [ "${USE_OPENSSL:-0}" = "1" ]; then
  vncgrab_cflags+=(-DUSE_OPENSSL)
  vncgrab_ldflags+=(-lcrypto)
fi

$cc -g -Wall -I"$root_dir" \
  "${vncgrab_cflags[@]}" \
  -o "$bin_dir/test_vncgrab" \
  "$root_dir/tests/test_vncgrab.c" \
  "$root_dir/vncgrab.c" \
  "${vncgrab_ldflags[@]}"

run_case() {
  local mode=$1
  local port=$2
  local expected=$3
  local v33=${4:-}

  if [ -n "$v33" ]; then
    echo "Case: mode=$mode expected=$expected rfb=3.3"
  else
    echo "Case: mode=$mode expected=$expected rfb=3.8"
  fi

  local ready_file
  ready_file=$(mktemp)
  python3 -u "$root_dir/tests/fake_vnc_server.py" --port "$port" --mode "$mode" $v33 >"$ready_file" 2>/dev/null &
  local server_pid=$!
  trap 'if [ -n "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi' EXIT
  for _ in $(seq 1 40); do
    if grep -q "READY" "$ready_file"; then
      break
    fi
    sleep 0.05
  done
  "$bin_dir/test_security" 127.0.0.1 "$port" "$expected"
  wait "$server_pid" || true
  trap - EXIT
  rm -f "$ready_file"
}

run_frame_case() {
  local port=$1
  local outfile=$2
  local mode=${3:-frame}
  local password=${4:-}

  echo "Case: mode=$mode expected=jpeg rfb=3.8"
  local ready_file
  ready_file=$(mktemp)
  python3 -u "$root_dir/tests/fake_vnc_server.py" --port "$port" --mode "$mode" >"$ready_file" 2>/dev/null &
  local server_pid=$!
  trap 'if [ -n "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi' EXIT
  for _ in $(seq 1 40); do
    if grep -q "READY" "$ready_file"; then
      break
    fi
    sleep 0.05
  done
  if [ -n "$password" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "$password"
  else
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile"
  fi
  wait "$server_pid" || true
  trap - EXIT
  rm -f "$ready_file"
}

echo "Running tests..."
passed=0
total=0
run_case noauth 5905 1
passed=$((passed + 1))
total=$((total + 1))
run_case auth 5906 0
passed=$((passed + 1))
total=$((total + 1))
run_case fail 5907 -1
passed=$((passed + 1))
total=$((total + 1))
run_case noauth 5908 1 --v33
passed=$((passed + 1))
total=$((total + 1))
run_case auth 5909 0 --v33
passed=$((passed + 1))
total=$((total + 1))

run_frame_case 5910 "$bin_dir/out.jpg"
passed=$((passed + 1))
total=$((total + 1))

if [ "${USE_OPENSSL:-0}" = "1" ]; then
  run_frame_case 5911 "$bin_dir/out-auth.jpg" frame-auth "secret"
  passed=$((passed + 1))
  total=$((total + 1))
  rm -f "$bin_dir/out-auth.jpg"
fi

echo "All tests passed ($passed/$total)."
