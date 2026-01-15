#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cc=${CC:-gcc}
bin_dir="$root_dir/tests/bin"
mkdir -p "$bin_dir"

echo "Building test helper..."
$cc -g -Wall -I"$root_dir/src" \
  -o "$bin_dir/test_security" \
  "$root_dir/tests/test_security.c" \
  "$root_dir/src/network_utils.c" \
  "$root_dir/src/misc_utils.c" \
  -lcap
$cc -g -Wall -I"$root_dir/src" \
  -o "$bin_dir/test_resume" \
  "$root_dir/tests/test_resume.c"

vncgrab_cflags=()
vncgrab_ldflags=(-ljpeg)
if [ "${USE_OPENSSL:-0}" = "1" ]; then
  vncgrab_ldflags+=(-lcrypto)
fi

$cc -g -Wall -I"$root_dir/src" \
  "${vncgrab_cflags[@]}" \
  -o "$bin_dir/test_vncgrab" \
  "$root_dir/tests/test_vncgrab.c" \
  "$root_dir/src/vncgrab.c" \
  "$root_dir/src/des.c" \
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
  for _ in $(seq 1 100); do
    if grep -q "READY" "$ready_file"; then
      break
    fi
    sleep 0.05
  done
  if ! grep -q "READY" "$ready_file"; then
    echo "Server failed to start for mode=$mode on port $port"
    exit 1
  fi
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
  local rect=${5:-}
  local allow_blank=${6:-}

  echo "Case: mode=$mode expected=jpeg rfb=3.8"
  local ready_file
  ready_file=$(mktemp)
  python3 -u "$root_dir/tests/fake_vnc_server.py" --port "$port" --mode "$mode" >"$ready_file" 2>/dev/null &
  local server_pid=$!
  trap 'if [ -n "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi' EXIT
  for _ in $(seq 1 100); do
    if grep -q "READY" "$ready_file"; then
      break
    fi
    sleep 0.05
  done
  if ! grep -q "READY" "$ready_file"; then
    echo "Server failed to start for mode=$mode on port $port"
    exit 1
  fi
  if [ -n "$password" ] && [ -n "$rect" ] && [ -n "$allow_blank" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "$password" "$rect" "$allow_blank"
  elif [ -n "$password" ] && [ -n "$rect" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "$password" "$rect"
  elif [ -n "$password" ] && [ -n "$allow_blank" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "$password" "" "$allow_blank"
  elif [ -n "$rect" ] && [ -n "$allow_blank" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "" "$rect" "$allow_blank"
  elif [ -n "$password" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "$password"
  elif [ -n "$rect" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "" "$rect"
  elif [ -n "$allow_blank" ]; then
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "" "" "$allow_blank"
  else
    "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile"
  fi
  wait "$server_pid" || true
  trap - EXIT
  rm -f "$ready_file"
}

run_frame_expect_fail() {
  local port=$1
  local outfile=$2
  local mode=$3
  local allow_blank=$4

  echo "Case: mode=$mode expected=fail rfb=3.8"
  local ready_file
  ready_file=$(mktemp)
  local err_file
  err_file=$(mktemp)
  python3 -u "$root_dir/tests/fake_vnc_server.py" --port "$port" --mode "$mode" >"$ready_file" 2>/dev/null &
  local server_pid=$!
  trap 'if [ -n "${server_pid:-}" ]; then kill "$server_pid" 2>/dev/null || true; fi' EXIT
  for _ in $(seq 1 100); do
    if grep -q "READY" "$ready_file"; then
      break
    fi
    sleep 0.05
  done
  if ! grep -q "READY" "$ready_file"; then
    echo "Server failed to start for mode=$mode on port $port"
    exit 1
  fi

  if "$bin_dir/test_vncgrab" 127.0.0.1 "$port" "$outfile" "" "" "$allow_blank" 2>"$err_file"; then
    echo "Expected failure but got success"
    cat "$err_file"
    exit 1
  fi

  wait "$server_pid" || true
  trap - EXIT
  rm -f "$ready_file"
  rm -f "$err_file"
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

echo "Case: resume parsing"
"$bin_dir/test_resume"
passed=$((passed + 1))
total=$((total + 1))

run_frame_case 5910 "$bin_dir/out.jpg"
passed=$((passed + 1))
total=$((total + 1))

run_frame_case 5912 "$bin_dir/out-rect.jpg" frame-2x2 "" "1x1+1+1"
if [ ! -s "$bin_dir/out-rect.jpg" ]; then
  echo "Rect output not created"
  exit 1
fi
rm -f "$bin_dir/out-rect.jpg"
passed=$((passed + 1))
total=$((total + 1))

run_frame_expect_fail 5913 "$bin_dir/out-black.jpg" frame-black 0
if [ -s "$bin_dir/out-black.jpg" ]; then
  echo "Blank frame should be skipped"
  exit 1
fi
rm -f "$bin_dir/out-black.jpg"
passed=$((passed + 1))
total=$((total + 1))

if [ "${USE_OPENSSL:-0}" = "1" ]; then
  run_frame_case 5911 "$bin_dir/out-auth.jpg" frame-auth "secret"
  passed=$((passed + 1))
  total=$((total + 1))
  rm -f "$bin_dir/out-auth.jpg"
fi

echo "All tests passed ($passed/$total)."
