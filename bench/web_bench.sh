#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNT="${COUNT:-1000}"

measure() {
  local label="$1" port="$2"
  local tmp
  tmp="$(mktemp)"
  /usr/bin/time -p sh -c "for i in \$(seq 1 $COUNT); do curl -sf http://127.0.0.1:${port}/ping >/dev/null; done" >/dev/null 2>"$tmp" || true
  local real
  real="$(grep '^real' "$tmp" | awk '{print $2}')"
  rm -f "$tmp"
  printf "%-12s %s\n" "${label}:" "${real:-n/a}"
}

start_qs() {
  target/release/quick "$ROOT/bench/web_qs.qx" >/dev/null 2>&1 &
  QS_PID=$!
  sleep 1
}

start_js() {
  node "$ROOT/bench/web_js.js" >/dev/null 2>&1 &
  JS_PID=$!
  sleep 1
}

cleanup() {
  kill ${QS_PID:-} ${JS_PID:-} >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_qs
start_js

echo "== Web server latency for $COUNT requests (curl loop) =="
measure "QuickScript" 9310
measure "Node" 9311
