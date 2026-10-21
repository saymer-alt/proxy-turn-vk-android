#!/bin/sh
# Owner-only NC-4210 WDTT PR34 120s TCP smoke; BusyBox ash compatible.
# No external download, automatic startup, route edits, or log of secret input.
LAB=/opt/wdtt-field-candidate
cd "$LAB" || { echo 'FAIL: candidate directory missing'; exit 1; }
umask 077
fail() { echo "FAIL: $1"; exit 1; }
[ -s config.json ] || fail 'private config missing'
[ -s wt-client-linux-arm64 ] || fail 'candidate ARM64 ELF missing'
[ -f SHA256SUMS ] || fail 'SHA256SUMS missing'
sha256sum -c SHA256SUMS || fail 'candidate hash mismatch'
AVAILABLE=$(awk '$1=="MemAvailable:" {print $2}' /proc/meminfo)
echo "MemAvailable_before=${AVAILABLE:-unknown} KiB"
[ -n "$AVAILABLE" ] || fail 'MemAvailable not found'
[ "$AVAILABLE" -ge 155648 ] || fail 'RAM below conservative 18-worker floor'
if ps | grep -q '[w]t-client-linux'; then fail 'another WDTT process running'; fi
if netstat -lnt 2>/dev/null | grep -q '127.0.0.1:1081 '; then fail 'test SOCKS port already in use'; fi
echo '=== START PR34 COMBINED CANDIDATE ==='
./wt-client-linux-arm64 -config-file "$LAB/config.json" >/dev/null 2>&1 &
PID=$!
echo "PID=$PID"
(
  sleep 120
  kill -TERM "$PID" 2>/dev/null
  sleep 3
  kill -KILL "$PID" 2>/dev/null
) &
WATCH=$!
cleanup() {
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null
  [ -n "$WATCH" ] && kill "$WATCH" 2>/dev/null
  [ -n "$PID" ] && wait "$PID" 2>/dev/null
  [ -n "$WATCH" ] && wait "$WATCH" 2>/dev/null
}
trap 'cleanup' 0
trap 'exit 129' 1
trap 'exit 130' 2
trap 'exit 143' 15
sleep 70
echo '=== FIXED STATUS CODES ==='
for f in status transport-ready getconf-status socks-status; do
  if [ -f "$f" ]; then
    printf '%s=' "$f"; tr -d '\r\n' < "$f"; echo
  else
    echo "$f=NOT_CREATED"
  fi
done
echo '=== SOCKS 127.0.0.1:1081 ==='
netstat -lnt 2>/dev/null | grep '127.0.0.1:1081 ' || echo PORT_CLOSED
echo '=== HTTPS THROUGH SOCKS ==='
curl -q -4 --noproxy '' --proxy socks5h://127.0.0.1:1081 \
  --connect-timeout 7 --max-time 15 -sS -o /dev/null \
  -w 'HTTP=%{http_code} BYTES=%{size_download}\n' https://example.com/
echo "CURL_EXIT=$?"
echo '=== NUMERIC GROUP AND MEMORY TELEMETRY ==='
if [ -f socks-telemetry.json ]; then
  grep -E '"(transport_worker_|transport_group[12]_|process_rss|go_heap_alloc_bytes|go_goroutines|tcp_connected|tcp_completed|tcp_dial_failed|udp_associate_ready|mem_available_kib)' socks-telemetry.json || true
else
  echo TELEMETRY_NOT_FOUND
fi
grep -E '^(MemAvailable|SwapFree):' /proc/meminfo
kill -TERM "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
echo "CLIENT_EXIT=$?"
PID=''
kill "$WATCH" 2>/dev/null
wait "$WATCH" 2>/dev/null
WATCH=''
sleep 2
echo '=== FINAL SOCKS PORT ==='
netstat -lnt 2>/dev/null | grep '127.0.0.1:1081 ' || echo PORT_CLOSED
trap - 0 1 2 15
echo '=== TEST FINISHED ==='
