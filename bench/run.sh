#!/usr/bin/env bash
# Load-test popple-ws against tokio-tungstenite and fastwebsockets under the
# same client, examples/bench_client, and print a markdown table.
#
#   bench/run.sh                 # every server, plain and TLS, every case
#   IMPLS=popple TLS=plain bench/run.sh
#
# Server and client are pinned to disjoint cores (SERVER_CPUS, CLIENT_CPUS).
# Beside throughput and latency, the server's CPU time over the measured
# window gives the messages it echoes per CPU-second: at equal throughput,
# the lighter server is the faster one.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"
SERVER_CPUS=${SERVER_CPUS:-0-3}
CLIENT_CPUS=${CLIENT_CPUS:-4-9}
IMPLS=${IMPLS:-popple tungstenite fastwebsockets}
TLS=${TLS:-plain tls}
SECS=${SECS:-5}
WARMUP=${WARMUP:-3}
# A port per run, so a run never meets the last server's connections still
# lingering in TIME_WAIT on its port.
PORT=${PORT:-9100}
# conns:depth:size
CASES=${CASES:-100:1:64 100:16:64 100:1:4096 100:1:65536 10000:1:64}

cargo build -q --release --examples
(cd bench/tokio-echo && cargo build -q --release)

ticks=$(getconf CLK_TCK)
cpu_ticks() { # utime + stime of a process, all threads; empty once it died
    local stat
    stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 0
    stat=${stat##*) }
    awk '{ print $12 + $13 }' <<<"$stat"
}

server() {
    local impl=$1 tls=$2
    local flag=""
    [ "$tls" = tls ] && flag=--tls
    case "$impl" in
    popple) exec taskset -c "$SERVER_CPUS" ./target/release/examples/bench_server --port $PORT $flag ;;
    *) exec taskset -c "$SERVER_CPUS" ./bench/tokio-echo/target/release/tokio-echo --impl "$impl" --port $PORT $flag ;;
    esac
}

echo "server cores $SERVER_CPUS, client cores $CLIENT_CPUS, ${SECS}s after ${WARMUP}s warmup"
echo
echo "| server | tls | conns | depth | size | msg/s | MiB/s | p50 µs | p99 µs | p99.9 µs | server cores | k msg/CPU-s |"
echo "|---|---|---|---|---|---|---|---|---|---|---|---|"
for tls in $TLS; do
    for case in $CASES; do
        IFS=: read -r conns depth size <<<"$case"
        for impl in $IMPLS; do
            PORT=$((PORT + 1))
            server "$impl" "$tls" >/dev/null 2>&1 &
            pid=$!
            for _ in $(seq 50); do
                (exec 3<>/dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break
                sleep 0.1
            done
            flag=""
            [ "$tls" = tls ] && flag=--tls
            out=$(mktemp)
            taskset -c "$CLIENT_CPUS" ./target/release/examples/bench_client \
                --addr 127.0.0.1:$PORT --conns "$conns" --depth "$depth" --size "$size" \
                --secs "$SECS" --warmup "$WARMUP" $flag >"$out" 2>&1 &
            client=$!
            sleep "$WARMUP"
            before=$(cpu_ticks $pid)
            sleep "$SECS"
            after=$(cpu_ticks $pid)
            wait $client || true
            kill $pid 2>/dev/null
            wait $pid 2>/dev/null || true
            line=$(grep '^RESULT' "$out" || true)
            if [ -z "$before" ] || [ -z "$after" ]; then
                echo "| $impl | $tls | $conns | $depth | $size | server died |"
            elif [ -z "$line" ]; then
                echo "| $impl | $tls | $conns | $depth | $size | failed: $(tail -1 "$out") |"
            else
                eval "${line#RESULT }"
                python3 - "$impl" "$tls" "$conns" "$depth" "$size" "$msgs" "$secs" "$p50_us" \
                    "$p99_us" "$p999_us" "$errors" "$((after - before))" "$ticks" "$SECS" <<'PY'
import sys
impl, tls, conns, depth, size, msgs, secs, p50, p99, p999, errors, cpu, ticks, window = sys.argv[1:]
rate = int(msgs) / float(secs)
cores = int(cpu) / int(ticks) / float(window)
per_cpu = rate / cores / 1000 if cores else 0
note = f" ({errors} errors)" if int(errors) else ""
print(f"| {impl} | {tls} | {conns} | {depth} | {size} | {rate:,.0f}{note} | "
      f"{rate * int(size) / 2**20:,.1f} | {p50} | {p99} | {p999} | {cores:.2f} | {per_cpu:,.0f} |")
PY
            fi
            rm -f "$out"
        done
    done
done
