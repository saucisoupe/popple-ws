#!/usr/bin/env bash
# Run the Autobahn conformance suite against popple-ws.
#
#   autobahn/run.sh server   # Autobahn plays client against examples/echo_server
#   autobahn/run.sh client   # examples/autobahn_client plays Autobahn's cases
#
# Uses a native `wstest` when there is one ($WSTEST, then
# ~/.local/autobahn/pypy/bin/wstest, then PATH), else the docker/podman image,
# which is amd64 only. Reports land in autobahn/reports/{server,client}/;
# open index.html there for the per-case details.
set -euo pipefail

mode=${1:?usage: $0 server|client}
here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")

wstest=${WSTEST:-}
[ -n "$wstest" ] || [ ! -x ~/.local/autobahn/pypy/bin/wstest ] || wstest=~/.local/autobahn/pypy/bin/wstest
[ -n "$wstest" ] || wstest=$(command -v wstest || true)
engine=$(command -v docker || command -v podman || true)

mkdir -p "$here/reports"
# Replaces the calling shell: always call it in a subshell, `(run ...)` or
# `run ... &`, so that `$!` is wstest itself and killing it stops the server.
run() {
    cd "$here"
    if [ -n "$wstest" ]; then
        exec "$wstest" "$@"
    elif [ -n "$engine" ]; then
        exec "$engine" run --rm --network host -v "$here:/work:z" -w /work \
            docker.io/crossbario/autobahn-testsuite wstest "$@"
    else
        echo "needs wstest, docker or podman" >&2
        exit 1
    fi
}

cd "$root"
cargo build --release --examples

# A server left over from an earlier run would answer in our place.
for port in 9001 9002; do
    if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then
        echo "port $port is already in use; stop what holds it first" >&2
        exit 1
    fi
done

case "$mode" in
server)
    ./target/release/examples/echo_server &
    pid=$!
    trap 'kill $pid 2>/dev/null' EXIT
    sleep 1
    (run -m fuzzingclient -s fuzzingclient.json)
    ;;
client)
    run -m fuzzingserver -s fuzzingserver.json &
    pid=$!
    trap 'kill $pid 2>/dev/null' EXIT
    # Wait for the fuzzing server to listen.
    for _ in $(seq 60); do
        (exec 3<>/dev/tcp/127.0.0.1/9002) 2>/dev/null && break
        sleep 1
    done
    ./target/release/examples/autobahn_client
    ;;
*)
    echo "usage: $0 server|client" >&2
    exit 1
    ;;
esac

python3 "$here/summary.py" "$here/reports/$mode/index.json"
