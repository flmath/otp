#!/bin/bash
###############################################################################
# run_erlang_client.sh — Test server with the Erlang TLCP mock client
#
# Usage:
#   ./run_erlang_client.sh              # Default: localhost:8443 TLCP
#   ./run_erlang_client.sh 9443         # Custom port
#   ./run_erlang_client.sh 9443 tls13   # TLS 1.3 mode
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8443}"
MODE="${2:-tlcp}"

# Find Erlang
ERL="${ERL:-}"
if [ -z "$ERL" ]; then
    for candidate in \
        "$SCRIPT_DIR/../shared/otp/bin/erl" \
        /usr/local/bin/erl \
        /usr/bin/erl; do
        if [ -x "$candidate" ]; then
            ERL="$candidate"
            break
        fi
    done
fi
if [ -z "$ERL" ]; then
    echo "ERROR: erl not found. Set ERL=/path/to/erl" >&2
    exit 1
fi

echo "Compiling client.erl..."
"$ERL" -noshell -eval "
    case compile:file(\"client\", [verbose, report]) of
        {ok, _} -> io:format(\"Compiled OK~n\"), halt(0);
        error   -> io:format(\"Compile FAILED~n\"), halt(1)
    end.
"

echo ""
echo "Starting Erlang TLCP client (target=localhost:$PORT, mode=$MODE)..."
echo ""

"$ERL" \
    -noshell \
    -eval "client:start($PORT, $MODE), halt(0)."
