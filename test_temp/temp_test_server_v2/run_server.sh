#!/bin/bash
###############################################################################
# run_server.sh — Start the Erlang TLCP debug server
#
# The server prints EVERY handshake step so you can see exactly what happens
# during the GMSSL/TLCP handshake.
#
# Usage:
#   ./run_server.sh              # Default: TLCP mode, port 8443
#   ./run_server.sh 9443         # Custom port
#   ./run_server.sh 9443 tls13   # TLS 1.3 mode
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

# Check that certs exist
if [ ! -f "certs/sign_chain.pem" ]; then
    echo "Certificates not found! Generating them first..."
    bash generate_certs.sh
fi

echo "Compiling server.erl..."
"$ERL" -noshell -eval "
    case compile:file(\"server\", [verbose, report]) of
        {ok, _} -> io:format(\"Compiled OK~n\"), halt(0);
        error   -> io:format(\"Compile FAILED~n\"), halt(1)
    end.
"

echo ""
echo "Starting TLCP Debug Server (port=$PORT, mode=$MODE)"
echo "Press Ctrl+C twice to stop."
echo ""

"$ERL" \
    -noshell \
    -eval "server:start($PORT, $MODE)."
