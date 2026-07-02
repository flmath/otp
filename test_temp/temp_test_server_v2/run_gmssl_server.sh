#!/bin/bash
###############################################################################
# run_gmssl_server.sh — Run GmSSL's native C TLCP server
#
# Use this to test non-Erlang clients against the GmSSL native server.
# This helps isolate whether handshake issues are in the Erlang SSL or
# in the client implementation.
#
# Usage:
#   ./run_gmssl_server.sh              # Default port 8444
#   ./run_gmssl_server.sh 9443         # Custom port
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8444}"

# Find gmssl binary
GMSSL="${GMSSL:-}"
if [ -z "$GMSSL" ]; then
    for candidate in \
        "$SCRIPT_DIR/../shared/offline/GmSSL/build/bin/gmssl" \
        /usr/local/bin/gmssl \
        /usr/bin/gmssl; do
        if [ -x "$candidate" ]; then
            GMSSL="$candidate"
            break
        fi
    done
fi
if [ -z "$GMSSL" ]; then
    echo "ERROR: gmssl binary not found." >&2
    exit 1
fi

echo "========================================"
echo "  GmSSL Native TLCP Server"
echo "  Port: $PORT"
echo "  Binary: $GMSSL"
echo "========================================"
echo ""
echo "This runs the GmSSL C implementation of a TLCP server."
echo "Use it as a reference to compare against the Erlang server."
echo ""
echo "Test with:"
echo "  Erlang client:  ./run_erlang_client.sh $PORT"
echo "  GmSSL client:   GMSSL=$GMSSL $GMSSL tlcp_client -host 127.0.0.1 -port $PORT -cipher_suite ECC_SM4_CBC_SM3 -cacert certs/rootca.crt -verbose"
echo ""
echo "Press Ctrl+C to stop."
echo ""

$GMSSL tlcp_server \
    -port "$PORT" \
    -cert certs/sign_chain.pem \
    -key certs/sign.key \
    -cert certs/enc_chain.pem \
    -key certs/enc.key \
    -cipher_suite ECC_SM4_CBC_SM3 \
    -cipher_suite ECDHE_SM4_CBC_SM3 \
    -verbose
