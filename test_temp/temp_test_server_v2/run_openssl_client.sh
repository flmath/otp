#!/bin/bash
###############################################################################
# run_openssl_client.sh — Test with OpenSSL s_client
#
# OpenSSL doesn't support TLCP, but you can use this to test TLS 1.2/1.3
# if the server is started in tls13 mode:
#   ./run_server.sh 8443 tls13
#   ./run_openssl_client.sh 8443
#
# For TLCP testing with non-Erlang clients, use run_gmssl_client.sh instead.
#
# Usage:
#   ./run_openssl_client.sh              # Default: localhost:8443
#   ./run_openssl_client.sh 9443         # Custom port
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PORT="${1:-8443}"
HOST="${2:-127.0.0.1}"

OPENSSL="${OPENSSL:-openssl}"

echo "========================================"
echo "  OpenSSL s_client -> Server"
echo "  Target: $HOST:$PORT"
echo "========================================"
echo ""
echo "NOTE: OpenSSL does NOT support TLCP/GMSSL."
echo "      Use this only when the server runs in tls13 mode:"
echo "        ./run_server.sh $PORT tls13"
echo ""
echo "If the server is in TLCP mode, you'll see a handshake failure."
echo "That's expected — it proves TLCP is properly enforced!"
echo ""
echo "Press Ctrl+C to abort."
echo ""

echo "Hello from OpenSSL" | \
    $OPENSSL s_client \
        -connect "$HOST:$PORT" \
        -CAfile certs/rootca.crt \
        -state \
        -debug \
        -msg \
        2>&1

RESULT=$?
echo ""
if [ $RESULT -eq 0 ]; then
    echo "=== Connection SUCCEEDED ==="
else
    echo "=== Connection FAILED (exit code $RESULT) ==="
    echo ""
    echo "If the server is in TLCP mode, this failure is EXPECTED."
    echo "OpenSSL doesn't speak TLCP. Use ./run_gmssl_client.sh instead."
fi
